mod awg;
mod mesh_math;
mod reconcile;

use anyhow::Context as _;
use common::mesh_types::{MeshLink, MeshNode};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Patch, PatchParams};
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::{Controller, watcher};
use kube::{Api, Client, Resource, ResourceExt};
use serde::de::DeserializeOwned;
use std::env;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

const MESH_KEYS_SECRET: &str = "mesh-keys";

/// Starts an independent watch on `api`, keeping a local `Store` live-updated for the lifetime of
/// the process. Used for resource types this operator reads but doesn't own (the Controller's own
/// primary type already gets this via `Controller::store()`).
async fn spawn_reflector<K>(api: Api<K>) -> anyhow::Result<Store<K>>
where
    K: Resource + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Hash + Clone + Send + Sync,
{
    let (store, writer) = reflector::store();
    let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()));
    tokio::spawn(async move {
        let mut stream = std::pin::pin!(stream);
        while let Some(event) = stream.next().await {
            if let Err(e) = event {
                tracing::warn!(error = %common::reconcile_error::error_chain(&e), "MeshNode watch stream error");
            }
        }
    });
    store.wait_until_ready().await?;
    Ok(store)
}

/// Blocks until this pod's own `MeshNode` object exists in the store - a fresh cluster or a node
/// awaiting provisioning both legitimately start with no entry. Polls rather than panicking.
async fn wait_for_own_mesh_node(
    store: &Store<MeshNode>,
    node_name: &str,
    namespace: &str,
) -> Arc<MeshNode> {
    let own_ref = ObjectRef::<MeshNode>::new(node_name).within(namespace);
    loop {
        if let Some(own) = store.get(&own_ref) {
            return own;
        }
        tracing::warn!(node_name, "waiting for our own MeshNode to be created");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Reads this node's private key from the shared `mesh-keys` Secret, keyed by `mesh_label` (not
/// the Kubernetes Node name - see `MeshNodeSpec::mesh_label`). Generates and persists a fresh key
/// on first boot; races with every other node's first-boot pod on the initial `Secret::create`,
/// same as roadwarriors' `shared_private_key` - see `common::keys::get_or_create_secret_key`.
async fn own_private_key(
    client: &Client,
    namespace: &str,
    mesh_label: &str,
) -> anyhow::Result<[u8; 32]> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    common::keys::get_or_create_secret_key(&secrets, namespace, MESH_KEYS_SECRET, mesh_label).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::maybe_print_version("mesh", env!("CARGO_PKG_VERSION"));

    // No timestamp/ANSI: this only ever runs as a container's stdout, which the container
    // runtime/kubelet already timestamps (`kubectl logs --timestamps`) - our own timestamp would
    // just duplicate it, and ANSI color codes have no terminal to render them, so `kubectl logs`
    // would show the raw escape sequences.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .init();

    let node_name = env::var("NODE_NAME").expect("NODE_NAME env var must be set (downward API)");
    let namespace =
        env::var("POD_NAMESPACE").expect("POD_NAMESPACE env var must be set (downward API)");

    tracing::info!(node_name, "starting mesh");

    let client = Client::try_default().await?;
    let meshnodes: Api<MeshNode> = Api::namespaced(client.clone(), &namespace);
    let mesh_node_store = spawn_reflector(meshnodes.clone()).await?;

    let own_mesh_node = wait_for_own_mesh_node(&mesh_node_store, &node_name, &namespace).await;
    let mesh_label = own_mesh_node.spec.mesh_label.clone();

    let private_key = own_private_key(&client, &namespace, &mesh_label).await?;
    let private_key_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(private_key)
    };
    let public_key = common::keys::derive_public_key(private_key);
    meshnodes
        .patch_status(
            &node_name,
            &PatchParams::apply("mesh"),
            &Patch::Merge(&serde_json::json!({ "status": { "publicKey": public_key } })),
        )
        .await
        .context("failed to publish this node's derived public key")?;

    let awg = common::netlink::awg::AwgClient::connect()?;
    let rt = common::netlink::rt::RtClient::connect()?;

    let meshlinks: Api<MeshLink> = Api::namespaced(client.clone(), &namespace);

    // One-time GC against the live API: removes any mesh-* interface with no corresponding
    // MeshLink, covering deletions/repoints missed while this pod wasn't running.
    let startup_links: Vec<Arc<MeshLink>> = meshlinks
        .list(&Default::default())
        .await?
        .items
        .into_iter()
        .map(Arc::new)
        .collect();
    reconcile::gc_stale_interfaces(
        &rt,
        &node_name,
        &namespace,
        &startup_links,
        &mesh_node_store,
    )
    .await?;
    drop(startup_links);

    let ctrl = Controller::new(meshlinks, watcher::Config::default());
    let meshlink_store = ctrl.store();

    // Periodic backstop for a MeshLink's node_a/node_b edited in place to point at a different
    // peer (see gc_stale_interfaces), on a slow bounded interval rather than every reconcile.
    {
        let rt = rt.clone();
        let node_name = node_name.clone();
        let namespace = namespace.clone();
        let meshlink_store = meshlink_store.clone();
        let mesh_node_store = mesh_node_store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // first tick fires immediately; startup GC above already covers it
            loop {
                interval.tick().await;
                if let Err(e) = reconcile::gc_stale_interfaces(
                    &rt,
                    &node_name,
                    &namespace,
                    &meshlink_store.state(),
                    &mesh_node_store,
                )
                .await
                {
                    tracing::warn!(error = %common::reconcile_error::anyhow_chain(&e), "periodic gc_stale_interfaces failed");
                }
            }
        });
    }

    let ctx = Arc::new(reconcile::Context {
        client: client.clone(),
        node_name,
        namespace,
        private_key_b64,
        awg,
        rt,
        meshlink_store: meshlink_store.clone(),
        mesh_node_store,
        dns_cache: awg::DnsCache::default(),
    });

    ctrl.watches(
        meshnodes,
        watcher::Config::default(),
        move |node: MeshNode| {
            // Map a MeshNode change to every MeshLink referencing it, from the in-memory store.
            let name = node.name_any();
            meshlink_store
                .state()
                .into_iter()
                .filter(|link| link.spec.node_a == name || link.spec.node_b == name)
                .map(|link| ObjectRef::from_obj(&*link))
                .collect::<Vec<_>>()
        },
    )
    .run(reconcile::reconcile, reconcile::error_policy, ctx)
    .for_each(|res| async move {
        match res {
            Ok(o) => tracing::debug!(?o, "reconciled"),
            Err(e) => {
                tracing::warn!(error = %common::reconcile_error::error_chain(&e), "reconcile error")
            }
        }
    })
    .await;

    Ok(())
}
