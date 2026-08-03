mod bird;
mod netutil;
mod reconcile;
mod resolver;
mod types;

use anyhow::Context as _;
use common::mesh_types::{MeshLink, MeshNode, RoadWarrior};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::networking::v1::ServiceCIDR;
use kube::runtime::reflector;
use kube::runtime::{Controller, watcher};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::hash::Hash;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use types::{BypassSource, RouterNode};

/// Watches `api` in the background for the lifetime of the process, both keeping `writer`'s
/// `Store` live-updated *and* calling `render(&ctx)` on every event - independent of the
/// Controller/MeshLink entirely. Must be a standalone watch, not `.watches(..., mapper)`: that
/// form schedules nothing when the mapper's returned iterator is empty, which would silently
/// drop every RouterNode/MeshNode/BypassSource/RoadWarrior event on a node with zero MeshLinks.
fn spawn_watch_render<K>(
    api: Api<K>,
    writer: reflector::store::Writer<K>,
    ctx: Arc<reconcile::Context>,
) where
    K: Resource + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Hash + Clone + Send + Sync,
{
    tokio::spawn(async move {
        let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()));
        let mut stream = std::pin::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(_) => {
                    if let Err(e) = reconcile::render(&ctx).await {
                        tracing::warn!(error = %common::reconcile_error::error_chain(&e), "render after watch event failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %common::reconcile_error::error_chain(&e), "watch stream error")
                }
            }
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::maybe_print_version("router", env!("CARGO_PKG_VERSION"));

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
    let bgp_as: u32 = env::var("ROUTER_BGP_AS")
        .unwrap_or_else(|_| "64512".to_string())
        .parse()
        .expect("ROUTER_BGP_AS must be a u32");
    let bird_conf_path = PathBuf::from(
        env::var("BIRD_CONF_PATH").unwrap_or_else(|_| "/etc/bird/bird.conf".to_string()),
    );
    let cni_conflist_path = PathBuf::from(
        env::var("CNI_CONFLIST_PATH")
            .unwrap_or_else(|_| "/etc/cni/net.d/10-slipmesh.conflist".to_string()),
    );
    let bypass_refresh_interval = match env::var("ROUTER_BYPASS_REFRESH_INTERVAL") {
        Ok(v) => Duration::from_secs(
            v.parse()
                .expect("ROUTER_BYPASS_REFRESH_INTERVAL must be a u64 (seconds)"),
        ),
        Err(_) => reconcile::DEFAULT_BYPASS_REFRESH_INTERVAL,
    };

    tracing::info!(node_name, bgp_as, bypass_refresh_interval = ?bypass_refresh_interval, "starting router");

    let rt = common::netlink::rt::RtClient::connect()?;

    let mut bird_child = bird::spawn_daemon(&bird_conf_path).await?;
    tokio::spawn(async move {
        match bird_child.wait().await {
            Ok(status) => tracing::error!(%status, "bird daemon exited, crashing pod for restart"),
            Err(e) => {
                tracing::error!(error = %common::reconcile_error::error_chain(&e), "failed waiting on bird daemon")
            }
        }
        std::process::exit(1);
    });

    let client = Client::try_default().await?;

    // One-shot startup: this node's own PodCIDR and the cluster's ServiceCIDR are both immutable
    // once set, so there's nothing to watch/react to here.
    let nodes: Api<Node> = Api::all(client.clone());
    let my_node = nodes
        .get(&node_name)
        .await
        .context("failed to fetch this node's own Node object")?;
    let pod_cidr = my_node
        .spec
        .and_then(|s| s.pod_cidr)
        .with_context(|| format!("Node {node_name} has no spec.podCIDR set"))?;
    bird::write_cni_conflist(&cni_conflist_path, &pod_cidr).await?;
    tracing::info!(pod_cidr, path = %cni_conflist_path.display(), "CNI conflist written");

    let servicecidrs: Api<ServiceCIDR> = Api::all(client.clone());
    let service_cidr = match servicecidrs.get("kubernetes").await {
        Ok(scidr) => scidr,
        Err(_) => servicecidrs
            .list(&Default::default())
            .await
            .context("failed to list ServiceCIDR objects")?
            .items
            .into_iter()
            .next()
            .context("no ServiceCIDR object found in the cluster")?,
    };
    // Picks the first *IPv4* entry, not just the first entry - a dual-stack cluster's ServiceCIDR
    // can list an IPv6 CIDR first, and this whole stack (OSPF/iBGP/BIRD config below) is IPv4-only.
    // Validated as a real aligned network CIDR now (`common::netlink::rt::parse_network_cidr`,
    // the same check every other pool/network field in this codebase goes through) rather than
    // trusting the string as-is - it gets spliced directly into rendered BIRD config
    // (`AnnounceRoute`/`bird::render`'s `ANNOUNCE` block) with no further validation there, so a
    // malformed value must fail loudly here at startup instead of breaking `birdc configure` for
    // this node on some later render.
    let service_cidr_net = service_cidr
        .spec
        .and_then(|s| s.cidrs)
        .into_iter()
        .flatten()
        .find(|c| common::netlink::rt::parse_network_cidr(c).is_ok())
        .context("ServiceCIDR object has no valid IPv4 CIDR set (this stack is IPv4-only)")?;
    let announce_routes = vec![bird::AnnounceRoute {
        net: service_cidr_net.clone(),
        label: "k8s-services".to_string(),
    }];
    tracing::info!(
        service_cidr = service_cidr_net,
        "service CIDR discovered for ANNOUNCE"
    );

    let meshlinks: Api<MeshLink> = Api::namespaced(client.clone(), &namespace);
    let routernodes: Api<RouterNode> = Api::namespaced(client.clone(), &namespace);
    let meshnodes: Api<MeshNode> = Api::namespaced(client.clone(), &namespace);
    let bypasssources: Api<BypassSource> = Api::namespaced(client.clone(), &namespace);
    let roadwarriors: Api<RoadWarrior> = Api::namespaced(client.clone(), &namespace);

    let (router_node_store, router_node_writer) = reflector::store();
    let (mesh_node_store, mesh_node_writer) = reflector::store();
    let (bypass_store, bypass_writer) = reflector::store();
    let (roadwarrior_store, roadwarrior_writer) = reflector::store();

    let ctrl = Controller::new(meshlinks, watcher::Config::default());
    let meshlink_store = ctrl.store();

    let ctx = Arc::new(reconcile::Context {
        client: client.clone(),
        node_name,
        namespace,
        bgp_as,
        bird_conf_path,
        bypass_cache: Mutex::new(HashMap::new()),
        render_lock: Mutex::new(()),
        bypass_refresh_interval,
        rt,
        meshlink_store,
        router_node_store: router_node_store.clone(),
        mesh_node_store: mesh_node_store.clone(),
        bypass_store: bypass_store.clone(),
        roadwarrior_store: roadwarrior_store.clone(),
        announce_routes,
    });

    spawn_watch_render(routernodes, router_node_writer, ctx.clone());
    spawn_watch_render(meshnodes, mesh_node_writer, ctx.clone());
    spawn_watch_render(bypasssources, bypass_writer, ctx.clone());
    spawn_watch_render(roadwarriors, roadwarrior_writer, ctx.clone());

    // The Controller's own watch machinery only starts once its stream is polled (`ctrl.run()`
    // below) - unlike the independent reflectors above, which start populating their store the
    // moment `spawn_watch_render` spawns them. Spawned here (rather than awaited inline at the
    // end of main, as the other three operators do) specifically so `meshlink_store` is already
    // being driven in the background by the time `wait_until_ready` is called on it next -
    // otherwise that call would wait on a store nothing is feeding yet and hang forever.
    let ctrl_ctx = ctx.clone();
    let ctrl_handle = tokio::spawn(async move {
        ctrl.run(reconcile::reconcile, reconcile::error_policy, ctrl_ctx)
            .for_each(|res| async move {
                match res {
                    Ok(o) => tracing::debug!(?o, "reconciled"),
                    Err(e) => tracing::warn!(error = %common::reconcile_error::error_chain(&e), "reconcile error"),
                }
            })
            .await;
    });

    // Read once: wait for each store's initial list before the startup render below - including
    // meshlink_store, whose OSPF interface list the render below depends on (see ctrl_handle).
    router_node_store.wait_until_ready().await?;
    mesh_node_store.wait_until_ready().await?;
    bypass_store.wait_until_ready().await?;
    roadwarrior_store.wait_until_ready().await?;
    ctx.meshlink_store.wait_until_ready().await?;

    // Startup: one full render against whatever RouterNode/MeshLink/MeshNode/BypassSource/
    // RoadWarrior state already exists, not gated on any MeshLink reconcile firing. Cheap even if
    // `spawn_watch_render`'s own initial events (or ctrl_handle's own initial reconciles) already
    // triggered one (render() is a no-op if nothing changed).
    reconcile::render(&ctx).await?;

    // One-time nudge for a startup-only race in bird's own interface-notification timing (see
    // `bird::force_reconfigure`).
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Err(e) = bird::force_reconfigure().await {
            tracing::warn!(error = %common::reconcile_error::anyhow_chain(&e), "startup birdc re-configure nudge failed");
        }
    });

    tokio::spawn(reconcile::bypass_refresh_loop(ctx.clone()));

    ctrl_handle
        .await
        .context("router Controller task panicked")?;

    Ok(())
}
