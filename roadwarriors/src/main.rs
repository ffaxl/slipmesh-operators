mod awg;
mod handshake;
mod reconcile;

use common::mesh_types::RoadWarrior;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::Controller;
use kube::runtime::watcher::Config;
use kube::{Api, Client, ResourceExt};
use roadwarriors::ROADWARRIORS_KEY_SECRET;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

const ROADWARRIORS_KEY_FIELD: &str = "privateKey";

/// Parses an optional numeric env var, panicking (not silently ignoring) on a value that's set
/// but unparseable - a typo'd obfuscation param should fail loudly at startup, not silently fall
/// back to "unset".
fn env_opt<T: std::str::FromStr>(key: &str) -> Option<T>
where
    T::Err: std::fmt::Debug,
{
    env::var(key).ok().map(|v| {
        v.parse()
            .unwrap_or_else(|e| panic!("{key} must parse: {e:?}"))
    })
}

/// Reads the shared `roadwarriors` interface's private key from a Secret - identical across every
/// node (unlike mesh's per-node keys), so every DaemonSet pod reads/writes the same single entry.
/// Generates one on first boot; races with every other pod on the initial `Secret::create` - see
/// `common::keys::get_or_create_secret_key`.
async fn shared_private_key(client: &Client, namespace: &str) -> anyhow::Result<[u8; 32]> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    common::keys::get_or_create_secret_key(
        &secrets,
        namespace,
        ROADWARRIORS_KEY_SECRET,
        ROADWARRIORS_KEY_FIELD,
    )
    .await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::maybe_print_version("roadwarriors", env!("CARGO_PKG_VERSION"));

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
    let iface = env::var("ROADWARRIORS_IFACE").unwrap_or_else(|_| "roadwarriors".to_string());
    let address_cidr = env::var("ROADWARRIORS_ADDRESS")
        .expect("ROADWARRIORS_ADDRESS env var must be set (e.g. 172.22.0.1/24)");
    let listen_port: u16 = env::var("ROADWARRIORS_LISTEN_PORT")
        .unwrap_or_else(|_| "51900".to_string())
        .parse()
        .expect("ROADWARRIORS_LISTEN_PORT must be a u16");
    let stale_secs: u64 = env::var("ROADWARRIORS_HANDSHAKE_STALE")
        .unwrap_or_else(|_| "180".to_string())
        .parse()
        .expect("ROADWARRIORS_HANDSHAKE_STALE must be a u64");

    let client = Client::try_default().await?;
    let private_key = shared_private_key(&client, &namespace).await?;
    let private_key_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(private_key)
    };

    // Device-level AmneziaWG obfuscation - one shared config for the whole interface (see
    // `awg.rs`'s module doc). Unset by default, keeping the interface wire-compatible with
    // ordinary WireGuard clients.
    let obfuscation = common::mesh_types::Obfuscation {
        jc: env_opt("ROADWARRIORS_OBFUSCATION_JC"),
        jmin: env_opt("ROADWARRIORS_OBFUSCATION_JMIN"),
        jmax: env_opt("ROADWARRIORS_OBFUSCATION_JMAX"),
        s1: env_opt("ROADWARRIORS_OBFUSCATION_S1"),
        s2: env_opt("ROADWARRIORS_OBFUSCATION_S2"),
        h1: env_opt("ROADWARRIORS_OBFUSCATION_H1"),
        h2: env_opt("ROADWARRIORS_OBFUSCATION_H2"),
        h3: env_opt("ROADWARRIORS_OBFUSCATION_H3"),
        h4: env_opt("ROADWARRIORS_OBFUSCATION_H4"),
    };

    tracing::info!(
        node_name, iface, %address_cidr, listen_port, stale_secs,
        obfuscation = !obfuscation.is_empty(),
        "starting roadwarriors"
    );

    let mut awg = common::netlink::awg::AwgClient::connect()?;
    let rt = common::netlink::rt::RtClient::connect()?;

    let clients_api: Api<RoadWarrior> = Api::namespaced(client.clone(), &namespace);

    // Startup: create the interface, set its identity, and sync the initial peer list. The
    // Controller isn't watching yet, so nothing else touches the interface concurrently.
    let (_index, created) = awg::ensure_link_up(&rt, &iface, &address_cidr).await?;
    awg::set_identity(
        &mut awg,
        &iface,
        &private_key_b64,
        listen_port,
        &obfuscation,
    )
    .await?;

    // If the link already existed (a restart - no shutdown teardown, by design), read back
    // whatever peers the kernel still has instead of assuming none (see `current_peers`).
    let previous_peers = if created {
        Vec::new()
    } else {
        awg::current_peers(&mut awg, &iface).await?
    };

    let initial = clients_api.list(&Default::default()).await?;
    let mut initial_peers = awg::peers_from_clients(initial.items.iter().map(|c| {
        (
            c.name_any(),
            c.spec.public_key.clone(),
            c.spec.allowed_ips.clone(),
        )
    }));
    initial_peers.sort();
    awg::sync_peers(&mut awg, &iface, &previous_peers, &initial_peers).await?;
    tracing::info!(peers = initial_peers.len(), "initial peer sync complete");

    let ctrl = Controller::new(clients_api.clone(), Config::default());
    let client_store = ctrl.store();

    let ctx = Arc::new(reconcile::Context {
        awg: awg.clone(),
        iface: iface.clone(),
        client_store: client_store.clone(),
        clients_api: clients_api.clone(),
        last_peers: Mutex::new(initial_peers),
    });

    // No shutdown teardown: the interface lives in the host netns independent of this process and
    // stays up across a restart/rollout, so clients' live sessions survive an operator update.
    tokio::spawn(handshake::run_forever(
        awg,
        rt,
        handshake::Config {
            iface,
            stale_secs,
            node_name,
            client_store,
            clients_api,
        },
    ));

    ctrl.run(reconcile::reconcile, reconcile::error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::debug!(?o, "reconciled"),
                Err(e) => tracing::warn!(error = %common::reconcile_error::error_chain(&e), "reconcile error"),
            }
        })
        .await;

    Ok(())
}
