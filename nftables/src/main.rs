mod nftables;
mod reconcile;

use futures::StreamExt;
use kube::runtime::Controller;
use kube::runtime::watcher::Config;
use kube::{Api, Client};
use slipmesh_core::nftables_types::NatPrivateRange;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::maybe_print_version("nftables", env!("CARGO_PKG_VERSION"));

    // No timestamp/ANSI: this only ever runs as a container's stdout, which the container
    // runtime/kubelet already timestamps (`kubectl logs --timestamps`) - our own timestamp would
    // just duplicate it, and ANSI color codes have no terminal to render them, so `kubectl logs`
    // would show the raw escape sequences.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .init();

    let namespace =
        env::var("POD_NAMESPACE").expect("POD_NAMESPACE env var must be set (downward API)");

    tracing::info!("starting nftables");

    let rt = common::netlink::rt::RtClient::connect()?;
    let client = Client::try_default().await?;
    let nat_ranges: Api<NatPrivateRange> = Api::namespaced(client.clone(), &namespace);

    let ctrl = Controller::new(nat_ranges, Config::default());
    let nat_range_store = ctrl.store();

    let ctx = Arc::new(reconcile::Context {
        nat_range_store,
        rt,
        last_applied: Mutex::new(None),
    });

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
