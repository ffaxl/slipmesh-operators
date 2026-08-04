use crate::nftables;
use common::netlink::rt::RtClient;
pub use common::reconcile_error::{Error, error_policy};
use kube::runtime::controller::Action;
use kube::runtime::reflector::Store;
use slipmesh_core::nftables_types::NatPrivateRange;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct Context {
    /// The Controller's own primary-resource cache (see `Controller::store()` in main.rs) - read
    /// from here instead of a fresh `Api::list()`.
    pub nat_range_store: Store<NatPrivateRange>,
    /// Cheap to clone (wraps an mpsc sender - see rtnetlink::Handle).
    pub rt: RtClient,
    /// (iface, sorted CIDR union) last actually applied - skips re-running `nft` when a reconcile
    /// is triggered by an unrelated event but nothing changed. `Mutex` held across the whole
    /// check-and-apply section, since the Controller runs with unbounded concurrency across
    /// NatPrivateRange objects by default.
    pub last_applied: Mutex<Option<(String, Vec<String>)>>,
}

/// Reacts only to NatPrivateRange watch events (`Action::await_change`, no periodic requeue) -
/// a default-interface change with no CRD change is a problem to fix at its source, not to
/// paper over with a re-scan timer.
pub async fn reconcile(_obj: Arc<NatPrivateRange>, ctx: Arc<Context>) -> Result<Action, Error> {
    let all = ctx.nat_range_store.state();

    let mut nat_private: Vec<String> = all
        .iter()
        .flat_map(|r| r.spec.cidrs.iter().cloned())
        .collect();
    nat_private.sort();
    nat_private.dedup();

    let Some(iface) = ctx.rt.default_iface().await? else {
        tracing::warn!("no default route found, skipping nftables baseline");
        // Bounded retry, not `await_change`: the default route isn't a watched resource, so
        // nothing would wake this reconcile once one appears.
        return Ok(Action::requeue(Duration::from_secs(30)));
    };

    let desired = (iface.clone(), nat_private.clone());
    let mut last_applied = ctx.last_applied.lock().await;
    if last_applied.as_ref() == Some(&desired) {
        return Ok(Action::await_change());
    }

    nftables::apply(&iface, &nat_private).await?;
    *last_applied = Some(desired);

    Ok(Action::await_change())
}
