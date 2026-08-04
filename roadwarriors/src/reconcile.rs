use crate::awg;
use common::netlink::awg::AwgClient;
pub use common::reconcile_error::{Error, error_policy};
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::reflector::Store;
use kube::{Api, Resource, ResourceExt};
use serde_json::json;
use slipmesh_core::mesh_types::RoadWarrior;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct Context {
    /// Cheap to clone (wraps a channel handle - see genetlink::GenetlinkHandle).
    pub awg: AwgClient,
    pub iface: String,
    /// The Controller's own primary-resource cache (see `Controller::store()` in main.rs).
    pub client_store: Store<RoadWarrior>,
    /// Same `Api` main.rs builds for the initial sync/handshake loop - reused to patch a
    /// RoadWarrior's own status on a public_key conflict.
    pub clients_api: Api<RoadWarrior>,
    /// Peer set (sorted) last actually pushed to the kernel. Diffing against this lets
    /// `sync_peers` touch only the peers that changed. Held across the whole read-diff-sync-write
    /// section: the Controller runs with unbounded concurrency across RoadWarrior objects, so
    /// without this two overlapping reconciles could race on the kernel interface and this cache.
    pub last_peers: Mutex<Vec<awg::Peer>>,
}

async fn set_client_condition(
    api: &Api<RoadWarrior>,
    client: &RoadWarrior,
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
) -> Result<(), Error> {
    let existing = client
        .status
        .as_ref()
        .map_or(&[][..], |s| s.conditions.as_slice());
    let cond = slipmesh_core::condition(
        existing,
        type_,
        status,
        reason,
        message,
        client.meta().generation,
    );
    api.patch_status(
        &client.name_any(),
        &PatchParams::apply("roadwarriors"),
        &Patch::Merge(&json!({ "status": { "conditions": [cond] } })),
    )
    .await?;
    Ok(())
}

/// Every roadwarriors instance runs an identical interface with the full client list as peers, so
/// any single RoadWarrior change re-lists all of them and re-syncs the peer set. Only reacts to
/// actual watch events, not a periodic requeue - interface lifecycle is handled once at
/// startup/shutdown in `main.rs`.
pub async fn reconcile(client: Arc<RoadWarrior>, ctx: Arc<Context>) -> Result<Action, Error> {
    // Guards a startup race: the Controller can schedule a reconcile before `client_store` has
    // ingested the full initial list, which would make the diff below treat every not-yet-
    // ingested client as "removed". Resolves near-instantly once ready.
    ctx.client_store
        .wait_until_ready()
        .await
        .map_err(|e| Error::Other(e.into()))?;
    let all = ctx.client_store.state();

    // public_key-uniqueness check (CRD schema can't express this). Scoped to whichever client's
    // own reconcile is running (no cross-mapping watch like mesh has for MeshNode/MeshLink), so
    // the other colliding client's status only updates once something touches it too.
    if let Some(other) = all
        .iter()
        .find(|c| c.name_any() != client.name_any() && c.spec.public_key == client.spec.public_key)
    {
        let msg = format!("public_key collides with RoadWarrior {}", other.name_any());
        tracing::warn!(client = %client.name_any(), "{msg}");
        set_client_condition(
            &ctx.clients_api,
            &client,
            "Ready",
            "False",
            "PublicKeyConflict",
            &msg,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // AmneziaWG itself accepts any allowedIps entry (IPv4 or IPv6), but the routing side of this
    // stack is IPv4-only end to end: `handshake.rs`'s kernel-route installer and the router's
    // BIRD `learn` filter both skip anything that isn't a plain IPv4 CIDR. A non-IPv4 entry still
    // gets a working AmneziaWG session, but stays reachable only from whichever node this client
    // is currently connected to, with nothing but a log line to explain why - surfaced here so
    // it shows up on the object itself instead.
    let unroutable: Vec<&str> = client
        .spec
        .allowed_ips
        .iter()
        .filter(|net| slipmesh_core::cidr::parse_cidr(net).is_err())
        .map(String::as_str)
        .collect();
    if unroutable.is_empty() {
        set_client_condition(
            &ctx.clients_api,
            &client,
            "AllowedIpsRoutable",
            "True",
            "AllIPv4",
            "every allowedIps entry is a valid IPv4 CIDR and can be learned by the router's BIRD kernel protocol and redistributed cluster-wide over iBGP",
        )
        .await?;
    } else {
        let msg = format!(
            "allowedIps entries not routable outside this tunnel (IPv4 only is supported): {}",
            unroutable.join(", ")
        );
        tracing::warn!(client = %client.name_any(), "{msg}");
        set_client_condition(
            &ctx.clients_api,
            &client,
            "AllowedIpsRoutable",
            "False",
            "NonIPv4AllowedIps",
            &msg,
        )
        .await?;
    }

    let mut desired = awg::peers_from_clients(all.iter().map(|c| {
        (
            c.name_any(),
            c.spec.public_key.clone(),
            c.spec.allowed_ips.clone(),
        )
    }));
    desired.sort();

    // Held for the whole read-diff-sync-write section (see the field doc comment).
    let mut last_peers = ctx.last_peers.lock().await;
    if *last_peers == desired {
        return Ok(Action::await_change());
    }

    let mut awg_client = ctx.awg.clone();
    awg::sync_peers(&mut awg_client, &ctx.iface, &last_peers, &desired).await?;
    tracing::info!(peers = desired.len(), "roadwarriors peer set converged");
    *last_peers = desired;

    Ok(Action::await_change())
}
