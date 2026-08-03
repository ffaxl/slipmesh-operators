use crate::bird;
use crate::resolver;
use crate::types::{BypassSource, RouterNode, RouterPool};
use common::mesh_types::{MeshLink, MeshLinkStatus, MeshNode, RoadWarrior};
use common::netlink::rt::RtClient;
pub use common::reconcile_error::{Error, error_policy};
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::reflector::{ObjectRef, Store};
use kube::{Api, Client, Resource, ResourceExt};
use serde_json::json;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Only ever added/removed by the router instance running on the same node as the `RouterNode`
/// it's attached to - unlike `MeshLink`, which two nodes' operators both hold a finalizer on,
/// `RouterNode` has exactly one party, so a single shared finalizer string is enough.
const ROUTER_POOL_FINALIZER: &str = "slipmesh.net/router-pool-release";

/// Fallback when `ROUTER_BYPASS_REFRESH_INTERVAL` isn't set - once a day, since RIPEstat/DNS data
/// doesn't change often enough to justify re-resolving hourly by default.
pub const DEFAULT_BYPASS_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Context {
    pub client: Client,
    pub node_name: String,
    /// Namespace all of this operator's CRs live in (from `POD_NAMESPACE`). Namespaced purely
    /// for RBAC hygiene; `Node`/`ServiceCIDR` stay `Api::all` since those are cluster-scoped
    /// Kubernetes built-ins.
    pub namespace: String,
    pub bgp_as: u32,
    pub bird_conf_path: PathBuf,
    /// Last-successful bypass resolution, keyed by BypassSource name - re-resolving (RIPEstat/
    /// DNS) only happens on the startup/refresh-interval/spec-change schedule (`needs_resolve`);
    /// every other reconcile reuses this instead of repeating network I/O.
    pub bypass_cache: Mutex<HashMap<String, CachedBypass>>,
    /// Serializes `render()`: the Controller runs with unbounded concurrency across different
    /// MeshLink objects, and the hourly `bypass_refresh_loop` calls `render()` independently.
    /// Without this, two overlapping renders could interleave writes to `bird_conf_path` and
    /// issue concurrent `birdc configure` calls against the same daemon.
    pub render_lock: Mutex<()>,
    /// Cheap to clone (wraps an mpsc sender - see rtnetlink::Handle).
    pub rt: RtClient,
    /// How often `bypass_refresh_loop` re-checks bypass staleness, and the threshold
    /// `needs_resolve` compares elapsed time against.
    pub bypass_refresh_interval: Duration,
    /// The Controller's own primary-resource cache (see `Controller::store()` in main.rs).
    pub meshlink_store: Store<MeshLink>,
    /// Populated by independent reflectors in main.rs.
    pub router_node_store: Store<RouterNode>,
    pub mesh_node_store: Store<MeshNode>,
    pub bypass_store: Store<BypassSource>,
    /// Every currently-declared RoadWarrior client, read-only (roadwarriors owns the CRD) -
    /// `render()` turns their `allowedIps` into the BIRD kernel protocol's scoped `learn` import
    /// filter, so a client's host route (installed directly into the kernel by roadwarriors'
    /// handshake loop, on whichever node it's actually connected to) gets re-announced over iBGP.
    pub roadwarrior_store: Store<RoadWarrior>,
    /// Static for the process lifetime - read once at startup from the cluster's `ServiceCIDR`
    /// object, since it's immutable once set. Rendered into the `ANNOUNCE` BIRD block every
    /// `render()` regardless.
    pub announce_routes: Vec<bird::AnnounceRoute>,
}

/// One BypassSource's last successful resolution, plus the input not visible in its own spec:
/// the MeshNode endpoint set that was punched out of it.
pub struct CachedBypass {
    routes: Vec<(String, String)>,
    /// Sorted, so comparison is order-insensitive - `mesh_node_store.state()` has no defined
    /// order.
    endpoints: Vec<String>,
}

/// True if this BypassSource has never been successfully resolved, was last resolved more than
/// `refresh_interval` ago, or its spec changed since the last successful resolution
/// (`status.observedGeneration` mismatch) - i.e. exactly "at startup, on the configured refresh
/// interval, or on CR change".
fn needs_resolve(bypass: &BypassSource, refresh_interval: Duration) -> bool {
    let Some(status) = &bypass.status else {
        return true;
    };
    if status.observed_generation != bypass.meta().generation {
        return true;
    }
    let Some(last) = &status.last_resolved_time else {
        return true;
    };
    let Ok(last_ts) = last.parse::<k8s_openapi::jiff::Timestamp>() else {
        return true;
    };
    let elapsed = k8s_openapi::jiff::Timestamp::now()
        .duration_since(last_ts)
        .unsigned_abs();
    elapsed >= refresh_interval
}

async fn set_router_node_status(
    api: &Api<RouterNode>,
    node: &RouterNode,
    status: &str,
    reason: &str,
    message: &str,
) -> Result<(), Error> {
    let existing = node
        .status
        .as_ref()
        .map_or(&[][..], |s| s.conditions.as_slice());
    let cond = common::reconcile_error::condition(
        existing,
        "Ready",
        status,
        reason,
        message,
        node.meta().generation,
    );
    api.patch_status(
        &node.name_any(),
        &PatchParams::apply("router"),
        &Patch::Merge(&json!({ "status": { "conditions": [cond] } })),
    )
    .await?;
    Ok(())
}

async fn set_bypass_status(
    api: &Api<BypassSource>,
    bypass: &BypassSource,
    prefix_count: u32,
    resolved_ok: bool,
    reason: &str,
    message: &str,
) -> Result<(), Error> {
    let now = k8s_openapi::jiff::Timestamp::now();
    let existing = bypass
        .status
        .as_ref()
        .map_or(&[][..], |s| s.conditions.as_slice());
    let cond = common::reconcile_error::condition(
        existing,
        "Resolved",
        if resolved_ok { "True" } else { "False" },
        reason,
        message,
        bypass.meta().generation,
    );
    let status = if resolved_ok {
        json!({
            "conditions": [cond],
            "prefixCount": prefix_count,
            "lastResolvedTime": now.to_string(),
            "observedGeneration": bypass.meta().generation,
        })
    } else {
        // Deliberately omit lastResolvedTime/observedGeneration on failure - see needs_resolve.
        json!({ "conditions": [cond] })
    };
    api.patch_status(
        &bypass.name_any(),
        &PatchParams::apply("router"),
        &Patch::Merge(&json!({ "status": status })),
    )
    .await?;
    Ok(())
}

/// Resolves this node's BypassSource (if any) into concrete blackhole routes, re-resolving only
/// when `needs_resolve` says so (startup / interval / spec changed) - RIPEstat/DNS lookups are
/// slow, non-deterministic network I/O kept off the hot path. A failed re-resolve keeps serving
/// the last-known-good cached result rather than blanking the bypass out over a transient outage.
/// Reads the BypassSource spec from `ctx.bypass_store`, never lists it fresh.
async fn current_bypass_routes(
    ctx: &Context,
    self_and_cluster_endpoints: Vec<String>,
) -> Result<Vec<bird::BypassRoute>, Error> {
    let bypasses: Api<BypassSource> = Api::namespaced(ctx.client.clone(), &ctx.namespace);

    // CRD schema can't express "at most one BypassSource per node". The first match by name is
    // picked deterministically; any others are reported via their own status, not blocking.
    let mut matches: Vec<BypassSource> = ctx
        .bypass_store
        .state()
        .into_iter()
        .filter(|b| b.spec.node == ctx.node_name)
        .map(|b| (*b).clone())
        .collect();
    matches.sort_by_key(ResourceExt::name_any);
    let Some(bypass) = matches.first().cloned() else {
        return Ok(Vec::new());
    };
    if matches.len() > 1 {
        let msg = format!(
            "node {:?} has {} BypassSource objects ({}) - only {} is used, the rest are ignored",
            ctx.node_name,
            matches.len(),
            matches
                .iter()
                .map(ResourceExt::name_any)
                .collect::<Vec<_>>()
                .join(", "),
            bypass.name_any()
        );
        tracing::warn!(node = %ctx.node_name, "{msg}");
        for other in &matches[1..] {
            set_bypass_status(&bypasses, other, 0, false, "NodeConflict", &msg).await?;
        }
    }
    let name = bypass.name_any();

    let mut endpoints = self_and_cluster_endpoints;
    endpoints.sort();
    endpoints.dedup();

    // The cache is per-pod and doesn't survive a restart, but `needs_resolve` only looks at
    // cluster-visible status - force a resolve whenever the cache has no entry yet, regardless
    // of staleness.
    //
    // The endpoint comparison covers what `needs_resolve` can't see: the MeshNode endpoint set
    // lives outside this BypassSource's spec/status, so a node joining, leaving, or changing its
    // endpoint must re-trigger the punch-out rather than waiting out the refresh interval - these
    // BYPASS statics are redistributed over iBGP, so every other node would blackhole the new
    // endpoint until then.
    let (cache_empty, endpoints_changed) = {
        let cache = ctx.bypass_cache.lock().await;
        match cache.get(&name) {
            None => (true, false),
            Some(cached) => (false, cached.endpoints != endpoints),
        }
    };

    if cache_empty || endpoints_changed || needs_resolve(&bypass, ctx.bypass_refresh_interval) {
        // The self/cluster punch-out is just one more `exclude` entry, resolved the same way as
        // any other (see `resolver::resolve`).
        let mut exclude = bypass.spec.exclude.clone();
        exclude.push(resolver::self_and_cluster_exclude_entry(endpoints.clone()));
        match resolver::resolve(&bypass.spec.include, &exclude).await {
            Ok(resolved) => {
                tracing::info!(node = %ctx.node_name, count = resolved.len(), "bypass sources resolved");
                set_bypass_status(
                    &bypasses,
                    &bypass,
                    resolved.len() as u32,
                    true,
                    "Resolved",
                    "sources resolved successfully",
                )
                .await?;
                ctx.bypass_cache.lock().await.insert(
                    name.clone(),
                    CachedBypass {
                        routes: resolved.clone(),
                        endpoints,
                    },
                );
                return Ok(resolved
                    .into_iter()
                    .map(|(net, label)| bird::BypassRoute { net, label })
                    .collect());
            }
            Err(e) => {
                // Deliberately does *not* propagate `e` up through `render()`: that would block
                // this node's unrelated OSPF/iBGP convergence on a slow/failing upstream until
                // bypass eventually resolves. `ResolveFailed` below is the surfacing mechanism,
                // not a hard failure of this reconcile.
                if cache_empty {
                    tracing::warn!(node = %ctx.node_name, error = %e, "bypass resolution failed with nothing cached yet - serving no bypass routes this pass");
                } else {
                    tracing::warn!(node = %ctx.node_name, error = %e, "bypass resolution failed, keeping last-known-good routes");
                }
                set_bypass_status(
                    &bypasses,
                    &bypass,
                    0,
                    false,
                    "ResolveFailed",
                    &e.to_string(),
                )
                .await?;
                // fall through to the cache below
            }
        }
    }

    Ok(ctx
        .bypass_cache
        .lock()
        .await
        .get(&name)
        .map(|c| c.routes.clone())
        .unwrap_or_default()
        .into_iter()
        .map(|(net, label)| bird::BypassRoute { net, label })
        .collect())
}

/// What `render()` actually managed to do this pass - `reconcile()` uses this to pick its
/// `Action`; the other two callers only care whether `render()` returned `Err` at all.
pub enum RenderOutcome {
    Converged,
    /// Loopback allocation hit a structural problem this pass (pin outside every configured
    /// `RouterPool`'s range, pin already claimed by another node, or every pool exhausted) -
    /// nothing was rendered/applied.
    Conflict,
}

/// Successive loopback candidates within `network/prefix_len`, in address order - skips `.0`
/// (not a usable host address). Paired with `None` (no port concept) to match `common::pool::allocate`'s
/// generic candidate shape.
fn router_pool_candidates(
    network: Ipv4Addr,
    prefix_len: u8,
) -> impl Iterator<Item = (String, Option<u16>)> {
    let network_u32 = u32::from(network);
    let host_bits = 32 - u32::from(prefix_len);
    let network_size: u64 = 1u64 << host_bits;
    (1u32..).map_while(move |offset| {
        let addr = network_u32.checked_add(offset)?;
        let in_range = (u64::from(offset)) < network_size;
        in_range.then(|| (Ipv4Addr::from(addr).to_string(), None))
    })
}

/// A `RouterPool`'s parsed/validated `spec.network` - see `common::pool::valid_pools`.
struct RouterPoolInfo {
    network: Ipv4Addr,
    prefix_len: u8,
}

async fn valid_pools(
    pools_api: &Api<RouterPool>,
) -> Result<Vec<common::pool::ParsedPool<RouterPoolInfo>>, Error> {
    Ok(common::pool::valid_pools(pools_api, |p| {
        let (network, prefix_len) = common::netlink::rt::parse_network_cidr(&p.spec.network)?;
        Ok(RouterPoolInfo {
            network,
            prefix_len,
        })
    })
    .await?)
}

async fn patch_router_node_loopback(
    api: &Api<RouterNode>,
    name: &str,
    pool: &str,
    loopback: Ipv4Addr,
) -> Result<(), Error> {
    let patch = json!({ "status": { "pool": pool, "loopback": loopback.to_string() } });
    api.patch_status(name, &PatchParams::apply("router"), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

/// Mirrors `mesh::reconcile::allocate_link_addressing` - tries `node.spec.loopback` (a pin)
/// first if set, else walks every `RouterPool` in name order via `common::pool::allocate`. On success,
/// patches this RouterNode's status and returns `Ok(true)`. On a structural problem sets a status
/// condition and returns `Ok(false)` - not a hard reconcile error, the caller retries.
async fn allocate_router_loopback(
    ctx: &Context,
    router_nodes: &Api<RouterNode>,
    node: &RouterNode,
) -> Result<bool, Error> {
    let pools_api: Api<RouterPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let pools = valid_pools(&pools_api).await?;

    if let Some(pinned) = node.spec.loopback {
        let Some(pool) = pools.iter().find(|p| {
            common::netlink::rt::cidr_contains(p.value.network, p.value.prefix_len, pinned)
        }) else {
            let msg = format!("no RouterPool configured contains pinned loopback {pinned}");
            tracing::warn!(node = %ctx.node_name, "{msg}");
            set_router_node_status(router_nodes, node, "False", "PinOutOfRange", &msg).await?;
            return Ok(false);
        };
        return match common::pool::allocate(
            &pools_api,
            &pool.name,
            &ctx.node_name,
            std::iter::once((pinned.to_string(), None)),
        )
        .await?
        {
            Some(_) => {
                patch_router_node_loopback(router_nodes, &ctx.node_name, &pool.name, pinned)
                    .await?;
                Ok(true)
            }
            None => {
                let msg =
                    format!("pinned loopback {pinned} is already allocated to another RouterNode");
                tracing::warn!(node = %ctx.node_name, "{msg}");
                set_router_node_status(router_nodes, node, "False", "PinConflict", &msg).await?;
                Ok(false)
            }
        };
    }

    for pool in &pools {
        let candidates = router_pool_candidates(pool.value.network, pool.value.prefix_len);
        if let Some((value, _)) =
            common::pool::allocate(&pools_api, &pool.name, &ctx.node_name, candidates).await?
        {
            let addr: Ipv4Addr = value
                .parse()
                .expect("value came from this same pool's own router_pool_candidates");
            patch_router_node_loopback(router_nodes, &ctx.node_name, &pool.name, addr).await?;
            return Ok(true);
        }
    }
    let msg = "no RouterPool has room for a new node".to_string();
    tracing::warn!(node = %ctx.node_name, "{msg}");
    set_router_node_status(router_nodes, node, "False", "PoolExhausted", &msg).await?;
    Ok(false)
}

/// Recomputes the full OSPF interface set, iBGP peer set, and bypass routes for this node, and
/// reloads BIRD. Reads every input from this operator's own reflector caches (`ctx.*_store`),
/// never a fresh `Api::list`/`Api::get` - shared by both the Controller's `reconcile()`
/// (triggered by watch events) and the periodic bypass-refresh timer in main.rs.
pub async fn render(ctx: &Context) -> Result<RenderOutcome, Error> {
    // Held for the whole render - see the field doc comment on `Context::render_lock`.
    let _render_guard = ctx.render_lock.lock().await;

    let Some(my_router_node) = ctx
        .router_node_store
        .get(&ObjectRef::new(&ctx.node_name).within(&ctx.namespace))
    else {
        tracing::warn!(node = %ctx.node_name, "no RouterNode for this node yet, skipping");
        return Ok(RenderOutcome::Converged);
    };

    let router_nodes: Api<RouterNode> = Api::namespaced(ctx.client.clone(), &ctx.namespace);

    // Deletion/finalizer handling - only ever acted on by the router instance running on this
    // same node (see ROUTER_POOL_FINALIZER). A deletion event for some other node's RouterNode
    // falls through to the normal render path below, unaffected.
    if my_router_node.meta().deletion_timestamp.is_some() {
        if my_router_node
            .finalizers()
            .iter()
            .any(|f| f == ROUTER_POOL_FINALIZER)
        {
            if let Some(pool_name) = my_router_node
                .status
                .as_ref()
                .and_then(|s| s.pool.as_deref())
            {
                let pools_api: Api<RouterPool> =
                    Api::namespaced(ctx.client.clone(), &ctx.namespace);
                if let Err(e) = common::pool::release(&pools_api, pool_name, &ctx.node_name).await {
                    tracing::warn!(node = %ctx.node_name, pool = pool_name, error = %e, "failed to release RouterPool slot on delete");
                }
            }
            let patch = json!({ "metadata": { "finalizers": my_router_node.finalizers().iter().filter(|f| *f != ROUTER_POOL_FINALIZER).collect::<Vec<_>>() } });
            router_nodes
                .patch(
                    &ctx.node_name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await?;
        }
        return Ok(RenderOutcome::Converged);
    }

    if !my_router_node
        .finalizers()
        .iter()
        .any(|f| f == ROUTER_POOL_FINALIZER)
    {
        let mut finalizers = my_router_node.finalizers().to_vec();
        finalizers.push(ROUTER_POOL_FINALIZER.to_string());
        router_nodes
            .patch(
                &ctx.node_name,
                &PatchParams::default(),
                &Patch::Merge(&json!({ "metadata": { "finalizers": finalizers } })),
            )
            .await?;
    }

    // Loopback comes from a RouterPool, not a human-picked spec field; allocate on demand rather
    // than requiring one to already be present.
    let loopback = match my_router_node.status.as_ref().and_then(|s| s.loopback) {
        Some(lb) => lb,
        None => {
            return match allocate_router_loopback(ctx, &router_nodes, &my_router_node).await? {
                // The status patch above re-triggers render() with fresh data via the RouterNode
                // watch in main.rs.
                true => Ok(RenderOutcome::Converged),
                false => Ok(RenderOutcome::Conflict),
            };
        }
    };

    // router_label uniqueness (CRD schema can't express cross-object uniqueness - see
    // RouterNodeSpec::router_label's doc comment). Compared post-sanitization: two labels that
    // only differ in characters `sanitize_bird_id` strips (e.g. "ams-1" and "ams_1") still
    // collide on the same `ibgp_<label>` BIRD identifier. A collision renders two identically
    // named protocol blocks; `birdc configure` rejects the whole file, breaking this node's
    // OSPF/iBGP convergence entirely - so this blocks rendering the same way a loopback
    // allocation conflict does, rather than rendering a config known to fail.
    let my_sanitized_label = bird::sanitize_bird_id(&my_router_node.spec.router_label);
    if let Some(other) = ctx.router_node_store.state().iter().find(|n| {
        n.name_any() != ctx.node_name
            && bird::sanitize_bird_id(&n.spec.router_label) == my_sanitized_label
    }) {
        let msg = format!(
            "router_label {:?} collides with RouterNode {}'s {:?} after BIRD identifier \
             sanitization (both become {my_sanitized_label:?})",
            my_router_node.spec.router_label,
            other.name_any(),
            other.spec.router_label,
        );
        tracing::warn!(node = %ctx.node_name, "{msg}");
        set_router_node_status(
            &router_nodes,
            &my_router_node,
            "False",
            "RouterLabelConflict",
            &msg,
        )
        .await?;
        return Ok(RenderOutcome::Conflict);
    }

    let bgp_peers: Vec<bird::BgpPeer> = ctx
        .router_node_store
        .state()
        .iter()
        .filter(|n| n.name_any() != ctx.node_name)
        .filter_map(|n| {
            // A peer with no loopback allocated yet isn't ready to be an iBGP peer - skipped,
            // not an error; shows up on a later render() once its status is populated.
            let peer_loopback = n.status.as_ref().and_then(|s| s.loopback)?;
            Some(bird::BgpPeer {
                label: bird::sanitize_bird_id(&n.spec.router_label),
                loopback: peer_loopback,
            })
        })
        .collect();

    let all_links = ctx.meshlink_store.state();
    // Interface names built from the peer MeshNode's `mesh_label`, not its Kubernetes Node name -
    // must match exactly what mesh created the interface as. A peer whose MeshNode can't be
    // found is skipped with a warning rather than guessed at.
    let mut ospf_ifaces: Vec<String> = all_links
        .iter()
        .filter(|l| l.status.as_ref().is_some_and(MeshLinkStatus::is_ready))
        .filter_map(|l| {
            let peer = l.spec.peer_label(&ctx.node_name)?;
            let Some(peer_node) = ctx
                .mesh_node_store
                .get(&ObjectRef::new(peer).within(&ctx.namespace))
            else {
                tracing::warn!(link = %l.name_any(), peer, "MeshNode not found, skipping in OSPF interface list");
                return None;
            };
            Some(format!("mesh-{}", peer_node.spec.mesh_label))
        })
        .collect();
    ospf_ifaces.sort();
    ospf_ifaces.dedup();

    // Every MeshNode's endpoint (IP or hostname, both resolved via
    // `resolver::self_and_cluster_exclude_entry`) - self/cluster addresses must never be
    // blackholed by a bypass.
    let self_and_cluster_endpoints: Vec<String> = ctx
        .mesh_node_store
        .state()
        .iter()
        .filter_map(|n| n.spec.endpoint.clone())
        .collect();

    let bypass_routes = current_bypass_routes(ctx, self_and_cluster_endpoints).await?;

    // Every RoadWarrior's allowedIps, validated as plain IPv4 CIDRs before ever reaching the BIRD
    // config text - a malformed or IPv6 entry is dropped with a warning rather than injected
    // as-is (schema `format: cidr` is a hint, not apiserver-enforced). Sorted/deduped for a stable
    // rendered config across reconciles.
    let mut learn_networks: Vec<String> = ctx
        .roadwarrior_store
        .state()
        .iter()
        .flat_map(|c| c.spec.allowed_ips.iter().cloned())
        .filter_map(|entry| match common::netlink::rt::parse_cidr(&entry) {
            Ok((addr, prefix)) => Some(format!("{addr}/{prefix}")),
            Err(e) => {
                tracing::warn!(entry, error = %e, "skipping malformed RoadWarrior allowedIps entry in BIRD learn filter");
                None
            }
        })
        .collect();
    learn_networks.sort();
    learn_networks.dedup();

    bird::ensure_loopback(&ctx.rt, loopback).await?;
    bird::reconcile(
        &ctx.bird_conf_path,
        loopback,
        ctx.bgp_as,
        &ospf_ifaces,
        &bgp_peers,
        &bypass_routes,
        &ctx.announce_routes,
        &learn_networks,
    )
    .await?;

    tracing::info!(
        node = %ctx.node_name,
        ospf_ifaces = ?ospf_ifaces,
        bgp_peers = bgp_peers.len(),
        bypass_routes = bypass_routes.len(),
        announce_routes = ctx.announce_routes.len(),
        learn_networks = learn_networks.len(),
        "router state converged"
    );
    Ok(RenderOutcome::Converged)
}

pub async fn reconcile(_link: Arc<MeshLink>, ctx: Arc<Context>) -> Result<Action, Error> {
    match render(&ctx).await? {
        RenderOutcome::Converged => Ok(Action::await_change()),
        // Bounded retry: fixing a loopback collision means editing the other RouterNode, an
        // object this reconcile has no subscription to.
        RenderOutcome::Conflict => Ok(Action::requeue(Duration::from_secs(30))),
    }
}

/// Runs forever as its own background task, independent of the kube reconcile loop - the
/// periodic bypass re-resolve must happen even without CRD changes. `needs_resolve`'s staleness
/// check inside `current_bypass_routes` decides whether an actual re-resolve happens, so a recent
/// watch-triggered refresh makes this a no-op.
pub async fn bypass_refresh_loop(ctx: Arc<Context>) {
    let mut tick = tokio::time::interval(ctx.bypass_refresh_interval);
    tick.tick().await; // first tick fires immediately; the real work already happened at startup
    loop {
        tick.tick().await;
        if let Err(e) = render(&ctx).await {
            tracing::warn!(error = %e, "hourly bypass refresh failed");
        }
    }
}
