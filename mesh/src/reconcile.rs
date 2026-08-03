use crate::{awg, mesh_math};
use common::mesh_types::{MeshLink, MeshNode, MeshPool};
use common::netlink::awg::AwgClient;
use common::netlink::rt::RtClient;
pub use common::reconcile_error::{Error, error_policy};
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::reflector::{ObjectRef, Store};
use kube::{Api, Client, Resource, ResourceExt};
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

/// Per-node, not a single shared constant: a MeshLink has two independent owners, each of which
/// must remove its own `mesh-<peer>` interface before the object can be deleted. A single shared
/// finalizer can't express "both parties are done".
fn finalizer_for(node_name: &str) -> String {
    format!("slipmesh.net/interface-cleanup-{node_name}")
}

pub struct Context {
    pub client: Client,
    /// This pod's own MeshNode name - must equal the Kubernetes Node it runs on.
    pub node_name: String,
    /// Namespace all of this operator's CRs live in (from `POD_NAMESPACE`). Namespaced purely
    /// for RBAC hygiene - there's only ever one instance of it.
    pub namespace: String,
    /// Loaded once at startup - see main.rs.
    pub private_key_b64: String,
    /// Cheap to clone (wraps a channel handle - see genetlink::GenetlinkHandle).
    pub awg: AwgClient,
    /// Cheap to clone (wraps an mpsc sender - see rtnetlink::Handle).
    pub rt: RtClient,
    /// The Controller's own primary-resource cache (see `Controller::store()` in main.rs).
    pub meshlink_store: Store<MeshLink>,
    /// Populated by an independent reflector in main.rs.
    pub mesh_node_store: Store<MeshNode>,
    pub dns_cache: awg::DnsCache,
}

async fn set_condition(
    api: &Api<MeshLink>,
    link: &MeshLink,
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
) -> Result<(), Error> {
    let existing = link
        .status
        .as_ref()
        .map_or(&[][..], |s| s.conditions.as_slice());
    let cond = common::reconcile_error::condition(
        existing,
        type_,
        status,
        reason,
        message,
        link.meta().generation,
    );
    let patch = json!({
        "status": { "conditions": [cond] }
    });
    api.patch_status(
        &link.name_any(),
        &PatchParams::apply("mesh"),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

async fn set_mesh_node_condition(
    api: &Api<MeshNode>,
    node: &MeshNode,
    type_: &str,
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
        type_,
        status,
        reason,
        message,
        node.meta().generation,
    );
    api.patch_status(
        &node.name_any(),
        &PatchParams::apply("mesh"),
        &Patch::Merge(&json!({ "status": { "conditions": [cond] } })),
    )
    .await?;
    Ok(())
}

/// Garbage-collects any `mesh-*` interface on the host with no active MeshLink for this node.
/// Direct MeshLink deletion is handled inline by the finalizer path in `reconcile()`; this covers
/// the one gap that leaves: `node_a`/`node_b` edited in place to point at a different peer, which
/// orphans the old interface without a deletion event. Run once at startup and on a slow periodic
/// timer rather than inline on every reconcile, since `list_links` is a full netlink dump.
///
/// Takes the current MeshLink set as a slice - the caller decides list vs. cache.
///
/// A link whose peer `MeshNode` can't be found in `mesh_node_store` is skipped with a warning
/// (no safe fallback interface name to guess).
pub async fn gc_stale_interfaces(
    rt: &RtClient,
    node_name: &str,
    namespace: &str,
    all_links: &[Arc<MeshLink>],
    mesh_node_store: &Store<MeshNode>,
) -> anyhow::Result<()> {
    let desired_ifaces: Vec<String> = all_links
        .iter()
        .filter(|l| l.spec.node_a == node_name || l.spec.node_b == node_name)
        .filter_map(|l| {
            let peer = l
                .spec
                .peer_label(node_name)
                .expect("already filtered to links involving node_name");
            let Some(peer_node) = mesh_node_store.get(&ObjectRef::new(peer).within(namespace))
            else {
                tracing::warn!(link = %l.name_any(), peer, "MeshNode not found, skipping in stale-interface scan");
                return None;
            };
            Some(format!("mesh-{}", peer_node.spec.mesh_label))
        })
        .collect();

    let existing = awg::existing_mesh_interfaces(rt).await?;
    for iface in existing {
        if !desired_ifaces.contains(&iface) {
            tracing::info!(iface, "removing stale mesh interface");
            awg::remove_interface(rt, &iface).await?;
        }
    }
    Ok(())
}

async fn patch_link_allocation(
    api: &Api<MeshLink>,
    name: &str,
    pool: &str,
    network: &str,
    port: u16,
) -> Result<(), Error> {
    let patch = json!({ "status": { "pool": pool, "network": network, "port": port } });
    api.patch_status(name, &PatchParams::apply("mesh"), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

fn link_port(
    network: Ipv4Addr,
    prefix_len: u8,
    base_port: u16,
    index: u32,
    link: &MeshLink,
    me: &str,
) -> Result<u16, Error> {
    Ok(mesh_math::addressing_for(
        network,
        prefix_len,
        base_port,
        index,
        &link.spec.node_a,
        &link.spec.node_b,
        me,
    )?
    .port)
}

/// A `MeshPool`'s parsed/validated `spec.network` plus its `base_port`.
struct MeshPoolInfo {
    network: Ipv4Addr,
    prefix_len: u8,
    base_port: u16,
}

async fn valid_pools(
    pools_api: &Api<MeshPool>,
) -> Result<Vec<common::pool::ParsedPool<MeshPoolInfo>>, Error> {
    Ok(common::pool::valid_pools(pools_api, |p| {
        let (network, prefix_len) = common::netlink::rt::parse_network_cidr(&p.spec.network)?;
        Ok(MeshPoolInfo {
            network,
            prefix_len,
            base_port: p.spec.base_port,
        })
    })
    .await?)
}

/// Called by the "lower" node of a link once `link.status.network` is empty (see
/// `MeshLinkSpec::is_lower`). Tries `link.spec.network` (a pin) first, else walks every
/// `MeshPool` in name order via `common::pool::allocate`. On success, patches this MeshLink's status with
/// the resolved pool/network/port and returns `Ok(true)`. On a structural problem (pin out of
/// range, pin conflict, pools exhausted) sets a status condition and returns `Ok(false)` - not a
/// hard reconcile error, the caller retries with a bounded delay.
async fn allocate_link_addressing(
    ctx: &Context,
    meshlink_api: &Api<MeshLink>,
    link: &MeshLink,
    name: &str,
) -> Result<bool, Error> {
    let pools_api: Api<MeshPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let pools = valid_pools(&pools_api).await?;

    if let Some(pinned) = &link.spec.network {
        let (pinned_addr, prefix) = common::netlink::rt::parse_cidr(pinned)?;
        if prefix != 31 {
            let msg = format!("pinned network {pinned:?} is not a /31");
            tracing::warn!(link = %name, "{msg}");
            set_condition(meshlink_api, link, "Ready", "False", "PinOutOfRange", &msg).await?;
            return Ok(false);
        }
        let Some(pool) = pools.iter().find(|p| {
            common::netlink::rt::cidr_contains(p.value.network, p.value.prefix_len, pinned_addr)
        }) else {
            let msg = format!("no MeshPool configured contains pinned network {pinned:?}");
            tracing::warn!(link = %name, "{msg}");
            set_condition(meshlink_api, link, "Ready", "False", "PinOutOfRange", &msg).await?;
            return Ok(false);
        };
        // `cidr_contains` only proves the pin is inside the pool's range, not aligned to a /31
        // boundary (e.g. an odd offset). Report misalignment as a config error, not a panic.
        let Some(index) = mesh_math::index_of(pool.value.network, pinned_addr) else {
            let msg = format!(
                "pinned network {pinned:?} is not aligned to a /31 slot boundary of MeshPool {:?} \
                 ({}) - only even offsets from the pool base are valid slots",
                pool.name, pool.value.network
            );
            tracing::warn!(link = %name, "{msg}");
            set_condition(meshlink_api, link, "Ready", "False", "PinOutOfRange", &msg).await?;
            return Ok(false);
        };
        let port = link_port(
            pool.value.network,
            pool.value.prefix_len,
            pool.value.base_port,
            index,
            link,
            &ctx.node_name,
        )?;
        return match common::pool::allocate(
            &pools_api,
            &pool.name,
            name,
            std::iter::once((pinned.clone(), Some(port))),
        )
        .await?
        {
            Some((value, port)) => {
                let port = port.expect("mesh candidates always carry Some(port)");
                patch_link_allocation(meshlink_api, name, &pool.name, &value, port).await?;
                Ok(true)
            }
            None => {
                let msg =
                    format!("pinned network {pinned:?} is already allocated to another MeshLink");
                tracing::warn!(link = %name, "{msg}");
                set_condition(meshlink_api, link, "Ready", "False", "PinConflict", &msg).await?;
                Ok(false)
            }
        };
    }

    for pool in &pools {
        let candidates = mesh_math::candidate_networks(
            pool.value.network,
            pool.value.prefix_len,
            pool.value.base_port,
        )
        .map(|(value, port)| (value, Some(port)));
        if let Some((value, port)) =
            common::pool::allocate(&pools_api, &pool.name, name, candidates).await?
        {
            let port = port.expect("mesh candidates always carry Some(port)");
            patch_link_allocation(meshlink_api, name, &pool.name, &value, port).await?;
            return Ok(true);
        }
    }
    let msg = "no MeshPool has room for a new link".to_string();
    tracing::warn!(link = %name, "{msg}");
    set_condition(meshlink_api, link, "Ready", "False", "PoolExhausted", &msg).await?;
    Ok(false)
}

pub async fn reconcile(link: Arc<MeshLink>, ctx: Arc<Context>) -> Result<Action, Error> {
    let meshlink_api: Api<MeshLink> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let name = link.name_any();
    let involved = link.spec.node_a == ctx.node_name || link.spec.node_b == ctx.node_name;
    let our_finalizer = finalizer_for(&ctx.node_name);

    // Deletion / finalizer handling. An uninvolved node never held this node's own finalizer and
    // has no interface to clean up here.
    if link.meta().deletion_timestamp.is_some() {
        if involved && link.finalizers().iter().any(|f| f == &our_finalizer) {
            let peer = link
                .spec
                .peer_label(&ctx.node_name)
                .expect("involved already checked node_a/node_b match");
            // If the peer MeshNode is already gone, there's no safe way to know the interface
            // name - skip direct removal and leave it to the periodic gc_stale_interfaces
            // backstop. The finalizer is released regardless.
            match ctx
                .mesh_node_store
                .get(&ObjectRef::new(peer).within(&ctx.namespace))
            {
                Some(peer_node) => {
                    let iface = format!("mesh-{}", peer_node.spec.mesh_label);
                    awg::remove_interface(&ctx.rt, &iface).await?;
                }
                None => {
                    tracing::warn!(link = %name, peer, "peer MeshNode not found on delete - skipping direct interface removal, periodic GC will catch it");
                }
            }

            // Only the "lower" side ever wrote a MeshPool entry for this link. A release failure
            // doesn't block finalizer removal - a leaked pool entry is recoverable.
            if link.spec.is_lower(&ctx.node_name)
                && let Some(pool_name) = link.status.as_ref().and_then(|s| s.pool.as_deref())
            {
                let pools_api: Api<MeshPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
                if let Err(e) = common::pool::release(&pools_api, pool_name, &name).await {
                    tracing::warn!(link = %name, pool = pool_name, error = %common::reconcile_error::anyhow_chain(&e), "failed to release MeshPool slot on delete");
                }
            }

            let patch = json!({ "metadata": { "finalizers": link.finalizers().iter().filter(|f| **f != our_finalizer).collect::<Vec<_>>() } });
            meshlink_api
                .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
                .await?;
        }
        return Ok(Action::await_change());
    }

    if involved && !link.finalizers().iter().any(|f| f == &our_finalizer) {
        let mut finalizers = link.finalizers().to_vec();
        finalizers.push(our_finalizer);
        let patch = json!({ "metadata": { "finalizers": finalizers } });
        meshlink_api
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
    }

    if !involved {
        return Ok(Action::await_change());
    }

    // Guards a startup race: the Controller can schedule a reconcile before `meshlink_store` has
    // ingested the full initial list, which `gc_stale_interfaces` below relies on being complete.
    // Resolves near-instantly once ready.
    ctx.meshlink_store
        .wait_until_ready()
        .await
        .map_err(|e| Error::Other(e.into()))?;

    let peer = link
        .spec
        .peer_label(&ctx.node_name)
        .expect("!involved already returned above")
        .to_string();
    let Some(peer_node) = ctx
        .mesh_node_store
        .get(&ObjectRef::new(&peer).within(&ctx.namespace))
    else {
        let msg = format!("MeshNode {peer} does not exist yet");
        set_condition(
            &meshlink_api,
            &link,
            "Ready",
            "False",
            "PeerNodeMissing",
            &msg,
        )
        .await?;
        // main.rs's MeshNode watch re-triggers this reconcile once the MeshNode appears.
        return Ok(Action::await_change());
    };

    let Some(peer_public_key) = peer_node.status.as_ref().and_then(|s| s.public_key.clone()) else {
        let msg = format!("MeshNode {peer}'s public key hasn't been computed yet");
        set_condition(
            &meshlink_api,
            &link,
            "Ready",
            "False",
            "PeerPublicKeyPending",
            &msg,
        )
        .await?;
        return Ok(Action::await_change());
    };

    // Cross-object uniqueness check the CRD schema can't express: two MeshNodes sharing a public
    // key would bind every mesh-* interface peering with either one to the same kernel identity.
    if let Some(other) = ctx.mesh_node_store.state().iter().find(|n| {
        n.name_any() != peer
            && n.status.as_ref().and_then(|s| s.public_key.as_deref())
                == Some(peer_public_key.as_str())
    }) {
        let msg = format!(
            "MeshNode {peer}'s public_key collides with MeshNode {}",
            other.name_any()
        );
        tracing::warn!(link = %name, "{msg}");
        set_condition(
            &meshlink_api,
            &link,
            "Ready",
            "False",
            "PublicKeyConflict",
            &msg,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // mesh_label-uniqueness check (same CRD-schema limitation): two MeshNodes sharing a label
    // would collide on the same `mesh-<label>` interface name. Reported on the conflicting
    // MeshNode itself, not this MeshLink.
    if let Some(other) = ctx
        .mesh_node_store
        .state()
        .iter()
        .find(|n| n.name_any() != peer && n.spec.mesh_label == peer_node.spec.mesh_label)
    {
        let msg = format!(
            "mesh_label {:?} collides with MeshNode {}",
            peer_node.spec.mesh_label,
            other.name_any()
        );
        tracing::warn!(link = %name, "{msg}");
        let mesh_nodes: Api<MeshNode> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
        set_mesh_node_condition(
            &mesh_nodes,
            &peer_node,
            "Ready",
            "False",
            "MeshLabelConflict",
            &msg,
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // /31 + port come from a MeshPool, not a human-picked index - allocate on demand (only the
    // "lower" side drives this, see MeshLinkSpec::is_lower).
    let status_network = link.status.as_ref().and_then(|s| s.network.as_ref());
    let status_port = link.status.as_ref().and_then(|s| s.port);
    let (Some(link_network), Some(port)) = (status_network, status_port) else {
        if !link.spec.is_lower(&ctx.node_name) {
            // The other side owns allocation; its status patch re-triggers us naturally.
            return Ok(Action::await_change());
        }
        return match allocate_link_addressing(&ctx, &meshlink_api, &link, &name).await? {
            true => Ok(Action::await_change()), // status patch above re-triggers with fresh data
            false => Ok(Action::requeue(Duration::from_secs(30))), // conflict/exhausted, condition set
        };
    };
    let (link_network_addr, link_prefix) = common::netlink::rt::parse_cidr(link_network)?;
    if link_prefix != 31 {
        return Err(Error::Other(anyhow::anyhow!(
            "MeshLink {name} status.network {link_network} is not a /31"
        )));
    }
    let local_addr = mesh_math::local_addr(
        link_network_addr,
        &link.spec.node_a,
        &link.spec.node_b,
        &ctx.node_name,
    )?;

    let iface = format!("mesh-{}", peer_node.spec.mesh_label);
    let peer_endpoint = match peer_node.spec.endpoint.as_deref() {
        Some(host) => Some(ctx.dns_cache.resolve(host, port).await?),
        None => None,
    };

    let mut awg_client = ctx.awg.clone();
    awg::ensure_interface(
        &mut awg_client,
        &ctx.rt,
        &awg::PeerConfig {
            iface: &iface,
            private_key_b64: &ctx.private_key_b64,
            listen_port: port,
            obfuscation: &link.spec.obfuscation,
            peer_public_key_b64: &peer_public_key,
            peer_endpoint,
            local_addr,
            local_prefix: 31,
        },
    )
    .await?;

    set_condition(
        &meshlink_api,
        &link,
        "Ready",
        "True",
        "Configured",
        "peer configured",
    )
    .await?;
    Ok(Action::await_change())
}
