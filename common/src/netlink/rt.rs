//! Thin wrapper around `rtnetlink` - the route/link/address netlink family (`NETLINK_ROUTE`,
//! distinct from the "amneziawg" genl one in `awg.rs`). Used by mesh and roadwarriors
//! (link/address/route management, replacing `ip` subprocess calls entirely) and by router
//! (loopback dummy-interface management and default-route-interface detection).

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::packet_route::route::RouteMessage;
use rtnetlink::{
    AddressMessageBuilder, Handle, LinkMessageBuilder, RouteMessageBuilder, new_connection,
};
use slipmesh_core::cidr::parse_cidr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RtClient {
    handle: Handle,
    /// Serializes every netlink request issued through this client - across every clone (shared
    /// via the `Arc`, not per-clone) and across every method, not just `ensure_address` - confirmed
    /// by reproduction that concurrent requests sharing one netlink socket (the Controller
    /// reconciles MeshLinks with unbounded concurrency, all sharing one `RtClient`) can get back
    /// `EBUSY` from the kernel, even across *different* links and *different* request types (e.g.
    /// one task's unlocked `ensure_link` racing another's `ensure_address`) - this is contention on
    /// the shared socket itself, not something scoped to a single link or a single operation. A
    /// `Mutex` rather than a retry loop: sidesteps picking a retry budget that's merely "probably
    /// enough" under some untested concurrency level.
    ///
    /// A handful of methods internally need the same lookup another public method already does
    /// (`ensure_link` needs what `link_index` does, `default_iface` needs what `list_links` does) -
    /// those internal call sites go through a private `link_index_inner`/`list_links_inner` helper
    /// directly, not the public locked method, since `tokio::sync::Mutex` isn't reentrant and the
    /// outer method (`ensure_link`/`default_iface`) already holds the lock for its whole duration.
    netlink_lock: Arc<Mutex<()>>,
}

/// Which of `current` addresses should be removed so only `desired` remains on the interface -
/// pure and independent of any actual netlink call, so `RtClient::ensure_address`'s cleanup
/// behavior can be unit-tested without a real link/kernel. Anything not an exact match gets
/// flagged, regardless of how many stale entries have piled up.
fn addresses_to_remove(current: &[(Ipv4Addr, u8)], desired: (Ipv4Addr, u8)) -> Vec<(Ipv4Addr, u8)> {
    current.iter().copied().filter(|&a| a != desired).collect()
}

impl RtClient {
    pub fn connect() -> Result<Self> {
        let (connection, handle, _) =
            new_connection().context("failed to open rtnetlink socket")?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            netlink_lock: Arc::new(Mutex::new(())),
        })
    }

    async fn link_index_inner(&self, name: &str) -> Result<Option<u32>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(msg)) => Ok(Some(msg.header.index)),
            Ok(None) => Ok(None),
            Err(rtnetlink::Error::NetlinkError(ref e)) if e.raw_code() == -19 => Ok(None), // ENODEV
            Err(e) => Err(e).with_context(|| format!("failed to look up link {name:?}")),
        }
    }

    /// Looks up a link's ifindex by name, without creating it. `Ok(None)` means the link doesn't
    /// exist.
    pub async fn link_index(&self, name: &str) -> Result<Option<u32>> {
        let _guard = self.netlink_lock.lock().await;
        self.link_index_inner(name).await
    }

    /// Creates the link if it doesn't exist yet (`ip link add <name> type <kind>`). Returns its
    /// ifindex plus whether it was just created, since device identity only needs (re)applying
    /// on creation.
    pub async fn ensure_link(&self, name: &str, kind: &str) -> Result<(u32, bool)> {
        let _guard = self.netlink_lock.lock().await;
        if let Some(index) = self.link_index_inner(name).await? {
            return Ok((index, false));
        }
        let msg = LinkMessageBuilder::<()>::new_with_info_kind(InfoKind::Other(kind.to_string()))
            .name(name.to_string())
            .build();
        self.handle
            .link()
            .add(msg)
            .execute()
            .await
            .with_context(|| format!("failed to create link {name:?} type {kind:?}"))?;
        let index = self
            .link_index_inner(name)
            .await?
            .with_context(|| format!("link {name:?} missing immediately after creation"))?;
        Ok((index, true))
    }

    async fn list_links_inner(&self) -> Result<Vec<(String, u32)>> {
        use rtnetlink::packet_route::link::LinkAttribute;
        let mut links = self.handle.link().get().execute();
        let mut out = Vec::new();
        while let Some(msg) = links.try_next().await.context("failed to list links")? {
            let name = msg.attributes.iter().find_map(|a| match a {
                LinkAttribute::IfName(name) => Some(name.clone()),
                _ => None,
            });
            if let Some(name) = name {
                out.push((name, msg.header.index));
            }
        }
        Ok(out)
    }

    /// Lists every link on the host as (name, ifindex) pairs - equivalent to `ip -o link show`.
    pub async fn list_links(&self) -> Result<Vec<(String, u32)>> {
        let _guard = self.netlink_lock.lock().await;
        self.list_links_inner().await
    }

    /// Equivalent to `ip link del <index>` - used on graceful shutdown so the interface doesn't
    /// persist in the host netns (it was created there directly via hostNetwork).
    pub async fn delete_link(&self, index: u32) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .with_context(|| format!("failed to delete link {index}"))
    }

    /// Equivalent to `ip link set <index> up`.
    pub async fn set_up(&self, index: u32) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let msg = LinkMessageBuilder::<()>::default()
            .index(index)
            .up()
            .build();
        self.handle
            .link()
            .set(msg)
            .execute()
            .await
            .with_context(|| format!("failed to set link {index} up"))
    }

    /// Every IPv4 address currently assigned to `index`, as `(address, prefix_len)` pairs -
    /// IPv6 entries (e.g. an autoconfigured link-local) are left out, since `ensure_address` only
    /// ever manages this interface's single IPv4 address.
    async fn ipv4_addresses(&self, index: u32) -> Result<Vec<(Ipv4Addr, u8)>> {
        use rtnetlink::packet_route::address::AddressAttribute;

        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut out = Vec::new();
        while let Some(msg) = addrs
            .try_next()
            .await
            .with_context(|| format!("failed to list addresses on link {index}"))?
        {
            let prefix_len = msg.header.prefix_len;
            for attr in &msg.attributes {
                if let AddressAttribute::Address(std::net::IpAddr::V4(addr)) = attr {
                    out.push((*addr, prefix_len));
                }
            }
        }
        Ok(out)
    }

    /// Equivalent to `ip addr replace <cidr> dev <index>`, plus removing every *other* IPv4
    /// address already on the interface - idempotent, and self-correcting for a link whose
    /// address changed (e.g. after a `MeshPool`/`RouterPool` reallocation moved it to a different
    /// `/31`). `NLM_F_REPLACE` on its own (the old behavior) only updates an exact matching
    /// address or adds a new one; it never removes a now-stale one, so without this an interface
    /// accumulates every address it was ever assigned across its whole lifetime.
    ///
    /// Holds `netlink_lock` for the whole list-then-add/delete sequence: reproduced directly
    /// (many concurrent `ensure_address` calls against a couple of test interfaces) that the
    /// kernel returns `EBUSY` for this sequence under real concurrency - the Controller reconciles
    /// MeshLinks with unbounded concurrency, all sharing one `RtClient`/netlink socket, and this
    /// showed up for *different* links' calls racing each other, not just two calls contending on
    /// the same one.
    pub async fn ensure_address(&self, index: u32, cidr: &str) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let desired = parse_cidr(cidr)?;
        let current = self.ipv4_addresses(index).await?;
        for (addr, prefix) in addresses_to_remove(&current, desired) {
            self.handle
                .address()
                .del(
                    AddressMessageBuilder::<Ipv4Addr>::new()
                        .index(index)
                        .address(addr, prefix)
                        .build(),
                )
                .execute()
                .await
                .with_context(|| {
                    format!("failed to remove stale address {addr}/{prefix} from link {index}")
                })?;
        }
        self.handle
            .address()
            .add(index, desired.0.into(), desired.1)
            .replace()
            .execute()
            .await
            .with_context(|| format!("failed to assign address {cidr} to link {index}"))
    }

    /// Equivalent to `ip route replace <cidr> dev <index>`.
    pub async fn route_add(&self, index: u32, cidr: &str) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let (addr, prefix) = parse_cidr(cidr)?;
        let msg: RouteMessage = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(addr, prefix)
            .output_interface(index)
            .build();
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .with_context(|| format!("failed to add route {cidr} dev {index}"))
    }

    /// Equivalent to `ip route del <cidr> dev <index>`. Deleting a missing route is success (ESRCH).
    pub async fn route_del(&self, index: u32, cidr: &str) -> Result<()> {
        let _guard = self.netlink_lock.lock().await;
        let (addr, prefix) = parse_cidr(cidr)?;
        let msg: RouteMessage = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(addr, prefix)
            .output_interface(index)
            .build();
        match self.handle.route().del(msg).execute().await {
            Ok(()) => Ok(()),
            Err(rtnetlink::Error::NetlinkError(ref e)) if e.raw_code() == -3 => Ok(()), // ESRCH
            Err(e) => Err(e).with_context(|| format!("failed to delete route {cidr} dev {index}")),
        }
    }

    /// Name of the interface the IPv4 default route (0.0.0.0/0) points at - equivalent to
    /// `ip route show default` followed by resolving the `dev` name. `Ok(None)` if none exists.
    pub async fn default_iface(&self) -> Result<Option<String>> {
        use rtnetlink::packet_route::route::RouteAttribute;

        let _guard = self.netlink_lock.lock().await;
        let msg = RouteMessageBuilder::<Ipv4Addr>::new().build();
        let mut routes = self.handle.route().get(msg).execute();
        let mut default_oif = None;
        while let Some(route) = routes.try_next().await.context("failed to list routes")? {
            if route.header.destination_prefix_length != 0 {
                continue;
            }
            if let Some(oif) = route.attributes.iter().find_map(|a| match a {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            }) {
                default_oif = Some(oif);
                break;
            }
        }
        let Some(oif) = default_oif else {
            return Ok(None);
        };

        let links = self.list_links_inner().await?;
        Ok(links
            .into_iter()
            .find(|(_, index)| *index == oif)
            .map(|(name, _)| name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_to_remove_empty_current_removes_nothing() {
        assert_eq!(
            addresses_to_remove(&[], (Ipv4Addr::new(10, 0, 0, 1), 31)),
            Vec::new()
        );
    }

    #[test]
    fn addresses_to_remove_matching_current_removes_nothing() {
        let desired = (Ipv4Addr::new(10, 0, 0, 1), 31);
        assert_eq!(addresses_to_remove(&[desired], desired), Vec::new());
    }

    #[test]
    fn addresses_to_remove_flags_a_single_stale_address() {
        // The exact live bug: a MeshPool reallocation moved this link to a new /31, but the old
        // address is still assigned - `ensure_address`'s bare NLM_F_REPLACE add never removes it.
        let stale = (Ipv4Addr::new(10, 62, 255, 6), 31);
        let desired = (Ipv4Addr::new(10, 62, 255, 10), 31);
        assert_eq!(addresses_to_remove(&[stale], desired), vec![stale]);
    }

    #[test]
    fn addresses_to_remove_keeps_desired_and_flags_every_other_one() {
        let stale_a = (Ipv4Addr::new(10, 0, 0, 2), 31);
        let stale_b = (Ipv4Addr::new(10, 0, 0, 4), 31);
        let desired = (Ipv4Addr::new(10, 0, 0, 6), 31);
        let mut removed = addresses_to_remove(&[stale_a, desired, stale_b], desired);
        removed.sort();
        assert_eq!(removed, vec![stale_a, stale_b]);
    }
}
