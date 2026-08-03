//! Manages per-peer `mesh-<peer>` AmneziaWG interfaces over netlink: one interface per MeshLink,
//! each with exactly one peer. Resending the same peer's config every reconcile is an
//! update-in-place (same public key = same kernel peer object) and doesn't reset the live
//! session, so `ensure_interface` is safe to call unconditionally.

use anyhow::{Context, Result};
use common::mesh_types::Obfuscation;
use common::netlink::awg::{AwgClient, decode_key, push_obfuscation_attrs};
use common::netlink::rt::RtClient;
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    AmneziaWireguardAttribute, AmneziaWireguardPeer, AmneziaWireguardPeerAttribute,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Caches resolved endpoint DNS lookups so `ensure_interface`'s unconditional per-reconcile call
/// doesn't re-resolve the same hostname every pass. Entries expire after `TTL`.
#[derive(Default)]
pub struct DnsCache(Mutex<HashMap<(String, u16), (SocketAddr, Instant)>>);

impl DnsCache {
    const TTL: Duration = Duration::from_secs(300);

    pub async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr> {
        let key = (host.to_string(), port);
        if let Some((addr, resolved_at)) = self.0.lock().unwrap().get(&key)
            && resolved_at.elapsed() < Self::TTL
        {
            return Ok(*addr);
        }
        let addr = tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("failed to resolve endpoint {host}:{port}"))?
            .next()
            .with_context(|| format!("no addresses found for endpoint {host}:{port}"))?;
        self.0.lock().unwrap().insert(key, (addr, Instant::now()));
        Ok(addr)
    }
}

pub struct PeerConfig<'a> {
    pub iface: &'a str,
    pub private_key_b64: &'a str,
    pub listen_port: u16,
    pub obfuscation: &'a Obfuscation,
    pub peer_public_key_b64: &'a str,
    /// `None` for a peer with no reachable endpoint (NAT'd): omits Endpoint/PersistentKeepalive
    /// so this side waits for the peer to dial in. Already resolved via `DnsCache`.
    pub peer_endpoint: Option<SocketAddr>,
    pub local_addr: Ipv4Addr,
    pub local_prefix: u8,
}

fn full_tunnel_allowed_ips() -> Vec<AmneziaWireguardAllowedIp> {
    vec![
        AmneziaWireguardAllowedIp(vec![
            AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv4),
            AmneziaWireguardAllowedIpAttr::IpAddr(Ipv4Addr::UNSPECIFIED.into()),
            AmneziaWireguardAllowedIpAttr::Cidr(0),
        ]),
        AmneziaWireguardAllowedIp(vec![
            AmneziaWireguardAllowedIpAttr::Family(AmneziaWireguardAddressFamily::Ipv6),
            AmneziaWireguardAllowedIpAttr::IpAddr(std::net::Ipv6Addr::UNSPECIFIED.into()),
            AmneziaWireguardAllowedIpAttr::Cidr(0),
        ]),
    ]
}

pub async fn ensure_interface(
    awg: &mut AwgClient,
    rt: &RtClient,
    cfg: &PeerConfig<'_>,
) -> Result<()> {
    let (index, _created) = rt.ensure_link(cfg.iface, "amneziawg").await?;

    let mut peer_attrs = vec![
        AmneziaWireguardPeerAttribute::PublicKey(decode_key(cfg.peer_public_key_b64)?),
        AmneziaWireguardPeerAttribute::AllowedIps(full_tunnel_allowed_ips()),
    ];
    if let Some(addr) = cfg.peer_endpoint {
        peer_attrs.push(AmneziaWireguardPeerAttribute::Endpoint(addr));
        peer_attrs.push(AmneziaWireguardPeerAttribute::PersistentKeepalive(25));
    }

    let mut device_attrs = vec![
        AmneziaWireguardAttribute::IfName(cfg.iface.to_string()),
        AmneziaWireguardAttribute::PrivateKey(decode_key(cfg.private_key_b64)?),
        AmneziaWireguardAttribute::ListenPort(cfg.listen_port),
    ];
    push_obfuscation_attrs(&mut device_attrs, cfg.obfuscation);
    device_attrs.push(AmneziaWireguardAttribute::Peers(vec![
        AmneziaWireguardPeer(peer_attrs),
    ]));

    awg.set_device(device_attrs)
        .await
        .context("SetDevice failed")?;

    rt.ensure_address(index, &format!("{}/{}", cfg.local_addr, cfg.local_prefix))
        .await?;
    rt.set_up(index).await?;
    Ok(())
}

/// Interface teardown on MeshLink deletion.
pub async fn remove_interface(rt: &RtClient, iface: &str) -> Result<()> {
    if let Some(index) = rt.link_index(iface).await? {
        rt.delete_link(index).await?;
    }
    Ok(())
}

/// All currently-existing `mesh-*` interfaces on this host, used by the stale-interface GC pass.
pub async fn existing_mesh_interfaces(rt: &RtClient) -> Result<Vec<String>> {
    let links = rt.list_links().await?;
    Ok(links
        .into_iter()
        .filter(|(name, _)| name.starts_with("mesh-"))
        .map(|(name, _)| name)
        .collect())
}
