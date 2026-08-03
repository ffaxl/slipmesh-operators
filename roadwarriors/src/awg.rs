//! Manages the shared `roadwarriors` AmneziaWG interface - identical server key/address/port on
//! every node; clients pick an entry point purely by which node's endpoint they dial. Obfuscation
//! (JC/Jmin/Jmax/S1/S2/H1-H4, see `common::mesh_types::Obfuscation`) is a device-level AmneziaWG setting,
//! not per-peer, so it's one shared config for the whole interface (via `ROADWARRIORS_OBFUSCATION_*`
//! env vars in main.rs). Unset by default, keeping the interface wire-compatible with ordinary
//! WireGuard clients.
//!
//! Interface creation and addressing go through `rt.rs` (rtnetlink); private key, listen port,
//! and peer set go over the "amneziawg" genl family via `netlink.rs`. No external binary (`ip`,
//! `awg`) is ever spawned.
//!
//! Peer sync is point-wise, not a blind full replace: the device-wide `WGDEVICE_F_REPLACE_PEERS`
//! flag tears down and recreates every peer - including live sessions - even when nothing
//! changed, since the kernel implements it as remove-then-readd rather than a diff. A `SetDevice`
//! call that omits the device-level flag instead operates in merge mode: peers not mentioned are
//! left untouched, so only changed peers are included, each with its own per-peer flag
//! (`WGPEER_F_REMOVE_ME` for a departed client, `WGPEER_F_REPLACE_ALLOWEDIPS` for a new/edited one).

use anyhow::{Context, Result};
use base64::Engine;
use common::mesh_types::Obfuscation;
use common::netlink::awg::{AwgClient, decode_key, push_obfuscation_attrs};
use common::netlink::rt::RtClient;
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAttribute, AmneziaWireguardPeer, AmneziaWireguardPeerAttribute,
};

/// See amneziawg-linux-kernel-module's uapi/wireguard.h `enum wg_peer_flag`.
const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub public_key: String,
    /// CIDR entries - semantically a *set* (WireGuard has no concept of AllowedIPs order), so
    /// `diff_peers` compares these order-independently.
    pub allowed_ips: Vec<String>,
}

/// Malformed entries are dropped (not fatal) but logged at `warn`, since a silently-empty-or-
/// partial allowed-ips set looks normal in `kubectl get roadwarriors` while black-holing traffic.
fn parse_allowed_ips(
    entries: &[String],
) -> Vec<netlink_packet_amnezia_wireguard::AmneziaWireguardAllowedIp> {
    use netlink_packet_amnezia_wireguard::{
        AmneziaWireguardAddressFamily, AmneziaWireguardAllowedIp, AmneziaWireguardAllowedIpAttr,
    };
    entries
        .iter()
        .filter_map(|entry| {
            let entry = entry.trim();
            let parsed = (|| {
                let (addr, cidr) = entry.split_once('/')?;
                let cidr: u8 = cidr.parse().ok()?;
                let ip: std::net::IpAddr = addr.parse().ok()?;
                Some((ip, cidr))
            })();
            let Some((ip, cidr)) = parsed else {
                tracing::warn!(entry, "skipping malformed allowedIps entry");
                return None;
            };
            let family = match ip {
                std::net::IpAddr::V4(_) => AmneziaWireguardAddressFamily::Ipv4,
                std::net::IpAddr::V6(_) => AmneziaWireguardAddressFamily::Ipv6,
            };
            Some(AmneziaWireguardAllowedIp(vec![
                AmneziaWireguardAllowedIpAttr::Family(family),
                AmneziaWireguardAllowedIpAttr::IpAddr(ip),
                AmneziaWireguardAllowedIpAttr::Cidr(cidr),
            ]))
        })
        .collect()
}

/// Ensures the link/address/up state - side-effect-free on WireGuard session state, safe to call
/// every reconcile. Returns the ifindex and whether the link was just created.
pub async fn ensure_link_up(rt: &RtClient, iface: &str, address_cidr: &str) -> Result<(u32, bool)> {
    let (index, created) = rt.ensure_link(iface, "amneziawg").await?;
    rt.ensure_address(index, address_cidr).await?;
    rt.set_up(index).await?;
    Ok((index, created))
}

/// Reads back the peer set actually configured on the kernel interface - used at startup instead
/// of assuming an empty `previous` set. The interface lives in the host netns and has no shutdown
/// teardown, so it survives a restart; without this readback, a client revoked while the pod was
/// down would never be removed (`diff_peers` only emits a removal for a key present in `previous`).
pub async fn current_peers(awg: &mut AwgClient, iface: &str) -> Result<Vec<Peer>> {
    use netlink_packet_amnezia_wireguard::{
        AmneziaWireguardAllowedIpAttr, AmneziaWireguardPeerAttribute,
    };

    fn allowed_ip_to_cidr(attrs: &[AmneziaWireguardAllowedIpAttr]) -> Option<String> {
        let ip = attrs.iter().find_map(|a| match a {
            AmneziaWireguardAllowedIpAttr::IpAddr(ip) => Some(*ip),
            _ => None,
        })?;
        let cidr = attrs.iter().find_map(|a| match a {
            AmneziaWireguardAllowedIpAttr::Cidr(c) => Some(*c),
            _ => None,
        })?;
        Some(format!("{ip}/{cidr}"))
    }

    let attrs = awg.get_device(iface).await?;
    let mut peers = Vec::new();
    for attr in attrs {
        let AmneziaWireguardAttribute::Peers(device_peers) = attr else {
            continue;
        };
        for peer in device_peers {
            let mut public_key = None;
            let mut allowed_ips = Vec::new();
            for pattr in peer.0 {
                match pattr {
                    AmneziaWireguardPeerAttribute::PublicKey(k) => {
                        public_key = Some(base64::engine::general_purpose::STANDARD.encode(k));
                    }
                    AmneziaWireguardPeerAttribute::AllowedIps(ips) => {
                        allowed_ips = ips
                            .iter()
                            .filter_map(|ip| allowed_ip_to_cidr(&ip.0))
                            .collect::<Vec<_>>();
                    }
                    _ => {}
                }
            }
            if let Some(public_key) = public_key {
                peers.push(Peer {
                    public_key,
                    allowed_ips,
                });
            }
        }
    }
    peers.sort();
    Ok(peers)
}

/// Sets the device's private key, listen port, and obfuscation params. Only needs calling once,
/// right after the link is first created - nothing about it changes at runtime.
pub async fn set_identity(
    awg: &mut AwgClient,
    iface: &str,
    private_key_b64: &str,
    listen_port: u16,
    obfuscation: &Obfuscation,
) -> Result<()> {
    let mut device_attrs = vec![
        AmneziaWireguardAttribute::IfName(iface.to_string()),
        AmneziaWireguardAttribute::PrivateKey(decode_key(private_key_b64)?),
        AmneziaWireguardAttribute::ListenPort(listen_port),
    ];
    push_obfuscation_attrs(&mut device_attrs, obfuscation);
    awg.set_device(device_attrs)
        .await
        .context("SetDevice (identity) failed")
}

/// Builds the desired peer list from `(client_name, public_key, allowed_ips)` triples, logging a
/// warning if two different RoadWarrior names share the same public_key - `diff_peers` keys peers
/// by public_key alone and would otherwise collapse the collision with no trace.
pub fn peers_from_clients(
    clients: impl Iterator<Item = (String, String, Vec<String>)>,
) -> Vec<Peer> {
    use std::collections::HashMap;
    let mut seen: HashMap<String, String> = HashMap::new(); // public_key -> first client name seen
    let mut peers = Vec::new();
    for (name, public_key, allowed_ips) in clients {
        if let Some(first_name) = seen.get(&public_key) {
            tracing::warn!(
                public_key,
                client_a = first_name,
                client_b = name,
                "two RoadWarrior objects share the same public_key - client_b is being dropped from the peer set"
            );
            continue;
        }
        seen.insert(public_key.clone(), name);
        peers.push(Peer {
            public_key,
            allowed_ips,
        });
    }
    peers
}

/// Computes the minimal peer-list diff between what was last applied and what's now desired.
/// `previous`/`desired` must both be sorted by `public_key`.
///
/// `allowed_ips` is compared as a *set*, not a sequence - `desired` (human-authored CRD order)
/// and `previous` (kernel readback order) have no semantically meaningful order to WireGuard.
/// Comparing as an ordered `Vec` would fire a spurious `WGPEER_F_REPLACE_ALLOWEDIPS` (dropping
/// the peer's live session) whenever the orders merely differed with identical entries.
fn diff_peers(previous: &[Peer], desired: &[Peer]) -> Vec<(String, Option<Vec<String>>)> {
    use std::collections::{BTreeMap, BTreeSet};
    fn as_set(ips: &[String]) -> BTreeSet<&str> {
        ips.iter().map(String::as_str).collect()
    }

    let prev_map: BTreeMap<&str, &Vec<String>> = previous
        .iter()
        .map(|p| (p.public_key.as_str(), &p.allowed_ips))
        .collect();
    let desired_map: BTreeMap<&str, &Vec<String>> = desired
        .iter()
        .map(|p| (p.public_key.as_str(), &p.allowed_ips))
        .collect();

    let mut ops = Vec::new();
    for (key, allowed_ips) in &desired_map {
        let unchanged = prev_map
            .get(key)
            .is_some_and(|prev| as_set(prev) == as_set(allowed_ips));
        if !unchanged {
            ops.push((key.to_string(), Some((*allowed_ips).clone())));
        }
    }
    for key in prev_map.keys() {
        if !desired_map.contains_key(key) {
            ops.push((key.to_string(), None));
        }
    }
    ops
}

/// Applies exactly the peers that changed between `previous` and `desired` - added/edited peers
/// get `WGPEER_F_REPLACE_ALLOWEDIPS`, removed peers get `WGPEER_F_REMOVE_ME`. Peers absent from
/// `ops` keep their live session untouched. No-op if `previous == desired`.
pub async fn sync_peers(
    awg: &mut AwgClient,
    iface: &str,
    previous: &[Peer],
    desired: &[Peer],
) -> Result<()> {
    let ops = diff_peers(previous, desired);
    if ops.is_empty() {
        return Ok(());
    }

    // Applied independently - one RoadWarrior with an undecodable public_key must not block
    // every other client's add/remove/update in the same batch. Skipped ops are logged.
    let peers: Vec<AmneziaWireguardPeer> = ops
        .into_iter()
        .filter_map(|(public_key, allowed_ips)| {
            let decoded = match decode_key(&public_key) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(public_key, error = %common::reconcile_error::anyhow_chain(&e), "skipping peer with undecodable public_key");
                    return None;
                }
            };
            Some(match allowed_ips {
                Some(allowed_ips) => AmneziaWireguardPeer(vec![
                    AmneziaWireguardPeerAttribute::PublicKey(decoded),
                    AmneziaWireguardPeerAttribute::Flags(WGPEER_F_REPLACE_ALLOWEDIPS),
                    AmneziaWireguardPeerAttribute::AllowedIps(parse_allowed_ips(&allowed_ips)),
                ]),
                None => AmneziaWireguardPeer(vec![
                    AmneziaWireguardPeerAttribute::PublicKey(decoded),
                    AmneziaWireguardPeerAttribute::Flags(WGPEER_F_REMOVE_ME),
                ]),
            })
        })
        .collect();

    if peers.is_empty() {
        return Ok(());
    }

    awg.set_device(vec![
        AmneziaWireguardAttribute::IfName(iface.to_string()),
        AmneziaWireguardAttribute::Peers(peers),
    ])
    .await
    .context("SetDevice (peer diff) failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(public_key: &str, allowed_ips: &[&str]) -> Peer {
        Peer {
            public_key: public_key.to_string(),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn identical_sets_produce_no_ops() {
        let a = vec![peer("k1", &["10.0.0.1/32"]), peer("k2", &["10.0.0.2/32"])];
        assert!(diff_peers(&a, &a).is_empty());
    }

    #[test]
    fn added_peer_yields_replace_op() {
        let previous = vec![peer("k1", &["10.0.0.1/32"])];
        let desired = vec![peer("k1", &["10.0.0.1/32"]), peer("k2", &["10.0.0.2/32"])];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![("k2".to_string(), Some(vec!["10.0.0.2/32".to_string()]))]
        );
    }

    #[test]
    fn removed_peer_yields_remove_op() {
        let previous = vec![peer("k1", &["10.0.0.1/32"]), peer("k2", &["10.0.0.2/32"])];
        let desired = vec![peer("k1", &["10.0.0.1/32"])];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(ops, vec![("k2".to_string(), None)]);
    }

    #[test]
    fn reordered_allowed_ips_produce_no_ops() {
        // Same entries, different order (e.g. a human rewrote the CRD's list, or the kernel just
        // happens to report them differently) - must not be treated as a change, or every
        // reconcile would drop and recreate the peer's live session for no real reason.
        let previous = vec![peer("k1", &["10.0.0.1/32", "10.0.0.2/32"])];
        let desired = vec![peer("k1", &["10.0.0.2/32", "10.0.0.1/32"])];
        assert!(diff_peers(&previous, &desired).is_empty());
    }

    #[test]
    fn actual_set_change_yields_replace_op() {
        let previous = vec![peer("k1", &["10.0.0.1/32", "10.0.0.2/32"])];
        let desired = vec![peer("k1", &["10.0.0.1/32", "10.0.0.3/32"])];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![(
                "k1".to_string(),
                Some(vec!["10.0.0.1/32".to_string(), "10.0.0.3/32".to_string()])
            )]
        );
    }

    #[test]
    fn changed_allowed_ips_yields_replace_op_not_remove_and_add() {
        let previous = vec![peer("k1", &["10.0.0.1/32"])];
        let desired = vec![peer("k1", &["10.0.0.99/32"])];
        let ops = diff_peers(&previous, &desired);
        assert_eq!(
            ops,
            vec![("k1".to_string(), Some(vec!["10.0.0.99/32".to_string()]))]
        );
    }

    #[test]
    fn unrelated_peers_are_never_mentioned() {
        // The whole point of point-wise sync: a peer that didn't change must not appear in the
        // op list at all, since any mention at all would touch its live session.
        let previous = vec![peer("k1", &["10.0.0.1/32"]), peer("k2", &["10.0.0.2/32"])];
        let desired = vec![
            peer("k1", &["10.0.0.1/32"]),
            peer("k2", &["10.0.0.2/32"]),
            peer("k3", &["10.0.0.3/32"]),
        ];
        let ops = diff_peers(&previous, &desired);
        assert!(!ops.iter().any(|(k, _)| k == "k1"));
        assert!(!ops.iter().any(|(k, _)| k == "k2"));
        assert_eq!(
            ops,
            vec![("k3".to_string(), Some(vec!["10.0.0.3/32".to_string()]))]
        );
    }
}
