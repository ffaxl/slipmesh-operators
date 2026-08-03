//! Polls peer/handshake state over the "amneziawg" genl family (via `common::netlink::awg`) and
//! maintains kernel routes via `common::netlink::rt` (rtnetlink), at 1Hz. Maintains a kernel route for
//! each allowed-ips network of any peer whose handshake is fresher than `stale_secs`, removing it
//! once stale. BIRD's `learn` (router) picks these routes up and carries them over iBGP, so a
//! client's /32 always points at whichever node it's actually connected to.

use anyhow::Result;
use base64::Engine;
use common::mesh_types::RoadWarrior;
use common::netlink::awg::AwgClient;
use common::netlink::rt::RtClient;
use kube::api::{Patch, PatchParams};
use kube::runtime::reflector::Store;
use kube::{Api, ResourceExt};
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAllowedIpAttr, AmneziaWireguardAttribute, AmneziaWireguardPeerAttribute,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::interval;

struct PeerHandshake {
    public_key_b64: String,
    /// CIDR strings, e.g. "10.99.0.5/32" - already formatted, ready for `ip route`.
    allowed_ips: Vec<String>,
    latest_handshake: u64,
}

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

async fn dump(awg: &mut AwgClient, iface: &str) -> Result<Vec<PeerHandshake>> {
    let attrs = awg.get_device(iface).await?;
    let mut peers = Vec::new();
    for attr in attrs {
        let AmneziaWireguardAttribute::Peers(device_peers) = attr else {
            continue;
        };
        for peer in device_peers {
            let mut public_key_b64 = None;
            let mut allowed_ips = Vec::new();
            let mut latest_handshake = 0u64;
            for pattr in peer.0 {
                match pattr {
                    AmneziaWireguardPeerAttribute::PublicKey(k) => {
                        public_key_b64 = Some(base64::engine::general_purpose::STANDARD.encode(k));
                    }
                    AmneziaWireguardPeerAttribute::AllowedIps(ips) => {
                        allowed_ips = ips
                            .iter()
                            .filter_map(|ip| allowed_ip_to_cidr(&ip.0))
                            .collect();
                    }
                    AmneziaWireguardPeerAttribute::LastHandshake(ts) => {
                        latest_handshake = ts.seconds.max(0) as u64;
                    }
                    _ => {}
                }
            }
            if let Some(public_key_b64) = public_key_b64 {
                peers.push(PeerHandshake {
                    public_key_b64,
                    allowed_ips,
                    latest_handshake,
                });
            }
        }
    }
    Ok(peers)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

/// Parameters that stay fixed for the whole `run_forever` loop, distinct from the live handles
/// (`awg`/`rt`) and the tick-to-tick mutable state (`installed_routes`).
pub struct Config {
    pub iface: String,
    pub stale_secs: u64,
    pub node_name: String,
    pub client_store: Store<RoadWarrior>,
    pub clients_api: Api<RoadWarrior>,
}

/// Runs forever as its own background task, independent of the kube reconcile loop - ticks at a
/// fixed rate regardless of whether any RoadWarrior changed. Tracks installed routes in memory
/// rather than querying the kernel each tick, since this task is their only owner.
pub async fn run_forever(mut awg: AwgClient, rt: RtClient, cfg: Config) {
    let mut tick = interval(Duration::from_secs(1));
    let mut installed_routes: HashSet<String> = HashSet::new();
    loop {
        tick.tick().await;
        if let Err(e) = one_pass(&mut awg, &rt, &cfg, &mut installed_routes).await {
            tracing::warn!(error = %common::reconcile_error::anyhow_chain(&e), "handshake pass failed");
        }
    }
}

async fn one_pass(
    awg: &mut AwgClient,
    rt: &RtClient,
    cfg: &Config,
    installed_routes: &mut HashSet<String>,
) -> Result<()> {
    let Some(index) = rt.link_index(&cfg.iface).await? else {
        // Interface not created yet (no reconcile has run) - nothing to do this tick.
        return Ok(());
    };
    let peers = dump(awg, &cfg.iface).await?;
    let now = now_unix();
    let is_fresh = |p: &PeerHandshake| {
        p.latest_handshake > 0 && now.saturating_sub(p.latest_handshake) < cfg.stale_secs
    };

    // Map pubkey -> client CR name, for status visibility only - read from the Controller's own
    // cache. Only built when at least one peer is fresh this tick, skipping the allocation on
    // every idle second.
    let by_pubkey: HashMap<String, String> = if peers.iter().any(is_fresh) {
        cfg.client_store
            .state()
            .iter()
            .map(|c| (c.spec.public_key.clone(), c.name_any()))
            .collect()
    } else {
        HashMap::new()
    };

    let mut still_fresh: HashSet<String> = HashSet::new();

    for peer in &peers {
        if is_fresh(peer) {
            for net in &peer.allowed_ips {
                // IPv4-only (route_add/route_del go through common::netlink::rt, which only
                // builds IPv4 RouteMessages) - an IPv6 (or otherwise unparsable) entry must be
                // skipped rather than propagated via `?`, which would abort this whole tick and
                // starve every other peer's route (re)install/cleanup and status patch below, one
                // second at a time, for as long as that peer stays connected.
                if common::netlink::rt::parse_cidr(net).is_err() {
                    tracing::warn!(
                        net,
                        peer = peer.public_key_b64,
                        "skipping non-IPv4 allowedIps entry - no kernel route installed, won't be BIRD-learned"
                    );
                    continue;
                }
                if !installed_routes.contains(net) {
                    rt.route_add(index, net).await?;
                    // Only recorded once the add succeeds, so a failure retries next tick.
                    installed_routes.insert(net.clone());
                }
                still_fresh.insert(net.clone());
            }
            if let Some(name) = by_pubkey.get(&peer.public_key_b64) {
                // RFC3339, not raw unix-seconds, so the CRD schema can declare `format: date-time`.
                // `expect`: a real handshake timestamp is trivially within jiff's valid range.
                let last_handshake_time =
                    k8s_openapi::jiff::Timestamp::from_second(peer.latest_handshake as i64)
                        .expect("real handshake timestamps are always within jiff's valid range")
                        .to_string();
                let patch = json!({
                    "status": {
                        "connectedNode": cfg.node_name,
                        "lastHandshakeTime": last_handshake_time,
                    }
                });
                if let Err(e) = cfg
                    .clients_api
                    .patch_status(
                        name,
                        &PatchParams::apply("roadwarriors"),
                        &Patch::Merge(&patch),
                    )
                    .await
                {
                    tracing::warn!(error = %common::reconcile_error::error_chain(&e), client = name, "failed to patch RoadWarrior status");
                }
            }
        }
    }

    // Anything we'd previously installed but isn't fresh this pass (peer went stale, or
    // disappeared entirely) gets torn down.
    let stale: Vec<String> = installed_routes.difference(&still_fresh).cloned().collect();
    for net in stale {
        rt.route_del(index, &net).await?;
        installed_routes.remove(&net);
    }

    Ok(())
}
