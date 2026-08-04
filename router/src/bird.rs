//! Renders the full BIRD config from the current desired state on every reconcile pass (not
//! patched incrementally) and reloads it via `birdc configure` - a live reload, not a restart,
//! so it doesn't flap sessions unaffected by whatever changed. OSPF over the mesh links, an iBGP
//! full mesh over loopbacks, plus DIRECT_CNI (the pod-bridge subnet) and ANNOUNCE (e.g. the
//! service CIDR) redistributed the same way BYPASS already is. The kernel protocol's scoped
//! `learn` picks up road-warrior /32s (see `render()`'s `learn` param) and re-announces them over
//! iBGP as `RTS_INHERIT`. Still out of scope: eBGP peers.

use anyhow::{Context, Result};
use common::netlink::rt::RtClient;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::process::{Child, Command};

/// Dedicated dummy interface carrying this node's router identity /32 - kept separate from the
/// real `lo` and from Talos-managed interfaces so nothing but this operator ever touches it.
pub const ROUTER_LOOPBACK_IFACE: &str = "router-lo";

/// Name of the pod-network bridge every node's local CNI conflist creates, shared with the
/// `DIRECT_CNI` protocol block in `render()`.
pub const CNI_BRIDGE_IFACE: &str = "cni0";

/// Starts the `bird` daemon as a child process - `reconcile()` below only ever writes config and
/// asks an already-running bird to reload it (`birdc configure`), never starts the daemon. Must
/// be called once at operator startup before the reconcile loop runs.
pub async fn spawn_daemon(path: &Path) -> Result<Child> {
    // Normally created by systemd's RuntimeDirectory= for the bird2 package's own unit - nothing
    // does that for us in a minimal container with no init system.
    tokio::fs::create_dir_all("/run/bird")
        .await
        .context("failed to create /run/bird")?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if tokio::fs::metadata(path).await.is_err() {
        // bird refuses to start with no config file at all - a minimal always-valid stub gets
        // it up before the first real reconcile writes actual OSPF interfaces.
        tokio::fs::write(path, "protocol device {\n}\n")
            .await
            .with_context(|| format!("failed to write placeholder {}", path.display()))?;
    }
    Command::new("bird")
        .args(["-f", "-c"])
        .arg(path)
        .spawn()
        .context("failed to spawn bird daemon")
}

pub struct BgpPeer {
    /// Sanitized for use as a BIRD protocol identifier (alphanumeric/underscore only) - always
    /// built via `sanitize_bird_id`, never a raw RouterNode name.
    pub label: String,
    pub loopback: Ipv4Addr,
}

/// A BIRD identifier (protocol name, etc.) may only contain letters, digits, and underscores,
/// and mustn't start with a digit. RouterNode names routinely contain `-`/`.`, so anything built
/// into a bare identifier (`ibgp_<label>`) must go through this first.
pub fn sanitize_bird_id(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// A BIRD quoted string ends at the first `"` - an embedded quote breaks out into the surrounding
/// block and lets whatever follows be parsed as real config. `ospf_ifaces` entries come from
/// CRD-supplied, apiserver-unvalidated strings, so they go through this before being quoted.
fn sanitize_quoted(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c != '"' && c != '\n' && c != '\r')
        .collect()
}

/// A BIRD `#` comment runs to the end of the line - an embedded newline breaks out of the comment
/// into real config. `BypassRoute` labels are user-supplied, so strip line breaks before writing
/// one into a comment.
fn sanitize_comment(raw: &str) -> String {
    raw.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

pub struct BypassRoute {
    pub net: String,
    pub label: String,
}

/// A network to redistribute into the iBGP mesh as a static blackhole route - same shape as
/// `BypassRoute`, but for cluster-infrastructure ranges (e.g. the Kubernetes service CIDR) rather
/// than VPN egress-bypass exits. Collapsed into one shared `ANNOUNCE` protocol.
pub struct AnnounceRoute {
    pub net: String,
    pub label: String,
}

/// OSPF over the mesh links + loopback stub (`export none` - OSPF must never re-export
/// kernel/BGP routes back into the IGP) plus an iBGP full mesh over loopbacks, exporting this
/// node's own BYPASS/ANNOUNCE statics (`source = RTS_STATIC`), the local pod-bridge subnet
/// (`proto = "DIRECT_CNI"`), and any road-warrior host route the kernel protocol learned
/// (`source = RTS_INHERIT`) - not OSPF-learned routes, which would risk a route-preference fight
/// between the two protocols for the same prefix. Still out of scope: eBGP peers.
///
/// `learn` is every currently-declared RoadWarrior client's `allowedIps` (already validated as
/// plain IPv4 CIDRs by the caller) - scopes the kernel protocol's `learn` import to exactly those
/// networks, rather than blindly importing the whole kernel routing table (which would include
/// the default route and anything else a host happens to have). Empty means no road-warrior
/// deployment on this cluster: `learn` stays off entirely, matching the previous behavior.
pub fn render(
    loopback: Ipv4Addr,
    as_number: u32,
    ospf_ifaces: &[String],
    bgp_peers: &[BgpPeer],
    bypass: &[BypassRoute],
    announce: &[AnnounceRoute],
    learn: &[String],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "router id {loopback};");
    out.push_str("protocol device {\n}\n");
    out.push_str("protocol direct direct1 {\n");
    let _ = writeln!(out, "    interface \"{ROUTER_LOOPBACK_IFACE}\";");
    out.push_str("    ipv4 { import all; };\n");
    out.push_str("}\n");
    out.push_str("protocol kernel {\n");
    out.push_str("    ipv4 {\n");
    if !learn.is_empty() {
        // Scoped to exactly the declared road-warrior networks - an unfiltered `learn` would pull
        // in the whole kernel routing table (default route included).
        out.push_str("        import filter {\n");
        let _ = writeln!(
            out,
            "            if net ~ [ {} ] then accept;",
            learn.join(", ")
        );
        out.push_str("            reject;\n");
        out.push_str("        };\n");
    }
    out.push_str("        export filter {\n");
    out.push_str("            if source = RTS_OSPF then accept;\n");
    out.push_str("            if source = RTS_BGP then accept;\n");
    out.push_str("            reject;\n");
    out.push_str("        };\n");
    out.push_str("    };\n");
    if learn.is_empty() {
        out.push_str("    learn no;\n");
    } else {
        out.push_str("    learn;\n");
    }
    out.push_str("}\n");
    out.push_str("protocol ospf v2 mesh {\n");
    out.push_str("    ipv4 {\n");
    out.push_str("        import all;\n");
    out.push_str("        export none;\n");
    out.push_str("    };\n");
    out.push_str("    area 0 {\n");
    let _ = writeln!(
        out,
        "        interface \"{ROUTER_LOOPBACK_IFACE}\" {{ stub yes; }};"
    );
    for iface in ospf_ifaces {
        let _ = writeln!(
            out,
            "        interface \"{}\" {{ type ptp; }};",
            sanitize_quoted(iface)
        );
    }
    out.push_str("    };\n");
    out.push_str("}\n");

    // Picks up the pod-bridge subnet once the CNI conflist assigns it an address - `direct`
    // tracks interface up/down + address-change events by name, no reconfigure needed even
    // though the interface doesn't exist yet at bird's own startup.
    let _ = writeln!(out, "protocol direct DIRECT_CNI {{");
    let _ = writeln!(out, "    interface \"{CNI_BRIDGE_IFACE}\";");
    out.push_str("    ipv4 { preference 250; import all; };\n");
    out.push_str("}\n");

    if !bypass.is_empty() {
        out.push_str("protocol static BYPASS {\n");
        out.push_str("    ipv4 { import all; };\n");
        for r in bypass {
            let _ = writeln!(
                out,
                "    route {} blackhole; # {}",
                r.net,
                sanitize_comment(&r.label)
            );
        }
        out.push_str("}\n");
    }

    if !announce.is_empty() {
        out.push_str("protocol static ANNOUNCE {\n");
        out.push_str("    ipv4 { import all; };\n");
        for r in announce {
            let _ = writeln!(
                out,
                "    route {} blackhole; # {}",
                r.net,
                sanitize_comment(&r.label)
            );
        }
        out.push_str("}\n");
    }

    for peer in bgp_peers {
        let _ = writeln!(out, "protocol bgp ibgp_{} {{", peer.label);
        let _ = writeln!(out, "    local {loopback} as {as_number};");
        let _ = writeln!(out, "    neighbor {} as {as_number};", peer.loopback);
        out.push_str("    strict bind yes;\n");
        out.push_str("    ipv4 {\n");
        out.push_str("        import all;\n");
        out.push_str("        export filter {\n");
        out.push_str("            if source = RTS_STATIC then accept;\n");
        out.push_str("            if proto = \"DIRECT_CNI\" then accept;\n");
        if !learn.is_empty() {
            // RTS_INHERIT is how BIRD tags a route the kernel protocol picked up via `learn`
            // (road-warrior host routes) - distinct from RTS_STATIC/RTS_DEVICE.
            out.push_str("            if source = RTS_INHERIT then accept;\n");
        }
        out.push_str("            reject;\n");
        out.push_str("        };\n");
        out.push_str("        next hop self;\n");
        out.push_str("    };\n");
        out.push_str("}\n");
    }

    out
}

/// Name of this operator's rendered OSPF protocol block - see `render()`.
const OSPF_PROTOCOL: &str = "mesh";

async fn run_birdc_configure() -> Result<()> {
    let output = Command::new("birdc")
        .arg("configure")
        .output()
        .await
        .context("failed to spawn birdc")?;
    anyhow::ensure!(
        output.status.success(),
        "birdc configure failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn birdc_show(args: &[&str]) -> Result<String> {
    let output = Command::new("birdc")
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to spawn birdc {}", args.join(" ")))?;
    anyhow::ensure!(
        output.status.success(),
        "birdc {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Verified directly against a real BIRD 2.19.1 (the version this operator's own image ships -
/// see router/Dockerfile) `strict bind yes` protocol whose local address didn't exist yet at
/// bind time: `show protocols`' Info column reads exactly `Error: No listening socket`, a
/// terminal failure state distinct from the normal `Connect`/`Active`/`OpenSent` states a
/// still-negotiating-but-healthy session passes through - so matching this substring anywhere in
/// `show protocols` can't false-positive on a peer that's simply not up yet.
fn has_no_listening_socket(show_protocols_output: &str) -> bool {
    show_protocols_output.contains("No listening socket")
}

/// Every interface name BIRD's OSPF instance has actually attached to, per a real
/// `birdc show ospf interface <proto>` (verified against BIRD 2.19.1): each configured interface
/// prints as a `Interface <name> (<network>)` line, in a block that's entirely absent (just the
/// `<proto>:` header) when nothing has been attached yet.
fn ospf_configured_interfaces(show_ospf_interface_output: &str) -> HashSet<&str> {
    show_ospf_interface_output
        .lines()
        .filter_map(|l| l.strip_prefix("Interface "))
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

/// True if BIRD's live state (queried fresh via `birdc show ...`, never the rendered config text)
/// already reflects `ospf_ifaces`: no BGP protocol stuck with "No listening socket", and every
/// name in `ospf_ifaces` has a working OSPF interface attached. Both are symptoms of the same
/// interface-notification race `force_reconfigure`'s doc comment describes - a config that
/// already lists an interface/peer doesn't mean BIRD's interface manager actually caught up to it
/// yet, and a config-diff-gated `reconcile()` alone can never detect or retry that on its own.
pub async fn protocols_healthy(ospf_ifaces: &[String]) -> Result<bool> {
    let protocols = birdc_show(&["show", "protocols"]).await?;
    if has_no_listening_socket(&protocols) {
        return Ok(false);
    }
    if ospf_ifaces.is_empty() {
        return Ok(true);
    }
    let ospf = birdc_show(&["show", "ospf", "interface", OSPF_PROTOCOL]).await?;
    let configured = ospf_configured_interfaces(&ospf);
    Ok(ospf_ifaces
        .iter()
        .all(|iface| configured.contains(iface.as_str())))
}

pub async fn reconcile(
    path: &Path,
    loopback: Ipv4Addr,
    as_number: u32,
    ospf_ifaces: &[String],
    bgp_peers: &[BgpPeer],
    bypass: &[BypassRoute],
    announce: &[AnnounceRoute],
    learn: &[String],
) -> Result<()> {
    let desired = render(
        loopback,
        as_number,
        ospf_ifaces,
        bgp_peers,
        bypass,
        announce,
        learn,
    );
    let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
    if current == desired {
        return Ok(());
    }
    tokio::fs::write(path, &desired)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    run_birdc_configure().await
}

/// Unconditional reload, bypassing the config-text diff `reconcile()` uses to skip redundant
/// reloads: `strict bind yes` BGP protocols and OSPF interfaces can both lose a race against the
/// kernel's own (asynchronous) interface/address-change notification reaching BIRD's interface
/// manager, landing in a permanent "No listening socket" / never-attaches state from the first
/// reload even though the config text already lists them correctly. Since the config text never
/// changes again afterward, `reconcile()`'s diff check would never retry on its own - called by
/// `reconcile::bird_health_watchdog` (see main.rs) whenever `protocols_healthy` reports a drift,
/// not on a fixed startup-only timer.
pub async fn force_reconfigure() -> Result<()> {
    run_birdc_configure().await
}

/// Ensures the dedicated router loopback (`router-lo`, a dummy interface) exists and carries
/// this node's identity /32.
pub async fn ensure_loopback(rt: &RtClient, loopback: Ipv4Addr) -> Result<()> {
    let (index, _created) = rt.ensure_link(ROUTER_LOOPBACK_IFACE, "dummy").await?;
    rt.ensure_address(index, &format!("{loopback}/32")).await?;
    rt.set_up(index).await?;
    Ok(())
}

/// Renders the CNI conflist for this node's own pod-bridge network. `bridge`/`host-local`/
/// `loopback` are already present in `/opt/cni/bin` on Talos v1.8+, so the conflist is the only
/// piece this operator writes. `ipMasq: false` because inter-pod/inter-node traffic is routed
/// (via DIRECT_CNI + the mesh), never NAT'd - masquerading is nftables' job, only for external
/// traffic. `mtu: 1420` matches the AmneziaWG mesh interfaces' MTU, since cross-node pod traffic
/// transits them; a default 1500 would silently blackhole on PMTU. No explicit `ipam.routes`
/// entry for `0.0.0.0/0`: `isDefaultGateway: true` already makes `bridge` install that route,
/// and adding it again via `ipam.routes` fails every pod sandbox creation with `EEXIST`.
pub fn render_cni_conflist(pod_cidr: &str) -> String {
    format!(
        r#"{{
  "cniVersion": "1.0.0",
  "name": "slipmesh-pod-network",
  "plugins": [
    {{
      "type": "bridge",
      "bridge": "{CNI_BRIDGE_IFACE}",
      "isGateway": true,
      "isDefaultGateway": true,
      "ipMasq": false,
      "hairpinMode": true,
      "mtu": 1420,
      "ipam": {{
        "type": "host-local",
        "ranges": [[{{ "subnet": "{pod_cidr}" }}]]
      }}
    }},
    {{ "type": "loopback" }}
  ]
}}
"#
    )
}

/// Writes the rendered conflist to `path` (a hostPath-mounted `/etc/cni/net.d/`) - a one-shot
/// startup call, not part of the reconcile loop: a node's PodCIDR is immutable once allocated.
pub async fn write_cni_conflist(path: &Path, pod_cidr: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    tokio::fs::write(path, render_cni_conflist(pod_cidr))
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_hyphens_and_dots() {
        assert_eq!(sanitize_bird_id("ip-10-0-1-5"), "ip_10_0_1_5");
        assert_eq!(sanitize_bird_id("node.example.com"), "node_example_com");
    }

    #[test]
    fn sanitize_prefixes_leading_digit() {
        assert_eq!(sanitize_bird_id("1msk"), "_1msk");
    }

    #[test]
    fn empty_learn_disables_kernel_learn_and_rts_inherit() {
        let peers = vec![BgpPeer {
            label: "peer1".to_string(),
            loopback: "10.62.0.2".parse().unwrap(),
        }];
        let conf = render(
            "10.62.0.1".parse().unwrap(),
            64512,
            &[],
            &peers,
            &[],
            &[],
            &[],
        );
        assert!(conf.contains("learn no;"));
        assert!(!conf.contains("import filter"));
        assert!(!conf.contains("RTS_INHERIT"));
    }

    #[test]
    fn nonempty_learn_scopes_kernel_import_and_exports_rts_inherit() {
        let peers = vec![BgpPeer {
            label: "peer1".to_string(),
            loopback: "10.62.0.2".parse().unwrap(),
        }];
        let learn = vec!["10.99.0.5/32".to_string(), "10.99.0.6/32".to_string()];
        let conf = render(
            "10.62.0.1".parse().unwrap(),
            64512,
            &[],
            &peers,
            &[],
            &[],
            &learn,
        );
        assert!(conf.contains("    learn;\n"));
        assert!(conf.contains("if net ~ [ 10.99.0.5/32, 10.99.0.6/32 ] then accept;"));
        assert!(conf.contains("if source = RTS_INHERIT then accept;"));
        assert!(!conf.contains("learn no;"));
    }

    #[test]
    fn sanitize_leaves_already_valid_ids_alone() {
        assert_eq!(sanitize_bird_id("msk"), "msk");
        assert_eq!(sanitize_bird_id("node_1"), "node_1");
    }

    #[test]
    fn comment_strips_embedded_newlines() {
        assert_eq!(
            sanitize_comment("legit label\nprotocol static evil { route 0.0.0.0/0 blackhole; }"),
            "legit label protocol static evil { route 0.0.0.0/0 blackhole; }"
        );
        assert_eq!(sanitize_comment("plain label"), "plain label");
    }

    #[test]
    fn sanitize_quoted_strips_quotes_and_newlines() {
        assert_eq!(
            sanitize_quoted("mesh-lon\"; protocol static evil { route 0.0.0.0/0 blackhole; } \""),
            "mesh-lon; protocol static evil { route 0.0.0.0/0 blackhole; } "
        );
        assert_eq!(sanitize_quoted("mesh-lon"), "mesh-lon");
    }

    #[test]
    fn cni_conflist_is_valid_json_with_expected_shape() {
        let rendered = render_cni_conflist("10.244.3.0/24");
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("conflist must be valid JSON");
        assert_eq!(parsed["plugins"][0]["type"], "bridge");
        assert_eq!(parsed["plugins"][0]["bridge"], CNI_BRIDGE_IFACE);
        assert_eq!(parsed["plugins"][0]["ipMasq"], false);
        assert_eq!(parsed["plugins"][0]["mtu"], 1420);
        assert_eq!(
            parsed["plugins"][0]["ipam"]["ranges"][0][0]["subnet"],
            "10.244.3.0/24"
        );
        assert_eq!(parsed["plugins"][1]["type"], "loopback");
    }

    // Fixtures below are real `birdc` output, captured against BIRD 2.19.1 (the exact version
    // router/Dockerfile ships) running in a container with a deliberately reproduced "strict bind
    // yes local address not present yet" / "OSPF interface not attached yet" race - not
    // hand-guessed from memory of BIRD's CLI format (see AGENTS.md's "verify before writing it
    // down" rule).
    const SHOW_PROTOCOLS_NO_LISTENING_SOCKET: &str = "\
BIRD 2.19.1 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     22:24:15.259
ospf1      OSPF       master4    up     22:24:15.259  Alone
ibgp_test  BGP        ---        down   22:24:15.266  Error: No listening socket
";

    const SHOW_PROTOCOLS_HEALTHY: &str = "\
BIRD 2.19.1 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     22:30:37.362
mesh       OSPF       master4    up     22:30:37.362  Alone
ibgp_test  BGP        ---        start  22:31:14.133  Connect
";

    const SHOW_OSPF_INTERFACE_NONE_CONFIGURED: &str = "BIRD 2.19.1 ready.\nmesh:\n";

    const SHOW_OSPF_INTERFACE_TWO_CONFIGURED: &str = "\
BIRD 2.19.1 ready.
mesh:
Interface lo (10.0.0.1/32)
\tType: nbma
\tArea: 0.0.0.0 (0)
\tState: Waiting (stub)
Interface mesh-a (10.99.0.0/31)
\tType: ptp
\tArea: 0.0.0.0 (0)
\tState: PtP (stub)
Interface mesh-b (10.99.0.2/31)
\tType: ptp
\tArea: 0.0.0.0 (0)
\tState: PtP (stub)
";

    #[test]
    fn detects_no_listening_socket() {
        assert!(has_no_listening_socket(SHOW_PROTOCOLS_NO_LISTENING_SOCKET));
    }

    #[test]
    fn no_listening_socket_absent_when_healthy() {
        assert!(!has_no_listening_socket(SHOW_PROTOCOLS_HEALTHY));
    }

    #[test]
    fn parses_configured_ospf_interfaces() {
        let configured = ospf_configured_interfaces(SHOW_OSPF_INTERFACE_TWO_CONFIGURED);
        assert_eq!(configured, HashSet::from(["lo", "mesh-a", "mesh-b"]));
    }

    #[test]
    fn no_configured_ospf_interfaces_parses_as_empty() {
        assert!(ospf_configured_interfaces(SHOW_OSPF_INTERFACE_NONE_CONFIGURED).is_empty());
    }
}
