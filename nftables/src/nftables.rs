//! Renders and applies the NAT/filter baseline via `nft -f` (subprocess): raw NFNETLINK
//! (`rustables`) has no support for the MSS-clamp statement used here. The runtime image only
//! carries the `nftables` package (default-iface detection goes through `common::netlink::rt`, not `ip`).
//!
//! Uses its own named tables (`nftables_operator_filter`/`nftables_operator_nat`), not
//! `flush ruleset` - kube-proxy manages its own nftables/iptables-nft rules on the same node, and
//! a global flush would break cluster networking.

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Rejects anything that isn't a well-formed IPv4 CIDR before it reaches the ruleset text handed
/// to `nft -f` - a malformed entry (e.g. containing `}`) could otherwise break out of the
/// `elements = { ... }` set literal and be interpreted as ruleset syntax.
fn validate_cidr(s: &str) -> Result<()> {
    common::netlink::rt::parse_cidr(s).map(|_| ())
}

pub async fn apply(iface: &str, nat_private: &[String]) -> Result<()> {
    for entry in nat_private {
        validate_cidr(entry)
            .with_context(|| "rejecting NatPrivateRange.spec.cidrs entry".to_string())?;
    }

    let mut ruleset = r#"table inet nftables_operator_filter {
	chain forward {
		type filter hook forward priority filter; policy accept;
		tcp flags syn / syn,rst counter tcp option maxseg size set rt mtu
	}
}
"#
    .to_string();

    // `elements = {{ }}` (empty set literal) is a hard nft syntax error, not an empty-but-valid
    // set - so an empty `nat_private` means "no NAT table at all" rather than a broken one.
    if !nat_private.is_empty() {
        let nat_private = nat_private.join(", ");
        ruleset.push_str(&format!(
            r#"
table ip nftables_operator_nat {{
	set nat_private {{
		type ipv4_addr
		flags interval
		elements = {{ {nat_private} }}
	}}

	chain postrouting {{
		type nat hook postrouting priority srcnat; policy accept;
		oifname "{iface}" ip saddr @nat_private counter masquerade
	}}
}}
"#
        ));
    }

    // Deleting our own named tables before recreating them is idempotent and safe - nothing else
    // references them. Errors are ignored: the delete fails (harmlessly) the first time either
    // table doesn't exist yet.
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "nftables_operator_filter"])
        .status()
        .await;
    let _ = Command::new("nft")
        .args(["delete", "table", "ip", "nftables_operator_nat"])
        .status()
        .await;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn nft")?;
    child
        .stdin
        .take()
        .expect("just configured with Stdio::piped()")
        .write_all(ruleset.as_bytes())
        .await
        .context("failed to write ruleset to nft stdin")?;
    let status = child.wait().await.context("failed waiting on nft")?;
    anyhow::ensure!(status.success(), "nft -f failed with status {status:?}");

    tracing::info!(iface, "nftables baseline applied");
    Ok(())
}
