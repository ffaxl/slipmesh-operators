//! Link-position numbering: link index `k` places its `/31` at `network + 2k` and its port at
//! `base_port + k` on both ends. `k` is implicit, not a stored field - either the position
//! `common::pool::allocate` walked to, or (for a pinned `MeshLink.spec.network`) recovered via
//! `index_of`. `node_a` always gets the lower address (see `MeshLinkSpec::is_lower`).

use std::net::Ipv4Addr;

/// Generates successive (`/31` CIDR, port) pairs within `network/prefix_len` starting at
/// `base_port`, in address order - the candidate stream `common::pool::allocate` walks. Stops once a
/// candidate no longer fits the range. Port is carried alongside its network so a successful
/// `common::pool::allocate` returns the exact port with no second lookup.
pub fn candidate_networks(
    network: Ipv4Addr,
    prefix_len: u8,
    base_port: u16,
) -> impl Iterator<Item = (String, u16)> {
    let network_u32 = u32::from(network);
    let host_bits = 32 - u32::from(prefix_len);
    let network_size: u64 = 1u64 << host_bits;
    (0u32..).map_while(move |index| {
        let offset = index.checked_mul(2)?;
        let lo = network_u32.checked_add(offset)?;
        let hi = lo.checked_add(1)?;
        let in_range = (hi as u64).wrapping_sub(u64::from(network_u32)) < network_size;
        if !in_range {
            return None;
        }
        let port = base_port.checked_add(u16::try_from(index).ok()?)?;
        Some((format!("{}/31", Ipv4Addr::from(lo)), port))
    })
}

/// Inverse of `candidate_networks`: recovers the position index of `link_network` (a `/31`'s low
/// address) within `network`. `None` if unaligned to a `/31` boundary or before `network`.
pub fn index_of(network: Ipv4Addr, link_network: Ipv4Addr) -> Option<u32> {
    let offset = u32::from(link_network).checked_sub(u32::from(network))?;
    (offset % 2 == 0).then_some(offset / 2)
}

/// Consumer-side counterpart to `addressing_for`, used once a link already has a `/31` in
/// `MeshLink.status.network`. Needs only the resolved `/31`'s low address, no pool lookup.
pub fn local_addr(
    link_network: Ipv4Addr,
    node_a: &str,
    node_b: &str,
    me: &str,
) -> anyhow::Result<Ipv4Addr> {
    anyhow::ensure!(
        me == node_a || me == node_b,
        "local_addr: {me} is not a party to link {node_a}<->{node_b}"
    );
    if me == node_a {
        return Ok(link_network);
    }
    u32::from(link_network)
        .checked_add(1)
        .map(Ipv4Addr::from)
        .ok_or_else(|| {
            anyhow::anyhow!("local_addr: {link_network} has no second address in its /31")
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkAddressing {
    pub local_addr: Ipv4Addr,
    pub local_prefix: u8,
    pub remote_addr: Ipv4Addr,
    pub port: u16,
}

/// Called by the allocating side of a link only (`node_a` - see `MeshLinkSpec::is_lower`), right
/// after `common::pool::allocate`/a pin resolves an index. `me` must be one of `node_a`/`node_b`.
pub fn addressing_for(
    network: Ipv4Addr,
    prefix_len: u8,
    base_port: u16,
    index: u32,
    node_a: &str,
    node_b: &str,
    me: &str,
) -> anyhow::Result<LinkAddressing> {
    anyhow::ensure!(
        me == node_a || me == node_b,
        "addressing_for: {me} is not a party to link {node_a}<->{node_b}"
    );

    let network_u32 = u32::from(network);
    // Each link consumes a /31 (2 addresses) at offset 2*index from the network base. Checked
    // arithmetic: an unchecked wraparound would silently compute a wrong address/port.
    let offset = index.checked_mul(2).ok_or_else(|| {
        anyhow::anyhow!("link {node_a}<->{node_b} (index={index}): index overflow")
    })?;
    let lo_u32 = network_u32.checked_add(offset).ok_or_else(|| {
        anyhow::anyhow!("link {node_a}<->{node_b} (index={index}): address overflow")
    })?;
    let hi_u32 = lo_u32.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("link {node_a}<->{node_b} (index={index}): address overflow")
    })?;

    // Confirm both addresses fall inside the configured network rather than silently aliasing
    // into a neighboring link's range.
    let host_bits = 32 - prefix_len as u32;
    let network_size: u64 = 1u64 << host_bits;
    let offset = (hi_u32 as u64).wrapping_sub(network_u32 as u64);
    anyhow::ensure!(
        offset < network_size,
        "link {node_a}<->{node_b} (index={index}) does not fit in {network}/{prefix_len}"
    );

    let lo = Ipv4Addr::from(lo_u32);
    let hi = Ipv4Addr::from(hi_u32);
    let (local, remote) = if me == node_a { (lo, hi) } else { (hi, lo) };

    Ok(LinkAddressing {
        local_addr: local,
        local_prefix: 31,
        remote_addr: remote,
        port: u16::try_from(index)
            .ok()
            .and_then(|index| base_port.checked_add(index))
            .ok_or_else(|| {
                anyhow::anyhow!("link {node_a}<->{node_b}: port overflow at index {index}")
            })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_link_matches_network_base() {
        let a = addressing_for(
            Ipv4Addr::new(172, 20, 255, 0),
            24,
            51820,
            0,
            "lon",
            "msk",
            "msk",
        )
        .unwrap();
        // me="msk" is node_b here, so it gets the high address (.1); node_a ("lon") gets .0.
        assert_eq!(a.local_addr, Ipv4Addr::new(172, 20, 255, 1));
        assert_eq!(a.remote_addr, Ipv4Addr::new(172, 20, 255, 0));
        assert_eq!(a.port, 51820);
    }

    #[test]
    fn second_link_offsets_by_two() {
        let a = addressing_for(
            Ipv4Addr::new(172, 20, 255, 0),
            24,
            51820,
            1,
            "fra",
            "lon",
            "fra",
        )
        .unwrap();
        assert_eq!(a.local_addr, Ipv4Addr::new(172, 20, 255, 2));
        assert_eq!(a.remote_addr, Ipv4Addr::new(172, 20, 255, 3));
        assert_eq!(a.port, 51821);
    }

    #[test]
    fn rejects_uninvolved_node() {
        assert!(
            addressing_for(
                Ipv4Addr::new(172, 20, 255, 0),
                24,
                51820,
                0,
                "lon",
                "msk",
                "fra"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_overflow_past_network() {
        // /31 host range for a /24 has 128 link slots (indices 0..=127); index 128 overflows.
        assert!(
            addressing_for(
                Ipv4Addr::new(172, 20, 255, 0),
                24,
                51820,
                128,
                "lon",
                "msk",
                "msk"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_port_overflow_instead_of_wrapping() {
        // A wide enough network (/8) admits an index whose port computation (base_port + index)
        // would silently truncate/wrap if cast to u16 before the overflow check - must fail
        // instead of colliding with the index=0 link's port.
        let a = addressing_for(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
            51820,
            65536,
            "lon",
            "msk",
            "msk",
        );
        assert!(a.is_err());
    }

    #[test]
    fn candidate_networks_step_by_two() {
        let mut c = candidate_networks(Ipv4Addr::new(172, 20, 255, 0), 24, 51820);
        assert_eq!(c.next(), Some(("172.20.255.0/31".to_string(), 51820)));
        assert_eq!(c.next(), Some(("172.20.255.2/31".to_string(), 51821)));
        assert_eq!(c.next(), Some(("172.20.255.4/31".to_string(), 51822)));
    }

    #[test]
    fn candidate_networks_stops_at_range_end() {
        // A /31 host range for a /24 has 128 link slots (indices 0..=127) - the 128th candidate
        // would overflow past the configured network, so the sequence must end at 128 items.
        let count = candidate_networks(Ipv4Addr::new(172, 20, 255, 0), 24, 51820).count();
        assert_eq!(count, 128);
    }

    #[test]
    fn index_of_recovers_position() {
        let network = Ipv4Addr::new(172, 20, 255, 0);
        assert_eq!(index_of(network, Ipv4Addr::new(172, 20, 255, 0)), Some(0));
        assert_eq!(index_of(network, Ipv4Addr::new(172, 20, 255, 2)), Some(1));
        assert_eq!(index_of(network, Ipv4Addr::new(172, 20, 255, 4)), Some(2));
    }

    #[test]
    fn index_of_rejects_misaligned_or_before_base() {
        let network = Ipv4Addr::new(172, 20, 255, 0);
        // Odd offset - not a /31 boundary produced by candidate_networks.
        assert_eq!(index_of(network, Ipv4Addr::new(172, 20, 255, 3)), None);
        // Before the pool's own base address entirely.
        assert_eq!(index_of(network, Ipv4Addr::new(172, 20, 254, 254)), None);
    }

    #[test]
    fn local_addr_picks_low_for_node_a_high_for_node_b() {
        let net = Ipv4Addr::new(172, 20, 255, 0);
        assert_eq!(local_addr(net, "lon", "msk", "lon").unwrap(), net);
        assert_eq!(
            local_addr(net, "lon", "msk", "msk").unwrap(),
            Ipv4Addr::new(172, 20, 255, 1)
        );
    }

    #[test]
    fn local_addr_picks_low_for_node_a_regardless_of_name() {
        // node_a="zzz", node_b="aaa" - node_a still gets the low address, name aside.
        let net = Ipv4Addr::new(172, 20, 255, 0);
        assert_eq!(local_addr(net, "zzz", "aaa", "zzz").unwrap(), net);
        assert_eq!(
            local_addr(net, "zzz", "aaa", "aaa").unwrap(),
            Ipv4Addr::new(172, 20, 255, 1)
        );
    }

    #[test]
    fn local_addr_rejects_uninvolved_node() {
        let net = Ipv4Addr::new(172, 20, 255, 0);
        assert!(local_addr(net, "lon", "msk", "fra").is_err());
    }
}
