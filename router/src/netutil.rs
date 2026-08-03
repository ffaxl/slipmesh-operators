//! IPv4-only CIDR set operations equivalent to Python's `ipaddress` module functions
//! `subnet_of`, `address_exclude`, `collapse_addresses`. IPv4 only - BIRD config here has no
//! ipv6 channel yet.

pub type Cidr = (u32, u8); // (network address, prefix length)

fn mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

pub fn network_addr(addr: u32, prefix_len: u8) -> u32 {
    addr & mask(prefix_len)
}

pub fn contains(outer: Cidr, inner: Cidr) -> bool {
    inner.1 >= outer.1 && network_addr(inner.0, outer.1) == outer.0
}

/// Splits `net` into the minimal set of subnets that cover `net` but exclude `exclude`.
/// Caller's responsibility: `exclude` must be `contains`ed by `net`.
pub fn address_exclude(net: Cidr, exclude: Cidr) -> Vec<Cidr> {
    if net.1 >= exclude.1 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = net;
    while current.1 < exclude.1 {
        let child_len = current.1 + 1;
        let half_size = 1u32 << (32 - child_len);
        let lower = (current.0, child_len);
        let upper = (current.0.wrapping_add(half_size), child_len);
        if contains(lower, exclude) {
            out.push(upper);
            current = lower;
        } else {
            out.push(lower);
            current = upper;
        }
    }
    out
}

/// Merges overlapping/subsumed/sibling-adjacent networks into their minimal covering set -
/// mirrors `ipaddress.collapse_addresses()`: first drops anything already contained in a larger
/// entry, then repeatedly merges same-length sibling pairs (differ only in their last bit, so
/// together they exactly fill their shared parent prefix) until no more merges apply.
pub fn collapse(nets: &[Cidr]) -> Vec<Cidr> {
    let mut nets: Vec<Cidr> = nets.to_vec();
    nets.sort();
    nets.dedup();

    // Drop anything fully contained in a different, larger entry.
    let mut deduped: Vec<Cidr> = Vec::new();
    for &n in &nets {
        if !nets
            .iter()
            .any(|&other| other != n && other.1 < n.1 && contains(other, n))
        {
            deduped.push(n);
        }
    }
    deduped.sort();
    deduped.dedup();

    loop {
        let mut merged: Vec<Cidr> = Vec::new();
        let mut used = vec![false; deduped.len()];
        let mut changed = false;
        for i in 0..deduped.len() {
            if used[i] {
                continue;
            }
            let (addr, len) = deduped[i];
            if len == 0 {
                merged.push(deduped[i]);
                continue;
            }
            let parent = network_addr(addr, len - 1);
            let sibling_addr = parent | (1u32 << (32 - len));
            let is_lower = addr == parent;
            let sibling = if is_lower {
                (sibling_addr, len)
            } else {
                (parent, len)
            };
            // Find an unused sibling entry.
            if let Some(j) = deduped
                .iter()
                .enumerate()
                .position(|(idx, &c)| idx != i && !used[idx] && c == sibling)
            {
                used[i] = true;
                used[j] = true;
                merged.push((parent, len - 1));
                changed = true;
            } else {
                used[i] = true;
                merged.push(deduped[i]);
            }
        }
        merged.sort();
        merged.dedup();
        deduped = merged;
        if !changed {
            break;
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(a: u8, b: u8, c_: u8, d: u8, len: u8) -> Cidr {
        (u32::from_be_bytes([a, b, c_, d]), len)
    }

    #[test]
    fn exclude_splits_correctly() {
        // 10.0.0.0/24 minus 10.0.0.128/25 -> 10.0.0.0/25
        let out = address_exclude(c(10, 0, 0, 0, 24), c(10, 0, 0, 128, 25));
        assert_eq!(out, vec![c(10, 0, 0, 0, 25)]);
    }

    #[test]
    fn exclude_splits_nested() {
        // 10.0.0.0/24 minus 10.0.0.64/26 -> 10.0.0.128/25, 10.0.0.0/26
        let out = address_exclude(c(10, 0, 0, 0, 24), c(10, 0, 0, 64, 26));
        let mut out = out;
        out.sort();
        let mut expected = vec![c(10, 0, 0, 128, 25), c(10, 0, 0, 0, 26)];
        expected.sort();
        assert_eq!(out, expected);
    }

    #[test]
    fn collapse_merges_siblings() {
        let out = collapse(&[c(10, 0, 0, 0, 25), c(10, 0, 0, 128, 25)]);
        assert_eq!(out, vec![c(10, 0, 0, 0, 24)]);
    }

    #[test]
    fn collapse_drops_subsumed() {
        let out = collapse(&[c(10, 0, 0, 0, 24), c(10, 0, 0, 0, 25)]);
        assert_eq!(out, vec![c(10, 0, 0, 0, 24)]);
    }

    #[test]
    fn collapse_leaves_unrelated_alone() {
        let mut out = collapse(&[c(10, 0, 0, 0, 24), c(192, 168, 1, 0, 24)]);
        out.sort();
        let mut expected = vec![c(10, 0, 0, 0, 24), c(192, 168, 1, 0, 24)];
        expected.sort();
        assert_eq!(out, expected);
    }

    #[test]
    fn contains_checks_prefix_and_alignment() {
        assert!(contains(c(10, 0, 0, 0, 8), c(10, 1, 2, 0, 24)));
        assert!(!contains(c(10, 0, 0, 0, 24), c(10, 0, 1, 0, 24)));
    }
}
