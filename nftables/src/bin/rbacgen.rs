//! Prints the exact `rules:` this operator's binary needs - see `common::rbacgen`'s module doc.
//! Entirely read-only against Kubernetes: `NatPrivateRange` has no status subresource, and this
//! operator never patches/creates/deletes anything - it only drives local `nft` state.

#[path = "../types.rs"]
mod types;

use common::rbacgen::rule_for;
use types::NatPrivateRange;

fn main() {
    common::rbacgen::print_rules(&[rule_for::<NatPrivateRange>(&["list", "watch"])]);
}
