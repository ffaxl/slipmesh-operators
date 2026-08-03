//! Prints the exact `rules:` this operator's binary needs - see `common::rbacgen`'s module doc.
//! Resource names/apiGroups come from each type's own `kube::Resource` impl (`rule_for`/
//! `status_rule_for`), not hand-typed strings - only the verb lists are still asserted by hand.

use common::mesh_types::RoadWarrior;
use common::rbacgen::{rule_for, status_rule_for};
use k8s_openapi::api::core::v1::Secret;

fn main() {
    common::rbacgen::print_rules(&[
        // roadwarriors-key Secret bootstrap (common::keys::get_or_create_secret_key) - identical
        // across every node, unlike mesh's per-node keys, but the same get/create/patch shape.
        rule_for::<Secret>(&["get", "create", "patch"]),
        // Primary resource of this operator's Controller (list/watch) and the startup peer-list
        // sync (list). No finalizer on this CRD - see main.rs's "no shutdown teardown" note.
        rule_for::<RoadWarrior>(&["list", "watch"]),
        // PublicKeyConflict/AllowedIpsRoutable conditions, plus connectedNode/lastHandshakeTime
        // from handshake.rs's 1Hz poll loop.
        status_rule_for::<RoadWarrior>(&["patch"]),
    ]);
}
