//! Prints the exact `rules:` this operator's binary needs - see `common::rbacgen`'s module doc.
//! Resource names/apiGroups come from each type's own `kube::Resource` impl (`rule_for`/
//! `status_rule_for`), not hand-typed strings - only the verb lists are still asserted by hand.

use common::mesh_types::RoadWarrior;
use common::rbacgen::{named_rule_for, rule_for, status_rule_for};
use k8s_openapi::api::core::v1::Secret;
use roadwarriors::{ROADWARRIORS_KEY_SECRET, RoadWarriorConfig};

fn main() {
    common::rbacgen::print_rules(&[
        // roadwarriors-key Secret bootstrap (common::keys::get_or_create_secret_key) - identical
        // across every node, unlike mesh's per-node keys. `create` can't be scoped by
        // resourceNames - the object doesn't exist yet at authorization time - but get/patch
        // (against the already-existing Secret) are scoped to this operator's own hardcoded name,
        // not every Secret in the namespace.
        rule_for::<Secret>(&["create"]),
        named_rule_for::<Secret>(&[ROADWARRIORS_KEY_SECRET], &["get", "patch"]),
        // Primary resource of this operator's Controller (list/watch) and the startup peer-list
        // sync (list). No finalizer on this CRD - see main.rs's "no shutdown teardown" note.
        rule_for::<RoadWarrior>(&["list", "watch"]),
        // PublicKeyConflict/AllowedIpsRoutable conditions, plus connectedNode/lastHandshakeTime
        // from handshake.rs's 1Hz poll loop.
        status_rule_for::<RoadWarrior>(&["patch"]),
        // One-shot at startup - see obfuscation_from_configs.
        rule_for::<RoadWarriorConfig>(&["list"]),
    ]);
}
