//! Prints the exact `rules:` this operator's binary needs - see `common::rbacgen`'s module doc.
//! Audited directly against `main.rs`/`reconcile.rs`'s own `Api<T>` calls (including
//! `common::keys::get_or_create_secret_key` for the `secrets` rule and `common::pool::allocate`/
//! `release` for the `meshpools`/`meshpools/status` rules - the latter goes through
//! `replace_status`, i.e. HTTP PUT, which Kubernetes maps to the `update` verb, not `patch`).
//! Resource names/apiGroups come from each type's own `kube::Resource` impl (`rule_for`/
//! `status_rule_for`), not hand-typed strings - only the verb lists are still asserted by hand.

use common::mesh_types::{MeshLink, MeshNode, MeshPool};
use common::rbacgen::{rule_for, status_rule_for};
use k8s_openapi::api::core::v1::Secret;

fn main() {
    common::rbacgen::print_rules(&[
        // mesh-keys Secret bootstrap (common::keys::get_or_create_secret_key) - get/create on
        // first boot, patch to add this node's own entry to an already-existing Secret.
        rule_for::<Secret>(&["get", "create", "patch"]),
        // Read-only: reconciled off an independent reflector (main.rs's spawn_reflector) and the
        // Controller's own MeshNode watch mapper.
        rule_for::<MeshNode>(&["list", "watch"]),
        // Publishes this node's derived public key, and a peer's Ready=False on a mesh_label
        // collision.
        status_rule_for::<MeshNode>(&["patch"]),
        // Primary resource of this operator's Controller - list/watch drive reconcile, patch adds/
        // removes the per-node finalizer.
        rule_for::<MeshLink>(&["list", "watch", "patch"]),
        // Ready condition plus pool/network/port allocation results.
        status_rule_for::<MeshLink>(&["patch"]),
        rule_for::<MeshPool>(&["list", "get"]),
        status_rule_for::<MeshPool>(&["update"]),
    ]);
}
