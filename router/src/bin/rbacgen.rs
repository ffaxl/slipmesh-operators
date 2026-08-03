//! Prints the exact `rules:` this operator's binary needs - see `common::rbacgen`'s module doc.
//!
//! Unlike `crdgen` (which only prints the CRDs router *owns* - RouterNode/BypassSource/
//! RouterPool - since MeshLink/MeshNode/RoadWarrior are mesh's/roadwarriors' to define), this
//! prints rules for every resource router's *binary* actually touches, ownership aside: it reads
//! MeshLink/MeshNode/RoadWarrior just as much as it reads its own CRDs, and needs RBAC for all of
//! it to run. `routerpools`/`routerpools/status` go through `common::pool::allocate`/`release`,
//! whose status write is `replace_status` (HTTP PUT -> the `update` verb, not `patch`).
//! Resource names/apiGroups come from each type's own `kube::Resource` impl (`rule_for`/
//! `status_rule_for`), not hand-typed strings - only the verb lists are still asserted by hand.
//!
//! Printed as two groups, cluster-scoped first - `common::rbacgen` itself has no opinion on
//! Role vs. ClusterRole (that's still a deployment decision, made by whatever consumes this
//! output), but router is the one binary in this codebase that needs *both* kinds simultaneously
//! (`Node`/`ServiceCIDR` are cluster-scoped built-ins - `main.rs` reaches them via `Api::all`,
//! everything else via `Api::namespaced`), so at least which rules go in which is spelled out
//! here instead of making every future reader re-derive it from `main.rs`.

#[path = "../types.rs"]
mod types;

use common::mesh_types::{MeshLink, MeshNode, RoadWarrior};
use common::rbacgen::{print_rules, rule_for, status_rule_for};
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::networking::v1::ServiceCIDR;
use types::{BypassSource, RouterNode, RouterPool};

fn main() {
    println!("# cluster-scoped - ClusterRole");
    print_rules(&[
        // This node's own Node object, for spec.podCIDR - one-shot at startup.
        rule_for::<Node>(&["get"]),
        // `main.rs` tries `get("kubernetes")` first, falls back to `list`.
        rule_for::<ServiceCIDR>(&["get", "list"]),
    ]);

    println!("# namespaced - Role");
    print_rules(&[
        // Read-only: OSPF interface set and iBGP peer public keys/loopbacks come from these via
        // independent reflectors/the Controller's own MeshLink watch.
        rule_for::<MeshLink>(&["list", "watch"]),
        rule_for::<MeshNode>(&["list", "watch"]),
        // Read-only: source of the BIRD kernel `learn` import filter (see router::bird).
        rule_for::<RoadWarrior>(&["list", "watch"]),
        // Owned by router: primary loopback/router_label identity, plus the RouterPool-release
        // finalizer.
        rule_for::<RouterNode>(&["list", "watch", "patch"]),
        status_rule_for::<RouterNode>(&["patch"]),
        rule_for::<BypassSource>(&["list", "watch"]),
        status_rule_for::<BypassSource>(&["patch"]),
        rule_for::<RouterPool>(&["list", "get"]),
        status_rule_for::<RouterPool>(&["update"]),
    ]);
}
