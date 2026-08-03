//! Shared plumbing for every operator's `*-rbacgen` binary - prints the exact `rules:` a binary
//! needs to run, built from what its own code actually calls (`Api::get`/`list`/`watch`/`patch`/
//! `patch_status`/`create`/`replace_status`) - the same "generate from the source of truth" idea
//! as `crdgen`, just for RBAC instead of CRD schemas. A rule here is a fact about the binary, not
//! a deployment decision: ServiceAccount naming, Role vs. ClusterRole, and which namespace(s) to
//! bind in are for whatever chart/manifest consumes this output to decide, and deliberately have
//! no representation here.
//!
//! Note this only covers direct API calls (`Api<T>`/`Controller`/`reflector`/`watcher`) - it
//! can't see calls made by an external process an operator merely spawns (e.g. `bird`/`birdc`,
//! `nft`), since those don't go through `kube` at all and (in this codebase) never touch the
//! Kubernetes API themselves.

use k8s_openapi::api::rbac::v1::PolicyRule;

/// One `PolicyRule` - `group` is the plain apiGroup string (`""` for core resources like
/// `secrets`/`nodes`, `"slipmesh.net"` for every CRD in this codebase, `"networking.k8s.io"` for
/// `ServiceCIDR`). A `/status` subresource (e.g. `"meshnodes/status"`) is just another string in
/// `resources`, in the same apiGroup as its base resource - Kubernetes has no separate concept for
/// it beyond that.
///
/// Prefer `rule_for`/`status_rule_for` over calling this directly with hand-typed strings - a
/// hand-typed `"meshnodes"` can drift from the CRD's actual `#[kube(plural = ...)]` the same way
/// the verbs list can drift from the code (see the module doc's admitted limits on that front);
/// `rule_for` at least closes the resource-name/apiGroup half of that gap.
pub fn rule(group: &str, resources: &[&str], verbs: &[&str]) -> PolicyRule {
    PolicyRule {
        api_groups: Some(vec![group.to_string()]),
        resources: Some(resources.iter().map(|s| s.to_string()).collect()),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        non_resource_urls: None,
        resource_names: None,
    }
}

/// `(apiGroup, plural resource name)` for `K`, read from `K`'s own `kube::Resource` impl - for a
/// `#[derive(CustomResource)]` type this is the exact same `#[kube(group = ..., plural = ...)]`
/// metadata `K::crd()` (i.e. `crdgen`) uses, and for a builtin (`Secret`, `Node`, `ServiceCIDR`)
/// it's k8s-openapi's own generated `GROUP`/`URL_PATH_SEGMENT` constants - never a hand-typed
/// string that could drift from either source.
pub fn resource<K: kube::Resource<DynamicType = ()>>() -> (String, String) {
    (K::group(&()).into_owned(), K::plural(&()).into_owned())
}

/// A rule against `K`'s own base resource (e.g. `meshnodes`), group/plural derived via
/// `resource::<K>()`.
pub fn rule_for<K: kube::Resource<DynamicType = ()>>(verbs: &[&str]) -> PolicyRule {
    let (group, plural) = resource::<K>();
    rule(&group, &[&plural], verbs)
}

/// A rule against `K`'s `/status` subresource (e.g. `meshnodes/status`) - same apiGroup as the
/// base resource, per Kubernetes' subresource convention.
pub fn status_rule_for<K: kube::Resource<DynamicType = ()>>(verbs: &[&str]) -> PolicyRule {
    let (group, plural) = resource::<K>();
    let status = format!("{plural}/status");
    rule(&group, &[&status], verbs)
}

/// Prints `rules` as a bare YAML sequence - not wrapped in its own `rules:` key, so a chart
/// template can embed the output directly as the value of a Role/ClusterRole's own `rules:` field.
pub fn print_rules(rules: &[PolicyRule]) {
    println!(
        "{}",
        serde_yaml::to_string(rules).expect("PolicyRule list always serializes to YAML")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_builds_expected_shape() {
        let r = rule(
            "slipmesh.net",
            &["meshnodes", "meshnodes/status"],
            &["get", "patch"],
        );
        assert_eq!(r.api_groups, Some(vec!["slipmesh.net".to_string()]));
        assert_eq!(
            r.resources,
            Some(vec![
                "meshnodes".to_string(),
                "meshnodes/status".to_string()
            ])
        );
        assert_eq!(r.verbs, vec!["get".to_string(), "patch".to_string()]);
        assert_eq!(r.non_resource_urls, None);
        assert_eq!(r.resource_names, None);
    }

    #[test]
    fn core_group_is_empty_string_not_omitted() {
        // Kubernetes' RBAC convention: the core apiGroup is the literal empty string "", not a
        // missing/omitted apiGroups entry - `rule("", ...)` must preserve that distinction.
        let r = rule("", &["secrets"], &["get"]);
        assert_eq!(r.api_groups, Some(vec![String::new()]));
    }

    #[test]
    fn resource_for_builtin_matches_k8s_openapi_constants() {
        // Secret's own generated GROUP/URL_PATH_SEGMENT constants ("" / "secrets") - resource::<K>
        // must read the exact same metadata a hand-typed `rule("", &["secrets"], ...)` guesses at.
        let (group, plural) = resource::<k8s_openapi::api::core::v1::Secret>();
        assert_eq!(group, "");
        assert_eq!(plural, "secrets");
    }

    #[test]
    fn resource_for_crd_matches_its_own_kube_macro_metadata() {
        // MeshNode's #[kube(group = "slipmesh.net", plural = "meshnodes", ...)] - the exact same
        // metadata crdgen's MeshNode::crd() renders into the CRD's spec.group/spec.names.plural.
        let (group, plural) = resource::<crate::mesh_types::MeshNode>();
        assert_eq!(group, "slipmesh.net");
        assert_eq!(plural, "meshnodes");
    }

    #[test]
    fn rule_for_and_status_rule_for_derive_the_right_strings() {
        let base = rule_for::<crate::mesh_types::MeshLink>(&["list", "watch"]);
        assert_eq!(base.api_groups, Some(vec!["slipmesh.net".to_string()]));
        assert_eq!(base.resources, Some(vec!["meshlinks".to_string()]));

        let status = status_rule_for::<crate::mesh_types::MeshLink>(&["patch"]);
        assert_eq!(status.api_groups, Some(vec!["slipmesh.net".to_string()]));
        assert_eq!(status.resources, Some(vec!["meshlinks/status".to_string()]));
    }
}
