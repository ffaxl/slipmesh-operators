//! Shared plumbing for every operator's `*-crdgen` binary - only the "serialize and print" part.
//! Which CRD *types* each binary prints is still decided per-operator (see `mesh_types.rs`'s
//! module doc for which types are actually cross-operator-shared vs. staying local to the one
//! operator that owns them) - this module has no opinion on that, just the boilerplate every
//! binary otherwise repeated.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

/// Prints each CRD as YAML, `---`-separated - the multi-document form `kubectl apply -f` expects
/// from a single file/stream.
pub fn print_all(crds: &[CustomResourceDefinition]) {
    for (i, crd) in crds.iter().enumerate() {
        if i > 0 {
            println!("---");
        }
        println!(
            "{}",
            serde_yaml::to_string(crd).expect("CRD always serializes to YAML")
        );
    }
}
