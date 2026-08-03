use kube::CustomResourceExt;

#[path = "../types.rs"]
mod types;

fn main() {
    // Only the CRDs this operator owns (RouterNode, BypassSource, RouterPool) - MeshLink/MeshNode
    // here are read-only mirrors of mesh's CRDs, which already own and apply those definitions;
    // applying them again from here would be redundant (and risks drifting if the two ever
    // disagree on schema).
    common::crdgen::print_all(&[
        types::RouterNode::crd(),
        types::BypassSource::crd(),
        types::RouterPool::crd(),
    ]);
}
