use kube::CustomResourceExt;

fn main() {
    // Only the CRDs this operator owns (RouterNode, BypassSource, RouterPool, RouterConfig) -
    // MeshLink/MeshNode here are read-only mirrors of mesh's CRDs, which already own and apply
    // those definitions; applying them again from here would be redundant (and risks drifting if
    // the two ever disagree on schema).
    common::crdgen::print_all(&[
        slipmesh_core::router_types::RouterNode::crd(),
        slipmesh_core::router_types::BypassSource::crd(),
        slipmesh_core::router_types::RouterPool::crd(),
        slipmesh_core::router_types::RouterConfig::crd(),
    ]);
}
