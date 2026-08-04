use kube::CustomResourceExt;

fn main() {
    common::crdgen::print_all(&[
        slipmesh_core::mesh_types::MeshNode::crd(),
        slipmesh_core::mesh_types::MeshLink::crd(),
        slipmesh_core::mesh_types::MeshPool::crd(),
    ]);
}
