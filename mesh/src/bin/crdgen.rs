use kube::CustomResourceExt;

fn main() {
    common::crdgen::print_all(&[
        common::mesh_types::MeshNode::crd(),
        common::mesh_types::MeshLink::crd(),
        common::mesh_types::MeshPool::crd(),
    ]);
}
