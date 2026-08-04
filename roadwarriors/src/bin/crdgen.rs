use kube::CustomResourceExt;

fn main() {
    common::crdgen::print_all(&[
        slipmesh_core::mesh_types::RoadWarrior::crd(),
        slipmesh_core::roadwarrior_types::RoadWarriorConfig::crd(),
    ]);
}
