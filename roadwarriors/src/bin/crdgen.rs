use kube::CustomResourceExt;

fn main() {
    common::crdgen::print_all(&[common::mesh_types::RoadWarrior::crd()]);
}
