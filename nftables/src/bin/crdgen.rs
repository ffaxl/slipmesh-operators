use kube::CustomResourceExt;

fn main() {
    common::crdgen::print_all(&[slipmesh_core::nftables_types::NatPrivateRange::crd()]);
}
