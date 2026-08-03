use kube::CustomResourceExt;

#[path = "../types.rs"]
mod types;

fn main() {
    common::crdgen::print_all(&[types::NatPrivateRange::crd()]);
}
