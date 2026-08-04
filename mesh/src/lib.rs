//! Tiny shared surface between this crate's binaries (`main.rs`, `bin/crdgen.rs`,
//! `bin/rbacgen.rs`) - each compiles as an independent binary target with no access to another's
//! `mod` tree, so anything more than one of them needs to agree on has to live here instead.

/// Name of the Secret `own_private_key` (main.rs) reads/writes via
/// `slipmesh_core::keys::get_or_create_secret_key` - the sole Secret name `mesh-rbacgen` scopes its
/// `get`/`patch` rule to (see `bin/rbacgen.rs`).
pub const MESH_KEYS_SECRET: &str = "mesh-keys";
