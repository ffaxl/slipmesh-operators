//! Tiny shared surface between this crate's binaries (`main.rs`, `bin/crdgen.rs`,
//! `bin/rbacgen.rs`) - each compiles as an independent binary target with no access to another's
//! `mod` tree, so anything more than one of them needs to agree on has to live here instead.

/// Name of the Secret `shared_private_key` (main.rs) reads/writes via
/// `slipmesh_core::keys::get_or_create_secret_key` - the sole Secret name `roadwarriors-rbacgen`
/// scopes its `get`/`patch` rule to (see `bin/rbacgen.rs`).
pub const ROADWARRIORS_KEY_SECRET: &str = "roadwarriors-key";
