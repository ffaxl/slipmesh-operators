pub mod crdgen;
pub mod netlink;
pub mod rbacgen;
pub mod reconcile_error;

/// Short git commit this binary was built from (`-dirty`/`-broken` suffixed if applicable) - see
/// `build.rs`. `"unknown"` if `git` wasn't available/`.git` wasn't present at build time (e.g. a
/// source tarball with no repo history).
pub const GIT_SHA: &str = env!("GIT_SHA");

/// Prints `<bin_name> <version> (<GIT_SHA>)` and exits 0 if `--version`/`-V` is the first CLI
/// argument, before doing anything else - no env vars, no netlink/kube connections, so it works
/// standalone (`kubectl exec <pod> -- /mesh --version`) even against a pod whose normal startup
/// would fail. `version` is the caller's own `env!("CARGO_PKG_VERSION")` (must be read in that
/// crate, not here, to reflect its own Cargo.toml rather than common's).
pub fn maybe_print_version(bin_name: &str, version: &str) {
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "-V")) {
        println!("{bin_name} {version} ({GIT_SHA})");
        std::process::exit(0);
    }
}
