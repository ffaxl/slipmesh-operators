//! Captures the working tree's git commit (short SHA, `-dirty` suffixed if uncommitted changes
//! are present) at compile time, exposed to every operator binary as `common::GIT_SHA` - lets
//! `--version` distinguish two builds that share the same `Cargo.toml` version (this workspace
//! doesn't bump it between iterative pushes) and answers "is the digest actually running the
//! commit I think it is" directly from the binary, without trusting registry/pull-policy state.

use std::process::Command;

fn main() {
    // Re-run whenever HEAD, the branch it points at, or the index changes - a plain
    // `cargo:rerun-if-changed=<crate dir>` (cargo's default with no directive at all) would only
    // watch this crate's own files, missing commits made anywhere else in the workspace.
    println!("cargo:rerun-if-changed=../.git");

    let sha = Command::new("git")
        .args(["describe", "--always", "--dirty", "--broken"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_SHA={sha}");
}
