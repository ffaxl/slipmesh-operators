# slipmesh operators

**Kubernetes operators for the slipmesh AmneziaWG mesh VPN**, written in Rust. Nodes join a
full-mesh AmneziaWG (obfuscated WireGuard) network, exchange routes over iBGP via
[BIRD](https://bird.network.cz/), and terminate both road-warrior clients and NAT'd egress
traffic — all driven by CRDs under the `slipmesh.net` API group.

---

## Architecture

| Crate | Kind | Purpose |
| --- | --- | --- |
| [`mesh`](mesh) | operator | Establishes and reconciles the AmneziaWG mesh between cluster nodes (`MeshNode`/`MeshLink`) |
| [`router`](router) | operator | Renders BIRD config (OSPF over mesh links, iBGP full mesh) and resolves bypass prefixes |
| [`roadwarriors`](roadwarriors) | operator | Terminates road-warrior AmneziaWG client connections and maintains their kernel routes |
| [`nftables`](nftables) | operator | Reconciles nftables NAT/masquerade rules for configured private ranges |
| [`common`](common) | library | Linux-specific plumbing shared by the four operator binaries: netlink transport (`netlink`), reconcile/RBAC/CRD-gen helpers (`reconcile_error`, `rbacgen`, `crdgen`) |
| [slipmesh-core](https://github.com/slipmesh/core) | library (external) | CRD types, pool allocation, key generation, CIDR math, bypass resolution, and desired-state computation - platform-independent, with no dependency on Linux netlink or `kube_runtime::Controller`. Pulled in as a git dependency; see its own README for details |

Each operator binary also ships a `*-crdgen` companion binary that emits its CRD manifest.

## Building

This is a Cargo workspace; build everything with:

```sh
cargo build --release
```

Each operator crate has a `Dockerfile` that packages an already-built binary - it doesn't run
`cargo build` itself, so cross-compile first (e.g. via `cargo zigbuild`, avoiding a QEMU-emulated
`cargo build`'s segfault on a non-native target):

```sh
cargo zigbuild --release --target x86_64-unknown-linux-musl -p mesh
mkdir -p target/amd64/release
cp target/x86_64-unknown-linux-musl/release/mesh target/amd64/release/
docker build -f mesh/Dockerfile --platform linux/amd64 .
```

`TARGETARCH` (`amd64`/`arm64`) is buildx's own automatic build arg, populated from `--platform` -
the binary must already be staged at `target/<TARGETARCH>/release/<bin>` before the build, matching
what `.github/workflows/release.yml` does for the real multi-arch release.

## Development

- Format: `cargo fmt --all`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo test --workspace`

## CI/CD

- `.github/workflows/ci.yml` - fmt/clippy/test/build on every push and PR.
- `.github/workflows/release.yml` - on a `vX.Y.Z` tag push, cross-compiles each operator for
  amd64+arm64 via `cargo zigbuild` and pushes a multi-arch image to `ghcr.io/<repo>/<operator>`,
  tagged with the version and `latest`.
