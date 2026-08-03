# Packaging only - expects the binary already cross-compiled locally/in CI via:
#   cargo zigbuild --release --target x86_64-unknown-linux-musl -p nftables
# (native cross-compilation via `cargo-zigbuild`/zig cc, not a `cargo build` inside this
# Dockerfile - a full rustc build segfaults under QEMU emulation for a non-native --platform,
# which this workspace's multi-arch release build needs for arm64). Build context is the
# operators/ workspace root. The `apk add` step below still runs under QEMU for a non-native
# --platform, since it executes inside the target-arch base image - lightweight package
# extraction tolerates emulation fine, unlike a full rustc build.
#
# TARGETARCH is buildx's own automatic build arg (`amd64`/`arm64`, populated from --platform) -
# the release build copies each cross-compiled binary to target/<TARGETARCH>/release/ before
# invoking `docker buildx build`, so this Dockerfile never needs a separate, manually-passed
# Rust-triple build-arg kept in sync with --platform by convention alone.
#
# Can't go FROM scratch like mesh/roadwarriors: `nft` is a real external binary this operator
# spawns as a subprocess (rustables was tried and dropped - it can't express the MSS-clamp exthdr
# rule, see nftables.rs), so the runtime stage needs a userland to hold it - kept to just the one
# package, nothing else.
FROM alpine:latest
RUN apk add --no-cache nftables
ARG TARGETARCH
COPY target/${TARGETARCH}/release/nftables /usr/bin/nftables
ENTRYPOINT ["/usr/bin/nftables"]
