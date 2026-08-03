# Packaging only - expects the binary already cross-compiled locally/in CI via:
#   cargo zigbuild --release --target x86_64-unknown-linux-musl -p roadwarriors
# (native cross-compilation via `cargo-zigbuild`/zig cc, not a `cargo build` inside this
# Dockerfile - a full rustc build segfaults under QEMU emulation for a non-native --platform,
# which this workspace's multi-arch release build needs for arm64). Build context is the
# operators/ workspace root. No RUN steps at all, so this stage needs no emulation either way -
# everything goes through rtnetlink/genetlink in-process instead of shelling out to `ip`/`awg`,
# so nothing besides the kernel and CAP_NET_ADMIN is required at runtime, hence FROM scratch.
#
# TARGETARCH is buildx's own automatic build arg (`amd64`/`arm64`, populated from --platform) -
# the release build copies each cross-compiled binary to target/<TARGETARCH>/release/ before
# invoking `docker buildx build`, so this Dockerfile never needs a separate, manually-passed
# Rust-triple build-arg kept in sync with --platform by convention alone.
FROM scratch
ARG TARGETARCH
COPY target/${TARGETARCH}/release/roadwarriors /roadwarriors
ENTRYPOINT ["/roadwarriors"]
