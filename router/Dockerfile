# Packaging only - expects the binary already cross-compiled locally/in CI via:
#   cargo zigbuild --release --target x86_64-unknown-linux-musl -p router
# (native cross-compilation via `cargo-zigbuild`/zig cc, not a `cargo build` inside this
# Dockerfile - a full rustc build segfaults under QEMU emulation for a non-native --platform,
# which this workspace's multi-arch release build needs for arm64). Build context is the
# operators/ workspace root. The `apk add`/`awg` build steps below still run under QEMU for a
# non-native --platform, since they execute inside the target-arch base image - lightweight
# package extraction and a small C build both tolerate emulation fine, unlike a full rustc build.
#
# TARGETARCH is buildx's own automatic build arg (`amd64`/`arm64`, populated from --platform) -
# the release build copies each cross-compiled binary to target/<TARGETARCH>/release/ before
# invoking `docker buildx build`, so this Dockerfile never needs a separate, manually-passed
# Rust-triple build-arg kept in sync with --platform by convention alone.
#
# Can't go FROM scratch like mesh/roadwarriors: `bird`/`birdc` (the actual OSPF/BGP routing
# daemon - reimplementing that is out of scope) is a real external binary this operator spawns as
# a subprocess, so the runtime stage needs a real userland to hold it.
FROM alpine:latest
RUN apk add --no-cache bird2 ca-certificates

# Diagnostics only, not used by router itself (it talks netlink directly - see common/netlink):
# `awg show` from inside the pod for inspecting mesh/roadwarriors interfaces, which are visible
# here too since every operator shares the host netns. Drop this stage once ops tooling moves
# elsewhere.
ARG AMNEZIAWG_TOOLS_REF=v3.0.20260730
RUN apk add --no-cache --virtual .awg-build git make gcc musl-dev linux-headers \
    && git clone --branch "$AMNEZIAWG_TOOLS_REF" --depth 1 \
        https://github.com/amnezia-vpn/amneziawg-tools /amneziawg-tools \
    && make -C /amneziawg-tools/src \
    && cp /amneziawg-tools/src/wg /usr/bin/awg \
    && apk del .awg-build \
    && rm -rf /amneziawg-tools

ARG TARGETARCH
COPY target/${TARGETARCH}/release/router /usr/bin/router
ENTRYPOINT ["/usr/bin/router"]
