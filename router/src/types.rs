use common::pool::Allocation;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A pool of loopback addresses that `RouterNode`s draw from instead of a human hand-picking a
/// never-reused address. Namespaced, multiple instances are meaningful (like `NatPrivateRange`/
/// `MeshPool`) - e.g. to add a second range once the first fills up.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "RouterPool",
    plural = "routerpools",
    shortname = "rpool",
    namespaced,
    status = "RouterPoolStatus",
    printcolumn = r#"{"name":"Network", "type":"string", "jsonPath":".spec.network"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct RouterPoolSpec {
    /// CIDR of this pool's address range, e.g. `"172.21.0.0/24"`. `format: cidr` validates syntax
    /// only; alignment is checked in Rust (see `common::netlink::rt::parse_network_cidr`).
    #[schemars(extend("format" = "cidr"))]
    pub network: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
pub struct RouterPoolStatus {
    #[serde(default)]
    pub allocated: Vec<Allocation>,
}

impl common::pool::PoolStatus for RouterPool {
    fn allocated(&self) -> &[Allocation] {
        self.status.as_ref().map_or(&[], |s| s.allocated.as_slice())
    }
    fn allocated_mut(&mut self) -> &mut Vec<Allocation> {
        &mut self
            .status
            .get_or_insert_with(RouterPoolStatus::default)
            .allocated
    }
}

/// Router identity for one node: its OSPF/BGP loopback address (`router-lo` dummy interface).
/// `metadata.name` must equal the Kubernetes Node name, same convention as MeshNode. The loopback
/// address is drawn from a `RouterPool` (`status.loopback`); `spec.loopback` is an escape hatch
/// to pin an existing address.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "RouterNode",
    plural = "routernodes",
    shortname = "rnode",
    namespaced,
    status = "RouterNodeStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct RouterNodeSpec {
    /// Escape hatch: pin this node to a specific loopback address instead of drawing one from a
    /// `RouterPool`. Must fall inside some `RouterPool`'s configured range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loopback: Option<std::net::Ipv4Addr>,
    /// Short, router-facing identity used to build the `ibgp_<router_label>` BIRD protocol name
    /// on every peer, independent of the Kubernetes Node name. Must be unique across all
    /// RouterNodes (checked at reconcile time).
    #[schemars(length(min = 1, max = 10))]
    #[schemars(regex(pattern = r"^[a-zA-Z0-9_-]+$"))]
    pub router_label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouterNodeStatus {
    #[serde(default)]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
    /// Which `RouterPool` `loopback` was drawn from - `None` if `spec.loopback` was pinned
    /// outside every configured pool's range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loopback: Option<std::net::Ipv4Addr>,
}

/// Cluster-wide router settings shared identically by every node - unlike `RouterNode` (per-node
/// identity) or `RouterPool` (multiple instances meaningful, e.g. to add capacity), exactly one
/// `RouterConfig` object is expected per namespace. No status/reconcile loop: `router` reads this
/// once at startup (see `main.rs`), the same one-shot-list pattern already used for the cluster's
/// `ServiceCIDR`/this node's own `podCIDR`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "RouterConfig",
    plural = "routerconfigs",
    shortname = "rcfg",
    namespaced,
    printcolumn = r#"{"name":"BgpAs", "type":"integer", "jsonPath":".spec.bgpAs"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct RouterConfigSpec {
    /// AS number shared by the full iBGP mesh - every node's rendered BIRD config uses this same
    /// value for its local `protocol bgp ibgp_<label> { local as <bgp_as>; ... }` block. Was
    /// previously the `ROUTER_BGP_AS` env var (default 64512, a private-use AS) - moved to this
    /// CRD so changing it doesn't require rebuilding/re-templating every node's Deployment spec.
    #[schemars(extend("format" = "int64"))]
    #[schemars(range(max = 4_294_967_295u32))]
    pub bgp_as: u32,
}

/// One bypass-prefix source, resolved into concrete CIDRs by `resolver.rs`: `asn` via
/// `whois -h whois.radb.net -i origin ASxxxx`, `literal` verbatim, `geoip` via RIPEstat's
/// country-resource-list.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BypassSourceEntry {
    /// "asn" | "literal" | "geoip" | "dns" - validated in resolver.rs, not by the schema (avoids
    /// CRD schema complexity of a tagged enum for a four-way, mostly-optional-fields shape).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<Vec<LabeledPrefix>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// "dns" only - resolved via a live A-record lookup at resolve time, on the same
    /// startup/hourly/on-change schedule as everything else. Whole list shares `label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabeledPrefix {
    #[schemars(extend("format" = "cidr"))]
    pub net: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A router-node's bypass-exit prefix set, computed from `include` minus `exclude` - both the
/// same four-kind shape (asn/literal/geoip/dns), resolved the same way, so an exclusion can
/// itself be "everything RIPE assigned to country X" or "everything ASN Y announces", not just
/// literal blocks. Every MeshNode's endpoint is always punched out on top of `exclude`,
/// regardless of what it resolves to - self/cluster addresses must never be blackholed.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "BypassSource",
    plural = "bypasssources",
    shortname = "bsrc",
    namespaced,
    status = "BypassSourceStatus",
    printcolumn = r#"{"name":"Node", "type":"string", "jsonPath":".spec.node"}"#,
    printcolumn = r#"{"name":"Prefixes", "type":"integer", "jsonPath":".status.prefixCount"}"#,
    printcolumn = r#"{"name":"LastResolved", "type":"string", "jsonPath":".status.lastResolvedTime"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct BypassSourceSpec {
    /// RouterNode (= Kubernetes Node name) this bypass belongs to.
    pub node: String,
    pub include: Vec<BypassSourceEntry>,
    #[serde(default)]
    pub exclude: Vec<BypassSourceEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BypassSourceStatus {
    #[serde(default)]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
    // Same reasoning as common::mesh_types::Obfuscation's h1-h4: a real u32 (max 4294967295)
    // overflows int32 (max 2147483647), so this needs int64 (the OpenAPI-standard format that
    // actually covers every u32 value) plus an explicit max - schemars doesn't auto-derive one
    // for u32 the way it does for u16.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int64"))]
    #[schemars(range(max = 4_294_967_295u32))]
    pub prefix_count: Option<u32>,
    /// Only updated on a *successful* resolve - a failed attempt leaves this (and
    /// `observedGeneration`) untouched, so the next trigger retries without waiting out a full
    /// extra refresh interval. RFC3339 (`jiff::Timestamp::to_string`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub last_resolved_time: Option<String>,
    /// Spec generation as of the last *successful* resolve - lags behind `metadata.generation`
    /// after a spec edit until the next successful re-resolve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

#[cfg(test)]
mod bypass_source_status_schema_tests {
    use super::*;

    #[test]
    fn prefix_count_gets_int64_with_an_explicit_real_max() {
        // Same reasoning as common::mesh_types::Obfuscation's h1-h4 (see that test module): a
        // real u32 doesn't fit in int32, and schemars doesn't auto-derive a `maximum` for u32.
        let schema = schemars::schema_for!(BypassSourceStatus);
        let value = serde_json::to_value(&schema).unwrap();
        let prefix_count = &value["properties"]["prefixCount"];
        assert_eq!(prefix_count["format"], "int64");
        assert_eq!(prefix_count["maximum"], 4_294_967_295u32);
    }
}
