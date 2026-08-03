//! CRD schema types shared across operators - each owned (created/written/finalized) by exactly
//! one operator, with every other operator that needs them treating them as read-only. `MeshNode`/
//! `MeshLink`/`MeshPool` belong to mesh, read by router; `RoadWarrior` belongs to roadwarriors,
//! read by router (BIRD's `learn` import filter - see `router::bird`).

use crate::pool::Allocation;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Identity of one mesh participant. `metadata.name` must equal the Kubernetes Node it runs on
/// (which may be an FQDN), but the OS-level `mesh-<label>` interface name has to fit `IFNAMSIZ`
/// (15 usable bytes; `"mesh-"` alone takes 5) - so `mesh_label` is its own short, explicit field.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "MeshNode",
    plural = "meshnodes",
    shortname = "mnode",
    namespaced,
    status = "MeshNodeStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct MeshNodeSpec {
    /// Explicit reachable endpoint (IP or hostname, no port - each link supplies its own port).
    /// Omit for a node with no inbound reachability (NAT): peers render it without
    /// Endpoint/PersistentKeepalive and wait for it to initiate. Two endpoint-less nodes can
    /// never link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Short, mesh-facing identity used to build the `mesh-<mesh_label>` interface name on every
    /// peer, independent of the Kubernetes Node name. Must be unique across all MeshNodes
    /// (checked at reconcile time; CRD schema can't express cross-object uniqueness). Length
    /// capped at admission time.
    #[schemars(length(min = 1, max = 10))]
    #[schemars(regex(pattern = r"^[a-zA-Z0-9_-]+$"))]
    pub mesh_label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeshNodeStatus {
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Base64 AmneziaWG public key, deterministically derived from the node's own private key
    /// (X25519: `public = private * basepoint`). Computed by mesh itself, not declared in spec.
    /// `None` until the owning mesh has computed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

// schemars otherwise emits `format: "uint16"`/`"uint32"` verbatim from the Rust type name, but
// the Kubernetes apiserver's OpenAPI validation only recognizes `int32`/`int64` (plus a handful
// of k8s-specific formats like `cidr`, already used elsewhere in this file) for `type: integer` -
// an unrecognized format isn't a hard error, just a `Warning:` on every `kubectl apply`/
// `helm install` against this CRD, from day one of a fresh cluster.
//
// `u16` fields (jc/jmin/jmax/s1/s2) use `format: int32`: int32's range comfortably covers every
// u16 value, and schemars already derives the correct `maximum: 65535` on its own from the Rust
// type, no extra annotation needed.
//
// `u32` fields (h1-h4) use `format: int64`, not `int32`: a real u32 (max 4294967295) doesn't fit
// in int32 (max 2147483647) - a real deployed h1 value (2888360298) already exceeds it. int64 is
// the OpenAPI-standard format that actually covers every valid u32 value. Also, unlike u16,
// schemars does *not* auto-derive a `maximum` for u32 - so these get an explicit
// `#[schemars(range(max = ...))]` too, or the schema would otherwise be silently unbounded above.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
pub struct Obfuscation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub jc: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub jmin: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub jmax: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub s1: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub s2: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int64"))]
    #[schemars(range(max = 4_294_967_295u32))]
    pub h1: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int64"))]
    #[schemars(range(max = 4_294_967_295u32))]
    pub h2: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int64"))]
    #[schemars(range(max = 4_294_967_295u32))]
    pub h3: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int64"))]
    #[schemars(range(max = 4_294_967_295u32))]
    pub h4: Option<u32>,
}

impl Obfuscation {
    pub fn is_empty(&self) -> bool {
        self.jc.is_none()
            && self.jmin.is_none()
            && self.jmax.is_none()
            && self.s1.is_none()
            && self.s2.is_none()
            && self.h1.is_none()
            && self.h2.is_none()
            && self.h3.is_none()
            && self.h4.is_none()
    }
}

#[cfg(test)]
mod obfuscation_schema_tests {
    use super::*;

    fn field_schema(field: &str) -> serde_json::Value {
        let schema = schemars::schema_for!(Obfuscation);
        let value = serde_json::to_value(&schema).unwrap();
        value["properties"][field].clone()
    }

    #[test]
    fn u16_fields_get_int32_with_their_real_max_already_derived() {
        // No explicit #[schemars(range(...))] needed here - schemars already derives u16's own
        // bounds (0..=65535) automatically, which fits comfortably inside int32's range.
        for field in ["jc", "jmin", "jmax", "s1", "s2"] {
            let schema = field_schema(field);
            assert_eq!(schema["format"], "int32", "{field} format");
            assert_eq!(schema["maximum"], 65535, "{field} maximum");
        }
    }

    #[test]
    fn u32_fields_get_int64_with_an_explicit_real_max() {
        // format: int32 (max ~2.1 billion) understates a real u32's range (max ~4.3 billion) -
        // a real deployed h1 value (2888360298) already exceeds int32's max. int64 is the
        // OpenAPI-standard format that actually covers every valid u32 value. schemars doesn't
        // auto-derive a `maximum` for u32 the way it does for u16 (see the sibling test), so it
        // needs an explicit #[schemars(range(max = ...))] to avoid being silently unbounded.
        for field in ["h1", "h2", "h3", "h4"] {
            let schema = field_schema(field);
            assert_eq!(schema["format"], "int64", "{field} format");
            assert_eq!(schema["maximum"], 4_294_967_295u32, "{field} maximum");
        }
    }
}

/// A pool of `/31` subnets (and, from each one's position, a port) that `MeshLink`s draw from.
/// Namespaced; multiple instances are meaningful, e.g. to add a second range once the first
/// fills up without touching already-allocated links.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "MeshPool",
    plural = "meshpools",
    shortname = "mpool",
    namespaced,
    status = "MeshPoolStatus",
    printcolumn = r#"{"name":"Network", "type":"string", "jsonPath":".spec.network"}"#,
    printcolumn = r#"{"name":"BasePort", "type":"integer", "jsonPath":".spec.basePort"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MeshPoolSpec {
    /// CIDR of this pool's address range, e.g. `"172.20.255.0/24"`. `format: cidr` validates
    /// syntax only - it doesn't check that `network` is the aligned base address of its own
    /// range, so that's checked in Rust (see `common::netlink::rt::parse_network_cidr`); an
    /// invalid pool is skipped with a warning, not a hard error.
    #[schemars(extend("format" = "cidr"))]
    pub network: String,
    /// Port for the `/31` at `network` itself; each subsequent `/31` gets the next port (see
    /// `mesh_math::addressing_for`).
    #[schemars(extend("format" = "int32"))]
    pub base_port: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
pub struct MeshPoolStatus {
    #[serde(default)]
    pub allocated: Vec<Allocation>,
}

impl crate::pool::PoolStatus for MeshPool {
    fn allocated(&self) -> &[Allocation] {
        self.status.as_ref().map_or(&[], |s| s.allocated.as_slice())
    }
    fn allocated_mut(&mut self) -> &mut Vec<Allocation> {
        &mut self
            .status
            .get_or_insert_with(MeshPoolStatus::default)
            .allocated
    }
}

/// A single mesh tunnel between two `MeshNode`s. Its `/31` and port are drawn from a `MeshPool`
/// (`status.network`/`status.port`); `spec.network` is an escape hatch to pin an existing subnet.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "MeshLink",
    plural = "meshlinks",
    shortname = "mlink",
    namespaced,
    status = "MeshLinkStatus",
    printcolumn = r#"{"name":"NodeA", "type":"string", "jsonPath":".spec.nodeA"}"#,
    printcolumn = r#"{"name":"NodeB", "type":"string", "jsonPath":".spec.nodeB"}"#,
    printcolumn = r#"{"name":"Network", "type":"string", "jsonPath":".status.network"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MeshLinkSpec {
    /// MeshNode name of one end. `node_a` always takes the lower `/31` address and drives pool
    /// allocation (see `is_lower`) - field order now matters, unlike an unordered pair. This
    /// matters specifically for pinning an external, never-Kubernetes `MeshNode` (e.g. an office
    /// router) as `node_b`: no pod will ever run under its name, so it must never be elected to
    /// drive allocation the way an alphabetical tie-break could pick it by accident.
    pub node_a: String,
    pub node_b: String,
    #[serde(default, skip_serializing_if = "Obfuscation::is_empty")]
    pub obfuscation: Obfuscation,
    /// Escape hatch: pin this link to a specific `/31` (e.g. `"10.200.100.0/31"`) instead of
    /// drawing one from a `MeshPool`. Must fall inside some `MeshPool`'s range - the port is
    /// still derived from its position there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "cidr"))]
    pub network: Option<String>,
}

impl MeshLinkSpec {
    /// The far end of this link as seen from `my_node` - `None` if `my_node` is neither side.
    pub fn peer_label(&self, my_node: &str) -> Option<&str> {
        if self.node_a == my_node {
            Some(&self.node_b)
        } else if self.node_b == my_node {
            Some(&self.node_a)
        } else {
            None
        }
    }

    /// Whether `my_node` is `node_a` - the side responsible for driving `/31`+port allocation
    /// against `MeshPool`. `node_a` is authoritative by manifest position, not by name: this
    /// used to be a lexicographic tie-break, which could silently elect a node that will never
    /// run this operator's code (see `node_a`'s field doc).
    pub fn is_lower(&self, my_node: &str) -> bool {
        self.node_a == my_node
    }
}

#[cfg(test)]
mod meshlink_spec_tests {
    use super::*;

    fn link(node_a: &str, node_b: &str) -> MeshLinkSpec {
        MeshLinkSpec {
            node_a: node_a.to_string(),
            node_b: node_b.to_string(),
            obfuscation: Obfuscation::default(),
            network: None,
        }
    }

    #[test]
    fn node_a_is_lower_even_when_alphabetically_last() {
        // Deliberately non-alphabetical: "aaa" < "zzz", so a lexicographic implementation would
        // pick "aaa" (node_b) as lower. node_a must win regardless - this is the whole point of
        // the authoritative-node_a contract (e.g. pinning an external, never-Kubernetes device
        // like "hq" as node_b so it's never the side an allocation silently waits on forever).
        let l = link("zzz", "aaa");
        assert!(l.is_lower("zzz"));
        assert!(!l.is_lower("aaa"));
    }

    #[test]
    fn node_a_is_lower_when_also_alphabetically_first() {
        // Same outcome as the alphabetical rule would give - must still hold, since node_a here
        // coincides with being alphabetically first too.
        let l = link("fra", "lon");
        assert!(l.is_lower("fra"));
        assert!(!l.is_lower("lon"));
    }

    #[test]
    fn is_lower_false_for_an_uninvolved_node() {
        let l = link("fra", "lon");
        assert!(!l.is_lower("msk"));
    }

    #[test]
    fn peer_label_is_unaffected_by_node_a_node_b_order() {
        // peer_label is identity-based, not order-based - confirms this test suite isn't
        // conflating the two, and that peer_label needs no change for this contract.
        let l = link("zzz", "aaa");
        assert_eq!(l.peer_label("zzz"), Some("aaa"));
        assert_eq!(l.peer_label("aaa"), Some("zzz"));
        assert_eq!(l.peer_label("msk"), None);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
pub struct MeshLinkStatus {
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Which `MeshPool` `network`/`port` were drawn from - `None` if `spec.network` was pinned
    /// outside every configured pool's range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "cidr"))]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub port: Option<u16>,
}

impl MeshLinkStatus {
    pub fn is_ready(&self) -> bool {
        self.conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
    }
}

/// One road-warrior client peer. Only `public_key` and `allowed_ips` live here - the client's
/// own private key never touches the server side (standard WireGuard asymmetry). `metadata.name`
/// is a human label, not tied to any node - a client can roam and connect to whichever
/// roadwarriors instance is reachable.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "RoadWarrior",
    plural = "roadwarriors",
    shortname = "rw",
    namespaced,
    status = "RoadWarriorStatus",
    printcolumn = r#"{"name":"AllowedIPs", "type":"string", "jsonPath":".spec.allowedIps"}"#,
    printcolumn = r#"{"name":"ConnectedNode", "type":"string", "jsonPath":".status.connectedNode"}"#,
    printcolumn = r#"{"name":"LastHandshake", "type":"string", "jsonPath":".status.lastHandshakeTime"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct RoadWarriorSpec {
    pub public_key: String,
    /// CIDR entries, e.g. "10.99.0.5/32" - a list (not a delimited string) matching AmneziaWG's
    /// own netlink AllowedIps attribute shape, with per-entry `format: cidr` validation. First
    /// entry becomes the client's own tunnel address when rendering a client config.
    #[schemars(extend("items" = {"type": "string", "format": "cidr"}))]
    pub allowed_ips: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoadWarriorStatus {
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Which node this client currently has a fresh (non-stale) handshake with - status only,
    /// not authoritative for routing (kernel routes + BIRD `learn` + iBGP handle that).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_node: Option<String>,
    /// RFC3339, formatted via `jiff::Timestamp` (see `handshake.rs`'s `one_pass`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub last_handshake_time: Option<String>,
}
