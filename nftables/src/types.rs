use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A named group of CIDRs to masquerade on egress (e.g. the RFC1918 ranges) - `metadata.name` is
/// the group's label, not tied to any node. nftables reads every instance and unions their
/// `cidrs` into one ruleset, applied identically by every DaemonSet pod (each detects its own
/// node's default interface at apply time; TCP MSS clamping on forward is unconditional, not
/// CRD-configurable). Namespaced purely for RBAC hygiene.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "NatPrivateRange",
    plural = "natprivateranges",
    shortname = "npr",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct NatPrivateRangeSpec {
    #[schemars(extend("items" = {"type": "string", "format": "cidr"}))]
    pub cidrs: Vec<String>,
}
