//! Tiny shared surface between this crate's binaries (`main.rs`, `bin/crdgen.rs`,
//! `bin/rbacgen.rs`) - each compiles as an independent binary target with no access to another's
//! `mod` tree, so anything more than one of them needs to agree on has to live here instead.

use common::mesh_types::Obfuscation;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Name of the Secret `shared_private_key` (main.rs) reads/writes via
/// `common::keys::get_or_create_secret_key` - the sole Secret name `roadwarriors-rbacgen` scopes
/// its `get`/`patch` rule to (see `bin/rbacgen.rs`).
pub const ROADWARRIORS_KEY_SECRET: &str = "roadwarriors-key";

/// Cluster-wide roadwarriors device settings - a single instance expected per namespace, same
/// convention as router's `RouterConfig`. No status/reconcile loop: roadwarriors reads this once
/// at startup (see `main.rs`).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "slipmesh.net",
    version = "v1alpha1",
    kind = "RoadWarriorConfig",
    plural = "roadwarriorconfigs",
    shortname = "rwcfg",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct RoadWarriorConfigSpec {
    /// Device-level AmneziaWG obfuscation for the whole roadwarriors interface - was previously 9
    /// separate `ROADWARRIORS_OBFUSCATION_*` env vars, hand-parsed one by one.
    /// `common::mesh_types::Obfuscation` is already CRD-embeddable (`MeshLinkSpec.obfuscation`
    /// uses it the same way) - this reuses it instead of reimplementing the same config surface
    /// as raw env parsing.
    #[serde(default)]
    pub obfuscation: Obfuscation,
}

/// Extracts the single cluster-wide `Obfuscation` config from every `RoadWarriorConfig` object in
/// the namespace. Zero objects is a valid, meaningful state - `Obfuscation::default()` (empty),
/// keeping the interface wire-compatible with ordinary WireGuard clients, matches the prior
/// behavior of every `ROADWARRIORS_OBFUSCATION_*` env var being unset - unlike `RouterConfig`'s
/// `bgp_as` (which has no sensible "unset" value), so this doesn't fail loudly on zero the way
/// `router`'s equivalent does. More than one object is still ambiguous and an error.
pub fn obfuscation_from_configs(configs: &[RoadWarriorConfig]) -> anyhow::Result<Obfuscation> {
    match configs {
        [] => Ok(Obfuscation::default()),
        [only] => Ok(only.spec.obfuscation.clone()),
        _ => anyhow::bail!(
            "expected at most one RoadWarriorConfig object, found {} - ambiguous, don't know \
             which one's obfuscation the interface should use",
            configs.len()
        ),
    }
}

#[cfg(test)]
mod obfuscation_from_configs_tests {
    use super::*;

    fn config(obfuscation: Obfuscation) -> RoadWarriorConfig {
        RoadWarriorConfig::new("cluster", RoadWarriorConfigSpec { obfuscation })
    }

    #[test]
    fn no_configs_returns_the_default_empty_obfuscation() {
        let result = obfuscation_from_configs(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn exactly_one_config_returns_its_obfuscation() {
        let obfuscation = Obfuscation {
            jc: Some(5),
            ..Default::default()
        };
        let result = obfuscation_from_configs(&[config(obfuscation.clone())]).unwrap();
        assert_eq!(result.jc, obfuscation.jc);
        assert!(!result.is_empty());
    }

    #[test]
    fn more_than_one_config_is_ambiguous_and_an_error() {
        let a = config(Obfuscation::default());
        let b = config(Obfuscation::default());
        assert!(obfuscation_from_configs(&[a, b]).is_err());
    }
}
