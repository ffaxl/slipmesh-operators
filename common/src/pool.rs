//! Generic "hand out the first free value from a shared pool, safely under concurrent writers"
//! primitive, shared by mesh (`MeshPool` - /31 subnets) and router (`RouterPool` - loopback
//! addresses). Callers hand this crate a `candidates` iterator in their own domain's order and
//! get back one of those strings, or `None` if every candidate is already taken.
//!
//! CAS via Kubernetes' own optimistic concurrency: `Api::replace_status` sends the whole object
//! back including the `resourceVersion` from the `get()` that produced it - the API server
//! rejects with a conflict error if anything else wrote to the object in between. No separate
//! Lease/lock needed; a conflict surfaces as an `Err` and the caller's `error_policy` retries.

use anyhow::{Context, Result};
use kube::api::{Api, PostParams};
use kube::{Resource, ResourceExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct Allocation {
    pub owner: String,
    pub value: String,
    /// Carried alongside `value` at allocation time, never recomputed later - an already-
    /// allocated owner keeps whatever port it was given even if the pool's own parameters
    /// (e.g. `MeshPoolSpec.basePort`) are edited afterward. `None` for callers with no such
    /// concept (`RouterPool`'s loopback addresses).
    // `format: "int32"`, not schemars' default `"uint16"` for a Rust `u16` - the apiserver's
    // OpenAPI validation doesn't recognize `uint16`/`uint32` (only `int32`/`int64`), so an
    // unoverridden field here would warn on every `kubectl apply`/`helm install` (see the same
    // note on `Obfuscation` in `mesh_types.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "int32"))]
    pub port: Option<u16>,
}

/// Implemented on the top-level CRD type (not its `Status` sub-struct) so this crate can mutate
/// a possibly-`None` status subresource directly.
pub trait PoolStatus {
    fn allocated(&self) -> &[Allocation];
    fn allocated_mut(&mut self) -> &mut Vec<Allocation>;
}

/// One pool object's own name plus whatever `parse` extracted from its `spec`.
pub struct ParsedPool<T> {
    pub name: String,
    pub value: T,
}

/// Lists every `K` in this namespace sorted by name (deterministic allocation order), parsing
/// each via `parse`. A pool that fails to parse (bad CIDR, or a network unaligned to its own
/// prefix - CRD schema can't express that) is logged and skipped rather than failing every
/// reconcile of every consumer over one broken object.
pub async fn valid_pools<K, T>(
    pools_api: &Api<K>,
    mut parse: impl FnMut(&K) -> Result<T>,
) -> Result<Vec<ParsedPool<T>>>
where
    K: Clone + DeserializeOwned + Debug + Resource<DynamicType = ()>,
{
    let mut raw = pools_api
        .list(&Default::default())
        .await
        .context("failed to list pools")?
        .items;
    raw.sort_by_key(ResourceExt::name_any);
    let kind = K::kind(&()).to_string();
    Ok(raw
        .iter()
        .filter_map(|pool| {
            let name = pool.name_any();
            match parse(pool) {
                Ok(value) => Some(ParsedPool { name, value }),
                Err(e) => {
                    tracing::warn!(kind = %kind, pool = %name, error = %e, "invalid pool spec - ignoring this pool");
                    None
                }
            }
        })
        .collect())
}

/// Pure - no I/O, unit-testable without a live API server. First candidate whose value isn't
/// already present as some entry's `value`; reuses gaps left by released entries.
pub fn first_free(
    allocated: &[Allocation],
    mut candidates: impl Iterator<Item = (String, Option<u16>)>,
) -> Option<(String, Option<u16>)> {
    candidates.find(|(value, _)| !allocated.iter().any(|a| &a.value == value))
}

/// Idempotent: if `owner` already has an entry, returns it unchanged without touching
/// `candidates`. Otherwise picks `first_free` and commits via `replace_status`. `Ok(None)` means
/// no free candidate - not an error, the caller tries another pool if one exists.
pub async fn allocate<K>(
    pool_api: &Api<K>,
    pool_name: &str,
    owner: &str,
    candidates: impl Iterator<Item = (String, Option<u16>)>,
) -> Result<Option<(String, Option<u16>)>>
where
    K: Clone + DeserializeOwned + Serialize + Debug + PoolStatus,
{
    let mut pool = pool_api
        .get(pool_name)
        .await
        .with_context(|| format!("failed to read pool {pool_name:?}"))?;

    if let Some(existing) = pool.allocated().iter().find(|a| a.owner == owner) {
        return Ok(Some((existing.value.clone(), existing.port)));
    }

    let Some((value, port)) = first_free(pool.allocated(), candidates) else {
        return Ok(None);
    };

    pool.allocated_mut().push(Allocation {
        owner: owner.to_string(),
        value: value.clone(),
        port,
    });
    pool_api
        .replace_status(pool_name, &PostParams::default(), &pool)
        .await
        .with_context(|| format!("failed to commit allocation in pool {pool_name:?}"))?;
    Ok(Some((value, port)))
}

/// Removes `owner`'s entry if present. Idempotent - no entry is not an error.
pub async fn release<K>(pool_api: &Api<K>, pool_name: &str, owner: &str) -> Result<()>
where
    K: Clone + DeserializeOwned + Serialize + Debug + PoolStatus,
{
    let mut pool = pool_api
        .get(pool_name)
        .await
        .with_context(|| format!("failed to read pool {pool_name:?}"))?;

    let before = pool.allocated().len();
    pool.allocated_mut().retain(|a| a.owner != owner);
    if pool.allocated().len() == before {
        return Ok(());
    }

    pool_api
        .replace_status(pool_name, &PostParams::default(), &pool)
        .await
        .with_context(|| format!("failed to commit release in pool {pool_name:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alloc(owner: &str, value: &str) -> Allocation {
        Allocation {
            owner: owner.to_string(),
            value: value.to_string(),
            port: None,
        }
    }

    fn candidates(values: &[&str]) -> impl Iterator<Item = (String, Option<u16>)> {
        values
            .iter()
            .map(|v| (v.to_string(), None))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn empty_pool_picks_first_candidate() {
        assert_eq!(
            first_free(&[], candidates(&["X0", "X1", "X2"])),
            Some(("X0".to_string(), None))
        );
    }

    #[test]
    fn skips_taken_slots() {
        let allocated = [alloc("a", "X0")];
        assert_eq!(
            first_free(&allocated, candidates(&["X0", "X1", "X2"])),
            Some(("X1".to_string(), None))
        );
    }

    #[test]
    fn reuses_freed_gap() {
        // b (X1) was released - a fresh allocation should reclaim it, not skip past to X3.
        let allocated = [alloc("a", "X0"), alloc("c", "X2")];
        assert_eq!(
            first_free(&allocated, candidates(&["X0", "X1", "X2", "X3"])),
            Some(("X1".to_string(), None))
        );
    }

    #[test]
    fn exhausted_returns_none() {
        let allocated = [alloc("a", "X0"), alloc("b", "X1")];
        assert_eq!(first_free(&allocated, candidates(&["X0", "X1"])), None);
    }

    #[test]
    fn port_rides_along_with_its_candidate() {
        let c = vec![
            ("X0".to_string(), Some(100u16)),
            ("X1".to_string(), Some(101)),
        ];
        assert_eq!(
            first_free(&[], c.into_iter()),
            Some(("X0".to_string(), Some(100)))
        );
    }
}
