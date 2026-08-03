//! The `reconcile::Error` shape and retry policy every operator's `kube_runtime::Controller`
//! uses. Shared across mesh/router/roadwarriors/nftables so a change to either doesn't need to
//! land as four separate edits.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::runtime::controller::Action;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Generic over both the primary resource type `K` and each operator's `Context` type `C` -
/// neither is used beyond logging/dropping, so no trait bounds are needed.
pub fn error_policy<K, C>(_obj: Arc<K>, err: &Error, _ctx: Arc<C>) -> Action {
    tracing::warn!(error = %err, "reconcile failed, retrying");
    Action::requeue(Duration::from_secs(15))
}

/// Builds a single `Condition` - shared by every `set_*_condition`/`set_*_status` helper across
/// mesh/router/roadwarriors. `existing` is the object's current `status.conditions` (empty slice
/// if there is none yet).
///
/// `last_transition_time` is only stamped to now when `status` actually differs from whatever
/// condition of this same `type_` is already stored (or none is stored yet) - matching upstream
/// Kubernetes convention, where a "transition" means a `status` flip, not any reason/message
/// change. Reusing the old timestamp otherwise means a reconcile that keeps producing the exact
/// same type/status/reason/message/observedGeneration writes a byte-identical `Condition`, which
/// the apiserver's status-subresource update treats as a no-op (no `resourceVersion` bump, no
/// watch event) - without this, any condition set on every reconcile pass (e.g. a steady
/// `Ready=True`, or a persisting failure reason) would re-trigger the very watch driving that
/// reconcile and spin forever.
pub fn condition(
    existing: &[Condition],
    type_: &str,
    status: &str,
    reason: &str,
    message: &str,
    observed_generation: Option<i64>,
) -> Condition {
    let last_transition_time = existing
        .iter()
        .find(|c| c.type_ == type_)
        .filter(|c| c.status == status)
        .map_or_else(
            || Time(k8s_openapi::jiff::Timestamp::now()),
            |c| c.last_transition_time.clone(),
        );
    Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
        last_transition_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_existing_condition_stamps_a_fresh_timestamp() {
        let before = k8s_openapi::jiff::Timestamp::now();
        let cond = condition(&[], "Ready", "True", "Configured", "ok", Some(1));
        assert!(cond.last_transition_time.0 >= before);
    }

    #[test]
    fn repeating_the_same_status_preserves_last_transition_time() {
        let first = condition(&[], "Ready", "True", "Configured", "ok", Some(1));
        // Same type/status on the second call - must reuse `first`'s timestamp verbatim, not
        // stamp a new one, so a reconcile that keeps producing this exact Condition writes a
        // byte-identical patch (see the function doc comment on why that matters).
        let second = condition(
            std::slice::from_ref(&first),
            "Ready",
            "True",
            "Configured",
            "ok",
            Some(1),
        );
        assert_eq!(first.last_transition_time, second.last_transition_time);
        assert_eq!(first, second);
    }

    #[test]
    fn status_flip_stamps_a_new_transition_time() {
        let first = condition(&[], "Ready", "False", "PeerNodeMissing", "waiting", Some(1));
        // A real transition (False -> True) must get a fresh timestamp, even though it's the
        // same condition `type_`.
        let second = condition(
            std::slice::from_ref(&first),
            "Ready",
            "True",
            "Configured",
            "ok",
            Some(1),
        );
        assert_ne!(first.last_transition_time, second.last_transition_time);
    }

    #[test]
    fn reason_change_at_the_same_status_preserves_last_transition_time() {
        // reason/message alone changing isn't a "transition" per upstream Kubernetes convention -
        // only a `status` flip is. The timestamp must still be reused here even though the
        // Condition as a whole differs (so the patch is NOT a no-op: this legitimately needs to
        // reach the apiserver once, but shouldn't look like a fresh transition when it does).
        let first = condition(&[], "Ready", "False", "PinOutOfRange", "msg a", Some(1));
        let second = condition(
            std::slice::from_ref(&first),
            "Ready",
            "False",
            "PoolExhausted",
            "msg b",
            Some(1),
        );
        assert_eq!(first.last_transition_time, second.last_transition_time);
        assert_ne!(first.reason, second.reason);
    }

    #[test]
    fn unrelated_condition_type_is_ignored() {
        let other = condition(&[], "Resolved", "True", "Ok", "ok", Some(1));
        let first_ready = condition(
            std::slice::from_ref(&other),
            "Ready",
            "True",
            "Configured",
            "ok",
            Some(1),
        );
        // No prior "Ready" condition existed - must stamp fresh, not reuse "Resolved"'s time.
        assert_ne!(other.last_transition_time, first_ready.last_transition_time);
    }
}
