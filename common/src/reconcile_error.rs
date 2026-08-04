//! The `reconcile::Error` shape and retry policy every operator's `kube_runtime::Controller`
//! uses. Shared across mesh/router/roadwarriors/nftables so a change to either doesn't need to
//! land as four separate edits.

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

/// Escapes any literal `\n`/`\r` in `s` (visibly, as the two-character sequences `\n`/`\r`) rather
/// than stripping them - an individual error's own `.to_string()` can legally contain embedded
/// newlines (nothing in `std::error::Error`/`Display` forbids it) even though the `": "` join
/// separator between chain layers never introduces one itself. Applied to the whole rendered
/// chain so `error_chain`/`anyhow_chain`'s single-line guarantee holds regardless of what an
/// individual layer's message happens to contain.
fn escape_newlines(s: &str) -> String {
    s.replace('\r', "\\r").replace('\n', "\\n")
}

/// Full causal chain of a `std::error::Error` implementor, as a single line
/// ("outer: middle: root") - for logging through a plain-text, line-oriented pipeline
/// (`kubectl logs`/journald/Loki without multi-line stitching), where a raw `{:?}` (Debug) chain
/// prints one physical line per "Caused by:" layer, which such a pipeline sees as several
/// unrelated, timestamp-less log entries instead of one event. Covers this crate's own `Error`,
/// `kube::Error`, and `kube_runtime`'s `controller::Error`/`watcher::Error`.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(e) = source {
        out.push_str(": ");
        out.push_str(&e.to_string());
        source = e.source();
    }
    escape_newlines(&out)
}

/// Same as `error_chain`, but for `anyhow::Error` specifically. Verified directly (a generic
/// `fn f<E: std::error::Error>()` instantiated with `anyhow::Error` fails to compile) that
/// `anyhow::Error` does not implement `std::error::Error` itself in the version pinned here, so it
/// can't be passed to `error_chain` as a `&dyn std::error::Error` trait object. Anyhow's own
/// alternate-`Display` (`{:#}`) already renders its whole context chain the same single-line way.
pub fn anyhow_chain(err: &anyhow::Error) -> String {
    escape_newlines(&format!("{err:#}"))
}

/// Generic over both the primary resource type `K` and each operator's `Context` type `C` -
/// neither is used beyond logging/dropping, so no trait bounds are needed.
pub fn error_policy<K, C>(_obj: Arc<K>, err: &Error, _ctx: Arc<C>) -> Action {
    tracing::warn!(error = %error_chain(err), "reconcile failed, retrying");
    Action::requeue(Duration::from_secs(15))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("root cause: device busy")]
    struct RootCause;

    #[derive(Debug, thiserror::Error)]
    #[error("failed to remove stale address 10.0.0.1/31 from link 14")]
    struct WithSource(#[source] RootCause);

    #[test]
    fn error_chain_joins_a_std_error_source_chain_on_one_line() {
        let err = WithSource(RootCause);
        let rendered = error_chain(&err);
        assert_eq!(
            rendered,
            "failed to remove stale address 10.0.0.1/31 from link 14: root cause: device busy"
        );
        assert!(
            !rendered.contains('\n'),
            "chain must be a single line, got {rendered:?}"
        );
    }

    #[test]
    fn error_chain_with_no_source_is_just_the_message() {
        let err = RootCause;
        assert_eq!(error_chain(&err), "root cause: device busy");
    }

    #[test]
    fn anyhow_chain_joins_context_layers_on_one_line() {
        let err: anyhow::Error = anyhow::anyhow!("root cause: device busy")
            .context("failed to remove stale address 10.0.0.1/31 from link 14");
        let rendered = anyhow_chain(&err);
        assert_eq!(
            rendered,
            "failed to remove stale address 10.0.0.1/31 from link 14: root cause: device busy"
        );
        assert!(
            !rendered.contains('\n'),
            "chain must be a single line, got {rendered:?}"
        );
    }

    #[derive(Debug, thiserror::Error)]
    #[error("root cause:\nsecond line\r\nthird line")]
    struct MultilineRootCause;

    #[test]
    fn error_chain_escapes_embedded_newlines_in_the_message_itself() {
        // The join separator (": ") never introduces a newline, but a wrapped error's own
        // .to_string() legally can (e.g. a multi-line message from some other library) - that must
        // still come out escaped, not as a literal embedded newline, or a single log event turns
        // into several unrelated lines for any line-oriented collector.
        let rendered = error_chain(&MultilineRootCause);
        assert_eq!(rendered, "root cause:\\nsecond line\\r\\nthird line");
        assert!(
            !rendered.contains(['\n', '\r']),
            "chain must be a single line, got {rendered:?}"
        );
    }

    #[test]
    fn anyhow_chain_escapes_embedded_newlines_in_a_context_message() {
        let err: anyhow::Error =
            anyhow::anyhow!("root cause").context("outer\nmessage with an embedded newline");
        let rendered = anyhow_chain(&err);
        assert!(
            !rendered.contains(['\n', '\r']),
            "chain must be a single line, got {rendered:?}"
        );
    }
}
