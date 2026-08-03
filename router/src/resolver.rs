//! Resolution pipeline: resolve each source (asn -> RIPEstat, literal -> verbatim, geoip ->
//! RIPEstat, dns -> A record) into (net, label) pairs, dedupe/collapse per label, then punch out
//! every excluded network (resolved the same way) plus every node's own address.

use crate::netutil::{self, Cidr};
use crate::types::BypassSourceEntry;
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Per-call ceiling for one RIPEstat request or one DNS lookup. `reqwest`'s default is *no*
/// request timeout at all unless configured, hence `RIPESTAT_CLIENT` below.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);

/// Ceiling on one whole `resolve()` call, not just its individual requests. `NETWORK_TIMEOUT`
/// alone bounds each call but not their *sum*: `"dns"` hostnames are looked up sequentially, and
/// RIPEstat requests are throttled to `RIPESTAT_CONCURRENCY` at a time, so a large BypassSource
/// against a slow-but-not-timing-out upstream can add up to minutes - all of it with
/// `render_lock` held, freezing this node's unrelated OSPF/iBGP convergence. Generous relative to
/// a healthy resolve (seconds), since blowing this budget means serving the last-known-good
/// cache until the next refresh.
pub const RESOLVE_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

/// One shared client for every RIPEstat call - connection/TLS reuse across the lookups a single
/// resolve makes, instead of a fresh connection pool and TLS handshake per request. Also where
/// the per-request timeout is configured.
static RIPESTAT_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(NETWORK_TIMEOUT)
        .user_agent("slipmesh-router")
        .build()
        .expect("reqwest client with only a timeout/user-agent set always builds")
});

fn parse_cidr(s: &str) -> Option<Cidr> {
    let (addr, len) = common::netlink::rt::parse_cidr(s).ok()?;
    Some((u32::from(addr), len))
}

fn format_cidr((addr, len): Cidr) -> String {
    format!("{}/{len}", Ipv4Addr::from(addr))
}

/// RIPEstat's documented limit is 8 concurrent requests per IP
/// (https://stat.ripe.net/docs/02.data-api/); kept comfortably under that cap. Shared across
/// every RIPEstat call this process makes.
static RIPESTAT_CONCURRENCY: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(5));

/// RIPEstat's suggested self-identification query param. Required format: alphanumeric plus
/// hyphens/underscores only, no whitespace.
const RIPESTAT_SOURCEAPP: &str = "slipmesh-router";

async fn ripestat_get(url: &str) -> Result<serde_json::Value> {
    let _permit = RIPESTAT_CONCURRENCY
        .acquire()
        .await
        .expect("RIPESTAT_CONCURRENCY semaphore is never closed");
    // `url` always already has a `?resource=...` query string, so appending with `&` is correct
    // here - not a general-purpose query-string builder.
    RIPESTAT_CLIENT
        .get(format!("{url}&sourceapp={RIPESTAT_SOURCEAPP}"))
        .send()
        .await
        .with_context(|| format!("RIPEstat request to {url} failed"))?
        .error_for_status()
        .context("RIPEstat returned an error status")?
        .json()
        .await
        .context("failed to parse RIPEstat response as JSON")
}

/// Validates RIPEstat's expected ASN format (`AS` followed by digits, e.g. `"AS15169"`) before
/// it's spliced into a request URL - a malformed value here isn't just a confusing upstream
/// error, it's unvalidated CRD input reaching a query string (e.g. `"AS123&foo=bar"` would inject
/// an extra query parameter into the RIPEstat request).
fn validate_asn(asn: &str) -> Result<()> {
    let digits = asn
        .strip_prefix("AS")
        .with_context(|| format!("ASN {asn:?} must start with \"AS\""))?;
    anyhow::ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
        "ASN {asn:?} is not in the expected AS<digits> format"
    );
    Ok(())
}

/// Every IPv4 prefix `asn` (e.g. `"AS15169"`) actually announces, via RIPEstat's
/// announced-prefixes API - IPv6 entries are dropped (IPv4-only scope). Uses RIPEstat's HTTPS/
/// JSON API rather than a direct WHOIS query against RADb: WHOIS doesn't handle the concurrent
/// lookups a multi-ASN BypassSource needs reliably, whereas RIPEstat tolerates concurrency within
/// its documented 8-per-IP limit (see `RIPESTAT_CONCURRENCY`).
async fn asn_prefixes(asn: &str) -> Result<Vec<String>> {
    validate_asn(asn)?;
    let url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}");
    let resp = ripestat_get(&url).await?;
    let prefixes = resp
        .pointer("/data/prefixes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.get("prefix")?.as_str())
                .filter(|p| !p.contains(':'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(prefixes)
}

/// Validates ISO 3166-1 alpha-2 format (exactly two ASCII letters) before it's spliced into a
/// request URL - same rationale as `validate_asn`. Returns the normalized (uppercase) code, since
/// callers may pass either case and RIPEstat's response/label should be consistent either way.
fn validate_country(country: &str) -> Result<String> {
    anyhow::ensure!(
        country.len() == 2 && country.bytes().all(|b| b.is_ascii_alphabetic()),
        "country {country:?} is not a valid ISO 3166-1 alpha-2 code"
    );
    Ok(country.to_ascii_uppercase())
}

/// Every IPv4 block RIPE NCC has allocated/assigned to `country` (ISO 3166-1 alpha-2), via
/// RIPEstat's country-resource-list API - the same registry data every GeoIP database derives
/// from.
async fn geoip_country_prefixes(country: &str) -> Result<Vec<String>> {
    let url =
        format!("https://stat.ripe.net/data/country-resource-list/data.json?resource={country}");
    let resp = ripestat_get(&url).await?;
    let prefixes = resp
        .pointer("/data/resources/ipv4")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(prefixes)
}

async fn collect_source(source: &BypassSourceEntry) -> Result<Vec<(String, String)>> {
    match source.kind.as_str() {
        "literal" => {
            let prefixes = source
                .prefixes
                .as_ref()
                .context("literal source requires `prefixes`")?;
            Ok(prefixes
                .iter()
                .map(|p| (p.net.clone(), p.label.clone().unwrap_or_default()))
                .collect())
        }
        "asn" => {
            let label = source
                .label
                .clone()
                .context("asn source requires `label`")?;
            let asns = source.asns.as_ref().context("asn source requires `asns`")?;
            // Each ASN is an independent RIPEstat request, resolved concurrently rather than one
            // at a time (see `asn_prefixes`'s doc comment).
            let routes_per_asn =
                futures::future::try_join_all(asns.iter().map(|asn| asn_prefixes(asn))).await?;
            Ok(routes_per_asn
                .into_iter()
                .flatten()
                .map(|route| (route, label.clone()))
                .collect())
        }
        "dns" => {
            let label = source
                .label
                .clone()
                .context("dns source requires `label`")?;
            let hostnames = source
                .hostnames
                .as_ref()
                .context("dns source requires `hostnames`")?;
            let mut entries = Vec::new();
            for host in hostnames {
                let addrs = tokio::time::timeout(
                    NETWORK_TIMEOUT,
                    tokio::net::lookup_host((host.as_str(), 0)),
                )
                .await
                .with_context(|| {
                    format!("DNS lookup for {host} timed out after {NETWORK_TIMEOUT:?}")
                })?
                .with_context(|| format!("DNS lookup failed for {host}"))?;
                for addr in addrs {
                    if let std::net::SocketAddr::V4(v4) = addr {
                        entries.push((format!("{}/32", v4.ip()), label.clone()));
                    }
                }
            }
            Ok(entries)
        }
        "geoip" => {
            let country = source
                .country
                .clone()
                .context("geoip source requires `country`")?;
            let country = validate_country(&country)?;
            let label = source
                .label
                .clone()
                .unwrap_or_else(|| format!("geoip {country}"));
            Ok(geoip_country_prefixes(&country)
                .await?
                .into_iter()
                .map(|p| (p, label.clone()))
                .collect())
        }
        other => anyhow::bail!("unknown bypass source kind: {other:?}"),
    }
}

/// Dedupe exact-duplicate CIDRs (first label wins), group by label, collapse each label's set
/// independently - a merge never crosses label/org boundaries.
fn dedupe_and_aggregate(entries: Vec<(String, String)>) -> Vec<(Cidr, String)> {
    let mut by_net: std::collections::BTreeMap<Cidr, String> = std::collections::BTreeMap::new();
    for (cidr_str, label) in entries {
        let Some(cidr) = parse_cidr(&cidr_str) else {
            // Not fatal - one bad entry shouldn't blank out the whole bypass set, but is logged
            // rather than silently dropped.
            tracing::warn!(cidr = cidr_str, "skipping malformed CIDR in bypass source");
            continue;
        };
        by_net.entry(cidr).or_insert(label);
    }
    let mut by_label: std::collections::BTreeMap<String, Vec<Cidr>> =
        std::collections::BTreeMap::new();
    for (cidr, label) in by_net {
        by_label.entry(label).or_default().push(cidr);
    }
    let mut result = Vec::new();
    for (label, nets) in by_label {
        for net in netutil::collapse(&nets) {
            result.push((net, label.clone()));
        }
    }
    result.sort();
    result
}

/// Builds the always-on exclusion for every MeshNode's own endpoint (self/cluster addresses must
/// never be blackholed by a bypass), as an ordinary `"dns"`-kind `BypassSourceEntry` appended to
/// a `BypassSource`'s own `exclude` list. The `"dns"` kind handles both a hostname and a literal
/// IP string via the same `collect_source`/`lookup_host` path (`ToSocketAddrs` tries parsing the
/// host as an address first, falling back to real resolution).
///
/// Blank endpoints are dropped here rather than passed through: `MeshNodeSpec.endpoint` has no
/// `minLength`, so an empty string is admissible and would otherwise fail the entire bypass
/// resolve over one cosmetically-broken MeshNode. A genuinely unresolvable hostname is still
/// fatal - see `resolve`'s doc comment for why that direction fails closed.
pub fn self_and_cluster_exclude_entry(endpoints: Vec<String>) -> BypassSourceEntry {
    let hostnames: Vec<String> = endpoints
        .into_iter()
        .filter(|e| {
            if e.trim().is_empty() {
                tracing::warn!("skipping blank MeshNode endpoint in self/cluster bypass exclusion");
                return false;
            }
            true
        })
        .collect();
    BypassSourceEntry {
        kind: "dns".to_string(),
        label: Some("self-and-cluster".to_string()),
        asns: None,
        prefixes: None,
        country: None,
        hostnames: Some(hostnames),
    }
}

async fn resolve_entries(sources: &[BypassSourceEntry]) -> Result<Vec<(Cidr, String)>> {
    // Each source is resolved independently (a RIPEstat call, a DNS lookup, or nothing for
    // `literal`), concurrently rather than one at a time.
    let per_source = futures::future::try_join_all(sources.iter().map(collect_source)).await?;
    Ok(dedupe_and_aggregate(
        per_source.into_iter().flatten().collect(),
    ))
}

/// Full pipeline: resolve `sources` and `exclude` (identical resolution logic for both, via
/// `resolve_entries`), then punch every exclusion out of every included prefix.
///
/// Any resolution failure fails the whole call rather than returning a partial result: a
/// partially-resolved *include* set would quietly shrink a node's bypass, and a partially-
/// resolved *exclude* set is worse - it could blackhole an address that was supposed to be
/// punched out, including a MeshNode's own endpoint. Failing means the caller serves its
/// last-known-good cache and surfaces `ResolveFailed` - it fails *closed*, toward "no blackholing".
///
/// The whole call is bounded by `RESOLVE_TOTAL_TIMEOUT` (see that constant's doc comment).
pub async fn resolve(
    sources: &[BypassSourceEntry],
    exclude: &[BypassSourceEntry],
) -> Result<Vec<(String, String)>> {
    tokio::time::timeout(RESOLVE_TOTAL_TIMEOUT, resolve_inner(sources, exclude))
        .await
        .with_context(|| {
            format!("bypass resolution exceeded its total budget of {RESOLVE_TOTAL_TIMEOUT:?}")
        })?
}

async fn resolve_inner(
    sources: &[BypassSourceEntry],
    exclude: &[BypassSourceEntry],
) -> Result<Vec<(String, String)>> {
    let included = resolve_entries(sources).await?;
    anyhow::ensure!(
        !included.is_empty(),
        "computed zero prefixes from sources - a source likely failed to resolve, refusing to \
         return an empty bypass"
    );

    let mut exclude_nets: Vec<Cidr> = resolve_entries(exclude)
        .await?
        .into_iter()
        .map(|(net, _label)| net)
        .collect();
    exclude_nets = netutil::collapse(&exclude_nets);

    let mut out = Vec::new();
    for (net, label) in included {
        let mut pending = vec![net];
        for &exc in &exclude_nets {
            let mut next_pending = Vec::new();
            for n in pending {
                if netutil::contains(exc, n) {
                    // n fully excluded - drop it.
                    continue;
                }
                if netutil::contains(n, exc) {
                    next_pending.extend(netutil::address_exclude(n, exc));
                } else {
                    next_pending.push(n);
                }
            }
            pending = next_pending;
        }
        for n in pending {
            out.push((format_cidr(n), label.clone()));
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_asn_accepts_well_formed() {
        assert!(validate_asn("AS15169").is_ok());
        assert!(validate_asn("AS1").is_ok());
    }

    #[test]
    fn validate_asn_rejects_missing_prefix() {
        assert!(validate_asn("15169").is_err());
    }

    #[test]
    fn validate_asn_rejects_non_digit_suffix() {
        assert!(validate_asn("AS").is_err());
        assert!(validate_asn("ASxyz").is_err());
    }

    #[test]
    fn validate_asn_rejects_query_string_injection() {
        // The exact concern this validation closes: an unvalidated ASN reaching the RIPEstat
        // request URL could inject an extra query parameter.
        assert!(validate_asn("AS123&foo=bar").is_err());
    }

    #[test]
    fn validate_country_accepts_two_letter_codes_either_case() {
        assert_eq!(validate_country("DE").unwrap(), "DE");
        assert_eq!(validate_country("de").unwrap(), "DE");
    }

    #[test]
    fn validate_country_rejects_wrong_length() {
        assert!(validate_country("D").is_err());
        assert!(validate_country("DEU").is_err());
    }

    #[test]
    fn validate_country_rejects_non_alphabetic() {
        assert!(validate_country("D1").is_err());
        assert!(validate_country("DE&foo=bar").is_err());
    }
}
