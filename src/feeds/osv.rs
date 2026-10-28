//! OSV.dev — aggregated open source advisories (GHSA, RustSec, PyPA, Go, ...).
//! Uses the per-ecosystem `modified_id.csv` index in the public GCS bucket,
//! then fetches each changed record and keeps the newly *published* ones.
use super::{FeedCtx, FeedOutput};
use crate::model::{severity_from_score, Advisory, PkgRef};
use futures::{stream, StreamExt};
use serde_json::Value;

pub const SOURCE: &str = "OSV";

/// Application ecosystems we can also scan in repositories.
pub const ECOSYSTEMS: &[&str] =
    &["crates.io", "npm", "PyPI", "Go", "Maven", "NuGet", "Packagist", "RubyGems", "Pub", "Hex", "GitHub Actions"];

const MAX_RECORDS: usize = 1500;

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let mut ids = Vec::new();
    for eco in ECOSYSTEMS {
        let url = format!("https://osv-vulnerabilities.storage.googleapis.com/{}/modified_id.csv", eco.replace(' ', "%20"));
        let body = match ctx.http.get(&url).send().await.and_then(|r| r.error_for_status()) {
            Ok(r) => r.text().await?,
            Err(e) => {
                tracing::warn!("osv index {eco}: {e}");
                continue;
            }
        };
        ids.extend(recent_ids(&body, ctx.since));
    }
    ids.sort();
    ids.dedup();
    ids.truncate(MAX_RECORDS);
    let records: Vec<Option<Value>> = stream::iter(ids)
        .map(|id| async move {
            let r = ctx.http.get(format!("https://api.osv.dev/v1/vulns/{id}")).send().await.ok()?;
            r.error_for_status().ok()?.json::<Value>().await.ok()
        })
        .buffer_unordered(24)
        .collect()
        .await;
    let out = records
        .into_iter()
        .flatten()
        .filter_map(|v| parse(&v))
        .filter(|a| a.published.map(|p| p >= ctx.since && p <= ctx.until).unwrap_or(false))
        .collect();
    Ok(Ok(out))
}

/// Lines are `timestamp,id`, newest first; stop at the first older entry.
pub fn recent_ids(csv: &str, since: chrono::DateTime<chrono::Utc>) -> Vec<String> {
    let mut out = Vec::new();
    for line in csv.lines() {
        let Some((ts, id)) = line.split_once(',') else { continue };
        match super::parse_rfc3339(ts) {
            Some(t) if t >= since => out.push(id.rsplit('/').next().unwrap_or(id).to_string()),
            Some(_) => break,
            None => continue,
        }
    }
    out
}

/// Convert an OSV record (also used by the scanner's vuln cache).
pub fn parse(v: &Value) -> Option<Advisory> {
    let id = v["id"].as_str()?;
    let source = if id.starts_with("MAL-") { super::openssf::SOURCE } else { SOURCE };
    let mut a = Advisory::new(source, id);
    for al in v["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        a.aliases.insert(al.to_string());
    }
    a.title = v["summary"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or(v["details"].as_str())
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    a.published = v["published"].as_str().and_then(super::parse_rfc3339);
    a.url = Some(format!("https://osv.dev/vulnerability/{id}"));
    a.severity = osv_severity(v);
    for aff in v["affected"].as_array().into_iter().flatten() {
        if let (Some(e), Some(n)) = (aff["package"]["ecosystem"].as_str(), aff["package"]["name"].as_str()) {
            a.packages.insert(PkgRef { ecosystem: e.split(':').next().unwrap_or(e).to_string(), name: n.to_string() });
        }
    }
    for c in v["database_specific"]["cwe_ids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        a.cwes.insert(c.to_string());
    }
    Some(a)
}

pub fn osv_severity(v: &Value) -> Option<String> {
    if let Some(s) = v["database_specific"]["severity"].as_str() {
        return Some(match s.to_uppercase().as_str() {
            "MODERATE" => "MEDIUM".into(),
            o => o.to_string(),
        });
    }
    if v["id"].as_str().map(|i| i.starts_with("MAL-")).unwrap_or(false) {
        return Some("CRITICAL".into());
    }
    // A numeric score is sometimes given directly instead of a vector.
    v["severity"][0]["score"].as_str().and_then(|s| s.parse::<f64>().ok()).map(|s| severity_from_score(s).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_ids_stops_at_cutoff() {
        let csv = "2026-10-28T09:00:00Z,RUSTSEC-2026-0414\n2026-10-27T16:30:00Z,GHSA-aaaa\n2026-10-20T00:00:00Z,GHSA-old\n";
        let since = parse_rfc3339("2026-10-27T00:00:00Z").unwrap();
        assert_eq!(recent_ids(csv, since), vec!["RUSTSEC-2026-0414", "GHSA-aaaa"]);
    }

    fn parse_rfc3339(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        super::super::parse_rfc3339(s)
    }

    #[test]
    fn parses_record() {
        let v: Value = serde_json::from_str(include_str!("../../tests/fixtures/feeds/osv_vuln.json")).unwrap();
        let a = parse(&v).unwrap();
        assert_eq!(a.id, "GHSA-test-0001");
        assert!(a.aliases.contains("CVE-2026-0002"));
        assert_eq!(a.severity.as_deref(), Some("MEDIUM"));
        assert!(a.packages.iter().any(|p| p.ecosystem == "npm" && p.name == "lodash"));
    }
}
