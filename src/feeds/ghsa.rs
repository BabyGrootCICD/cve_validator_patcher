//! GitHub Advisory Database (reviewed + unreviewed global advisories).
use super::{FeedCtx, FeedOutput};
use crate::model::{severity_from_score, Advisory, PkgRef};
use serde_json::Value;

pub const SOURCE: &str = "GitHub Advisory Database";

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let path = format!(
        "/advisories?published={}..{}&per_page=100&sort=published&direction=desc",
        ctx.since.format("%Y-%m-%dT%H:%M:%SZ"),
        ctx.until.format("%Y-%m-%dT%H:%M:%SZ")
    );
    let items = ctx.gh.paginate(&path, None, 30).await?;
    Ok(Ok(items.iter().filter_map(parse).collect()))
}

/// GitHub ecosystem names → OSV ecosystem names.
pub fn ecosystem(e: &str) -> &str {
    match e {
        "pip" => "PyPI",
        "rubygems" => "RubyGems",
        "maven" => "Maven",
        "nuget" => "NuGet",
        "composer" => "Packagist",
        "go" => "Go",
        "rust" => "crates.io",
        "erlang" => "Hex",
        "actions" => "GitHub Actions",
        "pub" => "Pub",
        "swift" => "SwiftURL",
        other => other,
    }
}

pub fn parse(v: &Value) -> Option<Advisory> {
    let id = v["ghsa_id"].as_str()?;
    let mut a = Advisory::new(SOURCE, id);
    if let Some(c) = v["cve_id"].as_str() {
        a.aliases.insert(c.to_string());
    }
    a.title = v["summary"].as_str().unwrap_or_default().to_string();
    a.published = v["published_at"].as_str().and_then(super::parse_rfc3339);
    a.url = v["html_url"].as_str().map(str::to_string);
    a.score = v["cvss"]["score"].as_f64().filter(|s| *s > 0.0);
    a.severity = v["severity"]
        .as_str()
        .filter(|s| *s != "unknown")
        .map(|s| if s == "moderate" { "MEDIUM".into() } else { s.to_uppercase() })
        .or_else(|| a.score.map(|s| severity_from_score(s).into()));
    for c in v["cwes"].as_array().into_iter().flatten() {
        if let Some(id) = c["cwe_id"].as_str() {
            a.cwes.insert(id.to_string());
        }
    }
    for vu in v["vulnerabilities"].as_array().into_iter().flatten() {
        if let (Some(e), Some(n)) = (vu["package"]["ecosystem"].as_str(), vu["package"]["name"].as_str()) {
            a.packages.insert(PkgRef { ecosystem: ecosystem(e).into(), name: n.into() });
        }
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_advisory() {
        let v = serde_json::json!({"ghsa_id":"GHSA-gww9-3rx9-535x","cve_id":"CVE-2026-118485","summary":"Path traversal",
            "severity":"moderate","published_at":"2026-10-28T12:31:08Z","cwes":[{"cwe_id":"CWE-24"}],
            "vulnerabilities":[{"package":{"ecosystem":"pip","name":"axel"}}]});
        let a = super::parse(&v).unwrap();
        assert_eq!(a.severity.as_deref(), Some("MEDIUM"));
        assert!(a.packages.iter().any(|p| p.ecosystem == "PyPI"));
        assert!(a.aliases.contains("CVE-2026-118485"));
    }
}
