//! OpenSSF initiatives: the Malicious Packages repository (`ossf/malicious-packages`).
//! New reports are discovered from commits in the window; the file path encodes
//! ecosystem, package and MAL id, so no per-file download is needed.
use super::{FeedCtx, FeedOutput};
use crate::model::{Advisory, PkgRef};
use serde_json::Value;

pub const SOURCE: &str = "OpenSSF Malicious Packages";
const MAX_COMMITS: usize = 60;

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let path =
        format!("/repos/ossf/malicious-packages/commits?since={}&until={}&per_page=100", ctx.since.to_rfc3339(), ctx.until.to_rfc3339());
    let commits = ctx.gh.paginate(&path, None, 1).await?;
    let mut out = Vec::new();
    for c in commits.iter().take(MAX_COMMITS) {
        let Some(sha) = c["sha"].as_str() else { continue };
        let detail: Value = ctx.gh.get(&format!("/repos/ossf/malicious-packages/commits/{sha}")).await?;
        let date = c["commit"]["committer"]["date"].as_str().and_then(super::parse_rfc3339);
        for f in detail["files"].as_array().into_iter().flatten() {
            if f["status"] != "added" {
                continue;
            }
            if let Some(mut a) = f["filename"].as_str().and_then(from_path) {
                a.published = date;
                out.push(a);
            }
        }
    }
    Ok(Ok(out))
}

/// `osv/malicious/<eco>/<package...>/MAL-YYYY-N.json` → advisory.
pub fn from_path(p: &str) -> Option<Advisory> {
    let rest = p.strip_prefix("osv/malicious/")?;
    let (dir, file) = rest.rsplit_once('/')?;
    let id = file.strip_suffix(".json")?;
    if !id.starts_with("MAL-") {
        return None;
    }
    let (eco_dir, pkg) = dir.split_once('/')?;
    let ecosystem = match eco_dir {
        "npm" => "npm",
        "pypi" => "PyPI",
        "crates-io" | "crates.io" => "crates.io",
        "rubygems" => "RubyGems",
        "nuget" => "NuGet",
        "go" => "Go",
        "maven" => "Maven",
        "packagist" => "Packagist",
        other => other,
    };
    let mut a = Advisory::new(SOURCE, id);
    a.title = format!("Malicious package: {pkg}");
    a.severity = Some("CRITICAL".into());
    a.url = Some(format!("https://osv.dev/vulnerability/{id}"));
    a.packages.insert(PkgRef { ecosystem: ecosystem.into(), name: pkg.to_string() });
    a.cwes.insert("CWE-506".into());
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn path_parsing() {
        let a = super::from_path("osv/malicious/npm/@evil/pkg/MAL-2026-1234.json").unwrap();
        assert_eq!(a.id, "MAL-2026-1234");
        let p = a.packages.iter().next().unwrap();
        assert_eq!((p.ecosystem.as_str(), p.name.as_str()), ("npm", "@evil/pkg"));
        assert!(super::from_path("osv/withdrawn/npm/x/MAL-1.json").is_none());
    }
}
