//! NIST NVD CVE API 2.0 — the canonical CVE list.
use super::{FeedCtx, FeedOutput};
use crate::model::{severity_from_score, Advisory};
use serde_json::Value;
use std::time::Duration;

pub const SOURCE: &str = "CVE (NVD)";

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let fmt = "%Y-%m-%dT%H:%M:%S%.3f";
    let mut out = Vec::new();
    let mut start = 0u64;
    loop {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={}&pubEndDate={}&resultsPerPage=2000&startIndex={start}",
            ctx.since.format(fmt),
            ctx.until.format(fmt)
        );
        let mut rb = ctx.http.get(&url).timeout(Duration::from_secs(180));
        if let Some(k) = &ctx.nvd_key {
            rb = rb.header("apiKey", k);
        }
        let v: Value = rb.send().await?.error_for_status()?.json().await?;
        let items = v["vulnerabilities"].as_array().cloned().unwrap_or_default();
        out.extend(items.iter().filter_map(|i| parse(&i["cve"])));
        let total = v["totalResults"].as_u64().unwrap_or(0);
        start += items.len() as u64;
        if items.is_empty() || start >= total {
            break;
        }
        // Public rate limit is 5 requests / 30 s without a key.
        tokio::time::sleep(Duration::from_secs(if ctx.nvd_key.is_some() { 1 } else { 7 })).await;
    }
    Ok(Ok(out))
}

pub fn parse(cve: &Value) -> Option<Advisory> {
    let id = cve["id"].as_str()?;
    let mut a = Advisory::new(SOURCE, id);
    a.url = Some(format!("https://nvd.nist.gov/vuln/detail/{id}"));
    a.published = cve["published"].as_str().and_then(super::parse_rfc3339);
    a.title = cve["descriptions"]
        .as_array()
        .and_then(|d| d.iter().find(|x| x["lang"] == "en"))
        .and_then(|d| d["value"].as_str())
        .unwrap_or_default()
        .to_string();
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(score) = cve["metrics"][key][0]["cvssData"]["baseScore"].as_f64() {
            a.score = Some(score);
            a.severity = Some(
                cve["metrics"][key][0]["cvssData"]["baseSeverity"]
                    .as_str()
                    .or(cve["metrics"][key][0]["baseSeverity"].as_str())
                    .unwrap_or(severity_from_score(score))
                    .to_uppercase(),
            );
            break;
        }
    }
    for w in cve["weaknesses"].as_array().into_iter().flatten() {
        for d in w["description"].as_array().into_iter().flatten() {
            if let Some(c) = d["value"].as_str().filter(|c| c.starts_with("CWE-")) {
                a.cwes.insert(c.to_string());
            }
        }
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_cve() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../tests/fixtures/feeds/nvd_cve.json")).unwrap();
        let a = super::parse(&v).unwrap();
        assert_eq!(a.id, "CVE-2026-0001");
        assert_eq!(a.score, Some(9.8));
        assert_eq!(a.severity.as_deref(), Some("CRITICAL"));
        assert!(a.cwes.contains("CWE-79"));
    }
}
