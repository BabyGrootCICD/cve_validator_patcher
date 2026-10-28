//! Vulners — aggregated CVEs, vendor bulletins and exploits. Requires an API key.
use super::{FeedCtx, FeedOutput};
use crate::model::{severity_from_score, Advisory};
use serde_json::{json, Value};

pub const SOURCE: &str = "Vulners";
const PAGE: u64 = 100;
const MAX_PAGES: u64 = 10;

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let Some(key) = &ctx.vulners_key else {
        return Ok(Err("VULNERS_API_KEY not set".into()));
    };
    let query = format!(
        "published:[{} TO {}] AND (type:cve OR bulletinFamily:exploit)",
        ctx.since.format("%Y-%m-%dT%H:%M:%S"),
        ctx.until.format("%Y-%m-%dT%H:%M:%S")
    );
    let mut out = Vec::new();
    for page in 0..MAX_PAGES {
        let body = json!({ "query": query, "size": PAGE, "skip": page * PAGE, "apiKey": key,
            "fields": ["id","title","published","cvss","cvelist","type","href","bulletinFamily","description"] });
        let v: Value = ctx
            .http
            .post("https://vulners.com/api/v3/search/lucene/")
            .header("X-Api-Key", key)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if v["result"] == "error" {
            anyhow::bail!("vulners: {}", v["data"]["error"]);
        }
        let items = v["data"]["search"].as_array().cloned().unwrap_or_default();
        out.extend(items.iter().filter_map(|i| parse(&i["_source"])));
        if (items.len() as u64) < PAGE {
            break;
        }
    }
    Ok(Ok(out))
}

pub fn parse(v: &Value) -> Option<Advisory> {
    let raw = v["id"].as_str()?;
    let is_cve = raw.starts_with("CVE-");
    let mut a = Advisory::new(SOURCE, if is_cve { raw.to_string() } else { format!("VULNERS-{raw}") });
    a.title = v["title"].as_str().unwrap_or_default().to_string();
    a.published = v["published"].as_str().and_then(super::parse_rfc3339);
    a.url = v["href"].as_str().map(str::to_string).or(Some(format!("https://vulners.com/{}/{raw}", v["type"].as_str().unwrap_or("cve"))));
    if let Some(s) = v["cvss"]["score"].as_f64().filter(|s| *s > 0.0) {
        a.score = Some(s);
        a.severity = Some(severity_from_score(s).into());
    }
    for c in v["cvelist"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        a.aliases.insert(c.to_string());
    }
    if v["bulletinFamily"] == "exploit" {
        if let Some(u) = &a.url {
            a.exploits.insert(u.clone());
        }
        if a.aliases.is_empty() {
            return None; // exploits not tied to a CVE are not actionable
        }
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exploit_links_to_cve() {
        let v = serde_json::json!({"id":"EDB-1","title":"PoC","bulletinFamily":"exploit","type":"exploitdb",
            "href":"https://vulners.com/exploitdb/EDB-1","cvelist":["CVE-2026-9"]});
        let a = super::parse(&v).unwrap();
        assert_eq!(a.id, "VULNERS-EDB-1");
        assert!(a.aliases.contains("CVE-2026-9") && !a.exploits.is_empty());
    }
}
