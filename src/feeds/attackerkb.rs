//! Rapid7 AttackerKB — community assessments of exploitability. Requires an API key.
use super::{FeedCtx, FeedOutput};
use crate::model::Advisory;
use serde_json::Value;

pub const SOURCE: &str = "AttackerKB";
const MAX_PAGES: usize = 10;

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let Some(key) = &ctx.attackerkb_key else {
        return Ok(Err("ATTACKERKB_API_KEY not set".into()));
    };
    let mut out = Vec::new();
    let mut url = Some(format!(
        "https://api.attackerkb.com/v1/topics?revisedDateAfter={}&size=100&sort=revisionDate:desc",
        ctx.since.format("%Y-%m-%dT%H:%M:%S.000Z")
    ));
    let mut pages = 0;
    while let Some(u) = url.take() {
        let v: Value = ctx.http.get(&u).header("Authorization", format!("basic {key}")).send().await?.error_for_status()?.json().await?;
        out.extend(v["data"].as_array().into_iter().flatten().filter_map(parse));
        pages += 1;
        url = v["links"]["next"]["href"].as_str().filter(|_| pages < MAX_PAGES).map(|h| {
            if h.starts_with("http") {
                h.to_string()
            } else {
                format!("https://api.attackerkb.com{h}")
            }
        });
    }
    Ok(Ok(out))
}

pub fn parse(v: &Value) -> Option<Advisory> {
    let id = v["id"].as_str()?;
    let name = v["name"].as_str().unwrap_or_default();
    let mut a = Advisory::new(SOURCE, format!("AKB-{id}"));
    for c in super::cve_ids(name) {
        a.aliases.insert(c);
    }
    a.title = v["document"].as_str().unwrap_or(name).lines().next().unwrap_or_default().to_string();
    a.published = v["created"].as_str().and_then(super::parse_rfc3339);
    a.url = Some(format!("https://attackerkb.com/topics/{id}"));
    let attacker_value = v["score"]["attackerValue"].as_f64().unwrap_or(0.0);
    let exploitability = v["score"]["exploitability"].as_f64().unwrap_or(0.0);
    if exploitability >= 3.0 || v["metadata"]["exploitedInTheWild"] == true {
        a.exploits.insert(format!("https://attackerkb.com/topics/{id} (exploitability {exploitability}, value {attacker_value})"));
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_topic() {
        let v = serde_json::json!({"id":"abc","name":"CVE-2026-1234","document":"RCE in X","created":"2026-10-28T00:00:00Z",
            "score":{"attackerValue":4.0,"exploitability":4.5}});
        let a = super::parse(&v).unwrap();
        assert!(a.aliases.contains("CVE-2026-1234"));
        assert_eq!(a.exploits.len(), 1);
    }
}
