//! ENISA EU Vulnerability Database (EUVD).
use super::{FeedCtx, FeedOutput};
use crate::model::{severity_from_score, Advisory};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;

pub const SOURCE: &str = "ENISA EUVD";
const PAGE: usize = 100;
const MAX_PAGES: usize = 30;

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let mut out = Vec::new();
    for page in 0..MAX_PAGES {
        let url = format!(
            "https://euvdservices.enisa.europa.eu/api/search?fromDate={}&toDate={}&size={PAGE}&page={page}",
            ctx.since.format("%Y-%m-%d"),
            ctx.until.format("%Y-%m-%d")
        );
        let v: Value = ctx.http.get(&url).send().await?.error_for_status()?.json().await?;
        let items = v["items"].as_array().cloned().unwrap_or_default();
        out.extend(
            items
                .iter()
                .filter_map(parse)
                .filter(|a| a.published.map(|p| p >= ctx.since && p <= ctx.until).unwrap_or(true)),
        );
        if items.len() < PAGE {
            break;
        }
    }
    Ok(Ok(out))
}

pub fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%b %d, %Y, %I:%M:%S %p").ok().map(|n| n.and_utc())
}

pub fn parse(v: &Value) -> Option<Advisory> {
    let id = v["id"].as_str()?;
    let mut a = Advisory::new(SOURCE, id);
    a.title = v["description"].as_str().unwrap_or_default().to_string();
    a.published = v["datePublished"].as_str().and_then(parse_date);
    a.url = Some(format!("https://euvd.enisa.europa.eu/vulnerability/{id}"));
    if let Some(s) = v["baseScore"].as_f64().filter(|s| *s > 0.0) {
        a.score = Some(s);
        a.severity = Some(severity_from_score(s).into());
    }
    for al in v["aliases"].as_str().unwrap_or_default().lines().map(str::trim).filter(|s| !s.is_empty()) {
        a.aliases.insert(al.to_string());
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_item() {
        let v = serde_json::json!({"id":"EUVD-2026-111993","description":"XXE","datePublished":"Oct 28, 2026, 12:30:36 PM",
            "baseScore":8.3,"aliases":"CVE-2026-112198\nGHSA-4cvm-388f-wj2m\n"});
        let a = super::parse(&v).unwrap();
        assert_eq!(a.aliases.len(), 2);
        assert_eq!(a.severity.as_deref(), Some("HIGH"));
        assert_eq!(a.published.unwrap().to_rfc3339(), "2026-10-28T12:30:36+00:00");
    }
}
