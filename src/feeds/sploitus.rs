//! Sploitus — exploit and PoC search engine. No official API: this uses the
//! site's JSON search endpoint on a best-effort basis.
use super::{FeedCtx, FeedOutput};
use crate::model::{severity_from_score, Advisory};
use chrono::NaiveDate;
use serde_json::{json, Value};

pub const SOURCE: &str = "Sploitus";
const MAX_PAGES: u64 = 15;

pub async fn fetch(ctx: &FeedCtx) -> FeedOutput {
    let since_day = ctx.since.date_naive();
    let mut out = Vec::new();
    let years: Vec<i32> = {
        use chrono::Datelike;
        let y = ctx.until.year();
        vec![y, y - 1]
    };
    for year in years {
        'pages: for page in 0..MAX_PAGES {
            let body = json!({"type":"exploits","sort":"date","query":format!("CVE-{year}"),"title":false,"offset":page*10});
            let resp = ctx
                .http
                .post("https://sploitus.com/search")
                .header("Origin", "https://sploitus.com")
                .header("Referer", "https://sploitus.com/")
                .json(&body)
                .send()
                .await?;
            if !resp.status().is_success() {
                if out.is_empty() {
                    anyhow::bail!("sploitus search HTTP {} (likely bot protection)", resp.status());
                }
                break;
            }
            let v: Value = resp.json().await?;
            let items = v["exploits"].as_array().cloned().unwrap_or_default();
            if items.is_empty() {
                break;
            }
            for it in &items {
                let day = it["published"].as_str().and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());
                if day.map(|d| d < since_day).unwrap_or(false) {
                    break 'pages;
                }
                out.extend(parse(it));
            }
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        }
    }
    Ok(Ok(out))
}

pub fn parse(v: &Value) -> Option<Advisory> {
    let id = v["id"].as_str()?;
    let title = v["title"].as_str().unwrap_or_default();
    let text = format!("{title} {}", v["source"].as_str().unwrap_or_default());
    let cves = super::cve_ids(&text);
    if cves.is_empty() {
        return None;
    }
    let mut a = Advisory::new(SOURCE, format!("SPLOITUS-{id}"));
    a.aliases.extend(cves);
    a.title = title.to_string();
    a.published = v["published"]
        .as_str()
        .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|d| d.and_utc());
    if let Some(s) = v["score"].as_f64().filter(|s| *s > 0.0) {
        a.score = Some(s);
        a.severity = Some(severity_from_score(s).into());
    }
    let href = v["href"].as_str().map(str::to_string).unwrap_or(format!("https://sploitus.com/exploit?id={id}"));
    a.url = Some(format!("https://sploitus.com/exploit?id={id}"));
    a.exploits.insert(href);
    Some(a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exploit_with_cves() {
        let v = serde_json::json!({"title":"php2shell-lab","score":9.8,"href":"https://github.com/x/y","published":"2026-10-28",
            "id":"CC26","source":"for CVE-2026-109618 and CVE-2026-109619"});
        let a = super::parse(&v).unwrap();
        assert_eq!(a.aliases.len(), 2);
        assert!(a.exploits.contains("https://github.com/x/y"));
        assert!(super::parse(&serde_json::json!({"id":"x","title":"no cve"})).is_none());
    }
}
