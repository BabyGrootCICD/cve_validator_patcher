//! Vulnerability intelligence feeds. Each feed returns advisories published
//! within the collection window; failures and missing API keys are recorded
//! per source instead of aborting the whole collection.

pub mod attackerkb;
pub mod euvd;
pub mod ghsa;
pub mod nvd;
pub mod openssf;
pub mod osv;
pub mod owasp;
pub mod sploitus;
pub mod vulners;

use crate::github::GitHub;
use crate::model::{dedupe, Advisory};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub struct FeedCtx {
    pub http: reqwest::Client,
    pub gh: GitHub,
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub nvd_key: Option<String>,
    pub vulners_key: Option<String>,
    pub attackerkb_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum FeedStatus {
    Ok { count: usize },
    Skipped { reason: String },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedResult {
    pub source: String,
    #[serde(flatten)]
    pub status: FeedStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Collection {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub feeds: Vec<FeedResult>,
    pub advisories: Vec<Advisory>,
}

/// Outcome of a single feed: `Ok(Err(reason))` means the source was skipped.
pub type FeedOutput = anyhow::Result<Result<Vec<Advisory>, String>>;

fn record(source: &str, out: FeedOutput, all: &mut Vec<Advisory>, feeds: &mut Vec<FeedResult>) {
    let status = match out {
        Ok(Ok(v)) => {
            let count = v.len();
            all.extend(v);
            FeedStatus::Ok { count }
        }
        Ok(Err(reason)) => FeedStatus::Skipped { reason },
        Err(e) => {
            tracing::warn!("feed {source} failed: {e:#}");
            FeedStatus::Error { message: format!("{e:#}") }
        }
    };
    feeds.push(FeedResult { source: source.to_string(), status });
}

pub async fn collect(ctx: &FeedCtx) -> Collection {
    let (nvd, osv, euvd, ghsa, ossf, vulners, akb, sploitus) = tokio::join!(
        nvd::fetch(ctx),
        osv::fetch(ctx),
        euvd::fetch(ctx),
        ghsa::fetch(ctx),
        openssf::fetch(ctx),
        vulners::fetch(ctx),
        attackerkb::fetch(ctx),
        sploitus::fetch(ctx),
    );
    let mut all = Vec::new();
    let mut feeds = Vec::new();
    record(nvd::SOURCE, nvd, &mut all, &mut feeds);
    record(osv::SOURCE, osv, &mut all, &mut feeds);
    record(euvd::SOURCE, euvd, &mut all, &mut feeds);
    record(ghsa::SOURCE, ghsa, &mut all, &mut feeds);
    record(openssf::SOURCE, ossf, &mut all, &mut feeds);
    record(vulners::SOURCE, vulners, &mut all, &mut feeds);
    record(attackerkb::SOURCE, akb, &mut all, &mut feeds);
    record(sploitus::SOURCE, sploitus, &mut all, &mut feeds);

    let mut advisories = dedupe(all);
    // OWASP publishes no advisory feed; it contributes a classification of
    // everything collected (CWE → OWASP Top 10).
    let tagged = owasp::tag(&mut advisories);
    feeds.push(FeedResult { source: owasp::SOURCE.into(), status: FeedStatus::Ok { count: tagged } });

    Collection { since: Some(ctx.since), until: Some(ctx.until), feeds, advisories }
}

/// Extract every CVE id mentioned in free text.
pub fn cve_ids(text: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap());
    let mut v: Vec<String> = re.find_iter(text).map(|m| m.as_str().to_string()).collect();
    v.sort();
    v.dedup();
    v
}

pub fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc)).or_else(|| {
        // NVD style without offset: 2026-10-28T12:00:00.000
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok().map(|n| n.and_utc())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn cve_extraction() {
        let v = super::cve_ids("PoC for CVE-2026-109618 and CVE-2026-109619, again CVE-2026-109618");
        assert_eq!(v, vec!["CVE-2026-109618", "CVE-2026-109619"]);
    }
}
