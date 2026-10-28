//! Durable tracking of findings across days, stored as JSON in the ops repo.
use crate::feeds::FeedResult;
use crate::model::Finding;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    FixProposed,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRef {
    pub repo: String,
    pub number: u64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrRef {
    pub number: u64,
    pub url: String,
    pub auto_merge: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tracked {
    pub finding: Finding,
    /// Report date on which this finding was first discovered.
    pub day: String,
    pub status: Status,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub issue: Option<IssueRef>,
    pub pr: Option<PrRef>,
    pub fix_attempts: u32,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Day {
    pub advisories: usize,
    pub feeds: Vec<FeedResult>,
    pub repos_scanned: usize,
    pub dependencies: usize,
    pub scan_errors: usize,
    pub tracker_issue: Option<u64>,
    pub archived: bool,
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub findings: BTreeMap<String, Tracked>,
    pub days: BTreeMap<String, Day>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Reconciled {
    pub new: usize,
    pub resolved: usize,
    pub reopened: usize,
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        if !path.exists() {
            return Ok(State::default());
        }
        let s = std::fs::read_to_string(path)?;
        serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)? + "\n")?;
        Ok(())
    }

    pub fn for_day<'a>(&'a self, day: &'a str) -> impl Iterator<Item = &'a Tracked> + 'a {
        self.findings.values().filter(move |t| t.day == day)
    }

    pub fn unresolved(&self) -> impl Iterator<Item = &Tracked> {
        self.findings.values().filter(|t| t.status != Status::Resolved)
    }

    /// Merge a fresh scan. Only repos in `scanned` (scanned without error) can
    /// have findings marked resolved.
    pub fn reconcile(&mut self, findings: &[Finding], scanned: &HashSet<String>, today: &str, now: DateTime<Utc>) -> Reconciled {
        let mut r = Reconciled::default();
        let seen: HashSet<String> = findings.iter().map(Finding::key).collect();
        for f in findings {
            match self.findings.get_mut(&f.key()) {
                Some(t) => {
                    if t.status == Status::Resolved {
                        t.status = Status::Open;
                        t.resolved_at = None;
                        t.note = Some(format!("regressed on {today}"));
                        r.reopened += 1;
                    }
                    t.last_seen = now;
                    let new_today = t.finding.new_today;
                    t.finding = f.clone();
                    t.finding.new_today = new_today;
                }
                None => {
                    self.findings.insert(
                        f.key(),
                        Tracked {
                            finding: f.clone(),
                            day: today.to_string(),
                            status: Status::Open,
                            first_seen: now,
                            last_seen: now,
                            resolved_at: None,
                            issue: None,
                            pr: None,
                            fix_attempts: 0,
                            note: None,
                        },
                    );
                    r.new += 1;
                }
            }
        }
        for (k, t) in self.findings.iter_mut() {
            if t.status != Status::Resolved && scanned.contains(&t.finding.repo) && !seen.contains(k) {
                t.status = Status::Resolved;
                t.resolved_at = Some(now);
                r.resolved += 1;
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(repo: &str, pkg: &str) -> Finding {
        Finding {
            repo: repo.into(),
            file: "Cargo.lock".into(),
            ecosystem: "crates.io".into(),
            package: pkg.into(),
            version: "1.0.0".into(),
            vuln_id: "RUSTSEC-1".into(),
            aliases: vec![],
            summary: String::new(),
            severity: None,
            fixed: Some("1.0.1".into()),
            new_today: false,
        }
    }

    #[test]
    fn lifecycle() {
        let mut s = State::default();
        let now = Utc::now();
        let scanned: HashSet<String> = ["me/a".to_string(), "me/b".to_string()].into();
        let r = s.reconcile(&[f("me/a", "x"), f("me/b", "y")], &scanned, "2026-10-28", now);
        assert_eq!(r, Reconciled { new: 2, resolved: 0, reopened: 0 });
        // me/b failed to scan the next day: its finding must stay open.
        let only_a: HashSet<String> = ["me/a".to_string()].into();
        let r = s.reconcile(&[], &only_a, "2026-10-29", now);
        assert_eq!(r.resolved, 1);
        assert_eq!(s.unresolved().count(), 1);
        let r = s.reconcile(&[f("me/a", "x")], &scanned, "2026-10-30", now);
        assert_eq!((r.reopened, r.resolved), (1, 1));
        assert_eq!(s.for_day("2026-10-28").count(), 2);
    }
}
