//! Archive a day once every finding discovered on it is resolved: the report,
//! the raw advisories and resolution metrics move to `archive/<date>/`.
use crate::feeds::FeedStatus;
use crate::state::{State, Status};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct Metrics {
    pub date: String,
    pub archived_at: DateTime<Utc>,
    pub advisories_collected: usize,
    pub advisories_by_source: BTreeMap<String, usize>,
    pub sources_skipped_or_failed: Vec<String>,
    pub repos_scanned: usize,
    pub dependencies_checked: usize,
    pub findings: usize,
    pub findings_from_todays_advisories: usize,
    pub distinct_vulnerabilities: usize,
    pub affected_repos: usize,
    pub affected_packages: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub tickets_opened: usize,
    pub fix_prs: usize,
    pub fix_prs_auto_merge: usize,
    pub resolved: usize,
    pub resolved_via_fix_pr: usize,
    pub mean_time_to_resolve_hours: Option<f64>,
    pub max_time_to_resolve_hours: Option<f64>,
}

pub fn metrics(state: &State, date: &str, now: DateTime<Utc>) -> Metrics {
    let day = state.days.get(date).cloned().unwrap_or_default();
    let items: Vec<_> = state.for_day(date).collect();
    let mut by_source = BTreeMap::new();
    let mut skipped = Vec::new();
    for f in &day.feeds {
        match &f.status {
            FeedStatus::Ok { count } => {
                by_source.insert(f.source.clone(), *count);
            }
            FeedStatus::Skipped { reason } => skipped.push(format!("{}: skipped ({reason})", f.source)),
            FeedStatus::Error { message } => {
                skipped.push(format!("{}: error ({})", f.source, message.chars().take(200).collect::<String>()))
            }
        }
    }
    let mut by_severity = BTreeMap::new();
    for t in &items {
        *by_severity.entry(t.finding.severity.clone().unwrap_or_else(|| "UNKNOWN".into())).or_insert(0) += 1;
    }
    let ttr: Vec<f64> = items.iter().filter_map(|t| t.resolved_at.map(|r| (r - t.first_seen).num_seconds() as f64 / 3600.0)).collect();
    let set = |f: &dyn Fn(&&crate::state::Tracked) -> Option<String>| items.iter().filter_map(f).collect::<BTreeSet<_>>().len();
    Metrics {
        date: date.to_string(),
        archived_at: now,
        advisories_collected: day.advisories,
        advisories_by_source: by_source,
        sources_skipped_or_failed: skipped,
        repos_scanned: day.repos_scanned,
        dependencies_checked: day.dependencies,
        findings: items.len(),
        findings_from_todays_advisories: items.iter().filter(|t| t.finding.new_today).count(),
        distinct_vulnerabilities: set(&|t| Some(t.finding.vuln_id.clone())),
        affected_repos: set(&|t| Some(t.finding.repo.clone())),
        affected_packages: set(&|t| Some(t.group())),
        by_severity,
        tickets_opened: set(&|t| t.issue.as_ref().map(|i| i.url.clone())),
        fix_prs: set(&|t| t.pr.as_ref().map(|p| p.url.clone())),
        fix_prs_auto_merge: set(&|t| t.pr.as_ref().filter(|p| p.auto_merge).map(|p| p.url.clone())),
        resolved: items.iter().filter(|t| t.status == Status::Resolved).count(),
        resolved_via_fix_pr: items.iter().filter(|t| t.status == Status::Resolved && t.pr.is_some()).count(),
        mean_time_to_resolve_hours: (!ttr.is_empty()).then(|| ttr.iter().sum::<f64>() / ttr.len() as f64),
        max_time_to_resolve_hours: ttr.iter().cloned().reduce(f64::max),
    }
}

pub fn metrics_md(m: &Metrics) -> String {
    let mut s = format!(
        "# Resolution metrics — {}\n\nArchived at {} (all findings discovered on this day are resolved).\n\n",
        m.date,
        m.archived_at.format("%Y-%m-%d %H:%M UTC")
    );
    let _ = writeln!(s, "| Metric | Value |\n|---|---|");
    let hours = |h: Option<f64>| h.map(|h| format!("{h:.1} h")).unwrap_or_else(|| "—".into());
    for (k, v) in [
        ("Advisories collected", m.advisories_collected.to_string()),
        ("Repositories scanned", m.repos_scanned.to_string()),
        ("Dependencies checked", m.dependencies_checked.to_string()),
        ("Findings", m.findings.to_string()),
        ("…from that day's advisories", m.findings_from_todays_advisories.to_string()),
        ("Distinct vulnerabilities", m.distinct_vulnerabilities.to_string()),
        ("Affected repositories", m.affected_repos.to_string()),
        ("Affected packages", m.affected_packages.to_string()),
        ("Tickets opened", m.tickets_opened.to_string()),
        ("Fix PRs", m.fix_prs.to_string()),
        ("Fix PRs with auto-merge", m.fix_prs_auto_merge.to_string()),
        ("Resolved", m.resolved.to_string()),
        ("Resolved via fix PR", m.resolved_via_fix_pr.to_string()),
        ("Mean time to resolve", hours(m.mean_time_to_resolve_hours)),
        ("Max time to resolve", hours(m.max_time_to_resolve_hours)),
    ] {
        let _ = writeln!(s, "| {k} | {v} |");
    }
    let _ = writeln!(s, "\n## Advisories by source\n\n| Source | Records |\n|---|---|");
    for (k, v) in &m.advisories_by_source {
        let _ = writeln!(s, "| {k} | {v} |");
    }
    for x in &m.sources_skipped_or_failed {
        let _ = writeln!(s, "| {x} | – |");
    }
    if !m.by_severity.is_empty() {
        let _ = writeln!(s, "\n## Findings by severity\n\n| Severity | Findings |\n|---|---|");
        for (k, v) in &m.by_severity {
            let _ = writeln!(s, "| {k} | {v} |");
        }
    }
    s
}

/// Days that are complete: scanned, not yet archived, nothing unresolved.
/// The current day is only archived once its scan has run.
pub fn archivable(state: &State) -> Vec<String> {
    state
        .days
        .iter()
        .filter(|(d, day)| !day.archived && day.repos_scanned > 0 && state.for_day(d).all(|t| t.status == Status::Resolved))
        .map(|(d, _)| d.clone())
        .collect()
}

/// Move `reports/<d>.md|json` into `archive/<d>/` with metrics. The caller
/// renders the final report first.
pub fn archive_day(state: &mut State, date: &str, report_dir: &Path, archive_dir: &Path, now: DateTime<Utc>) -> Result<()> {
    let dest = archive_dir.join(date);
    std::fs::create_dir_all(&dest)?;
    for (src, dst) in [(format!("{date}.md"), "report.md"), (format!("{date}.json"), "advisories.json")] {
        let s = report_dir.join(&src);
        if s.exists() {
            std::fs::rename(&s, dest.join(dst)).or_else(|_| std::fs::copy(&s, dest.join(dst)).and_then(|_| std::fs::remove_file(&s)))?;
        }
    }
    let m = metrics(state, date, now);
    std::fs::write(dest.join("metrics.json"), serde_json::to_string_pretty(&m)? + "\n")?;
    std::fs::write(dest.join("metrics.md"), metrics_md(&m))?;
    let findings: Vec<_> = state.for_day(date).cloned().collect();
    std::fs::write(dest.join("findings.json"), serde_json::to_string_pretty(&findings)? + "\n")?;
    let day = state.days.entry(date.to_string()).or_default();
    day.archived = true;
    day.archived_at = Some(now);
    // Resolved findings now live in the archive; drop them from active state.
    state.findings.retain(|_, t| !(t.day == date && t.status == Status::Resolved));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;
    use std::collections::HashSet;

    fn f(pkg: &str) -> Finding {
        Finding {
            repo: "me/a".into(),
            file: "Cargo.lock".into(),
            ecosystem: "crates.io".into(),
            package: pkg.into(),
            version: "1.0.0".into(),
            vuln_id: format!("RUSTSEC-{pkg}"),
            aliases: vec![],
            summary: String::new(),
            severity: Some("HIGH".into()),
            fixed: None,
            new_today: true,
        }
    }

    #[test]
    fn archives_only_when_resolved() {
        let mut s = State::default();
        let now = Utc::now();
        let scanned: HashSet<String> = ["me/a".to_string()].into();
        s.reconcile(&[f("x"), f("y")], &scanned, "2026-10-28", now);
        s.days.entry("2026-10-28".into()).or_default().repos_scanned = 1;
        assert!(archivable(&s).is_empty());
        s.reconcile(&[f("y")], &scanned, "2026-10-29", now);
        assert!(archivable(&s).is_empty());
        s.reconcile(&[], &scanned, "2026-10-30", now);
        assert_eq!(archivable(&s), vec!["2026-10-28"]);

        let d = tempfile::tempdir().unwrap();
        let (rep, arc) = (d.path().join("reports"), d.path().join("archive"));
        std::fs::create_dir_all(&rep).unwrap();
        std::fs::write(rep.join("2026-10-28.md"), "# r").unwrap();
        archive_day(&mut s, "2026-10-28", &rep, &arc, now).unwrap();
        assert!(arc.join("2026-10-28/report.md").exists() && !rep.join("2026-10-28.md").exists());
        let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(arc.join("2026-10-28/metrics.json")).unwrap()).unwrap();
        assert_eq!((m["findings"].as_u64(), m["resolved"].as_u64()), (Some(2), Some(2)));
        assert!(s.findings.is_empty() && s.days["2026-10-28"].archived);
    }
}
