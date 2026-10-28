//! Markdown rendering of the daily report.
use crate::feeds::{Collection, FeedStatus};
use crate::model::Advisory;
use crate::state::{State, Status};
use std::collections::BTreeMap;
use std::fmt::Write;

fn cell(s: &str, max: usize) -> String {
    let s = s.replace('|', "\\|").replace(['\n', '\r'], " ");
    if s.chars().count() > max {
        format!("{}…", s.chars().take(max).collect::<String>())
    } else {
        s
    }
}

fn adv_link(a: &Advisory) -> String {
    match &a.url {
        Some(u) => format!("[{}]({u})", a.id),
        None => a.id.clone(),
    }
}

pub fn render(date: &str, c: &Collection, state: &State) -> String {
    let mut md = String::new();
    let day = state.days.get(date).cloned().unwrap_or_default();
    let tracked: Vec<_> = state.for_day(date).collect();
    let open = tracked.iter().filter(|t| t.status != Status::Resolved).count();
    let _ = writeln!(md, "# Vulnerability intel — {date}\n");
    if let (Some(s), Some(u)) = (c.since, c.until) {
        let _ = writeln!(md, "Window: `{}` → `{}` (UTC)\n", s.format("%Y-%m-%d %H:%M"), u.format("%Y-%m-%d %H:%M"));
    }
    let exploited = c.advisories.iter().filter(|a| !a.exploits.is_empty()).count();
    let crit = c.advisories.iter().filter(|a| a.severity.as_deref() == Some("CRITICAL")).count();
    let _ = writeln!(md, "## Summary\n");
    let _ = writeln!(md, "| Metric | Value |\n|---|---|");
    let _ = writeln!(md, "| Advisories collected (deduplicated) | {} |", c.advisories.len());
    let _ = writeln!(md, "| Critical | {crit} |");
    let _ = writeln!(md, "| With public exploit / PoC | {exploited} |");
    let _ = writeln!(md, "| Repositories scanned | {} |", day.repos_scanned);
    let _ = writeln!(md, "| Dependencies checked | {} |", day.dependencies);
    let _ = writeln!(md, "| Findings discovered today | {} |", tracked.len());
    let _ = writeln!(md, "| …of which from today's advisories | {} |", tracked.iter().filter(|t| t.finding.new_today).count());
    let _ = writeln!(md, "| Still unresolved | {open} |\n");

    let _ = writeln!(md, "## Sources\n\n| Source | Status | Records |\n|---|---|---|");
    for f in &c.feeds {
        let (status, n) = match &f.status {
            FeedStatus::Ok { count } => ("ok".to_string(), count.to_string()),
            FeedStatus::Skipped { reason } => (format!("skipped: {}", cell(reason, 80)), "–".into()),
            FeedStatus::Error { message } => (format!("error: {}", cell(message, 80)), "–".into()),
        };
        let _ = writeln!(md, "| {} | {status} | {n} |", f.source);
    }

    let _ = writeln!(md, "\n## Exposure in my repositories\n");
    if tracked.is_empty() {
        let _ = writeln!(md, "No vulnerable dependencies newly discovered today.\n");
    } else {
        let _ = writeln!(md, "| Status | Repo | Package | Version | Fixed in | Vulnerability | Severity | Today's intel | Ticket | PR |\n|---|---|---|---|---|---|---|---|---|---|");
        let mut rows = tracked.clone();
        rows.sort_by_key(|t| (t.status == Status::Resolved, !t.finding.new_today, t.finding.repo.clone()));
        for t in rows {
            let f = &t.finding;
            let status = match t.status {
                Status::Open => "🔴 open",
                Status::FixProposed => "🟡 fix proposed",
                Status::Resolved => "🟢 resolved",
            };
            let _ = writeln!(
                md,
                "| {status} | `{}` | `{}` ({}) | {} | {} | [{}](https://osv.dev/vulnerability/{}) | {} | {} | {} | {} |",
                f.repo,
                f.package,
                f.ecosystem,
                f.version,
                f.fixed.as_deref().unwrap_or("—"),
                f.vuln_id,
                f.vuln_id,
                f.severity.as_deref().unwrap_or("?"),
                if f.new_today { "⭐" } else { "" },
                t.issue.as_ref().map(|i| format!("[#{}]({})", i.number, i.url)).unwrap_or_default(),
                t.pr.as_ref().map(|p| format!("[#{}]({})", p.number, p.url)).unwrap_or_default(),
            );
        }
        md.push('\n');
    }

    let exploits: Vec<&Advisory> = c.advisories.iter().filter(|a| !a.exploits.is_empty()).collect();
    if !exploits.is_empty() {
        let _ = writeln!(md, "## Exploits / PoCs published\n\n| Advisory | Aliases | Exploit refs |\n|---|---|---|");
        for a in exploits {
            let refs: Vec<String> = a.exploits.iter().take(3).map(|e| cell(e, 90)).collect();
            let _ = writeln!(md, "| {} | {} | {} |", adv_link(a), cell(&a.aliases.iter().cloned().collect::<Vec<_>>().join(", "), 60), refs.join("<br>"));
        }
        md.push('\n');
    }

    let mut owasp: BTreeMap<&str, usize> = BTreeMap::new();
    for a in &c.advisories {
        for o in &a.owasp {
            *owasp.entry(o.as_str()).or_default() += 1;
        }
    }
    if !owasp.is_empty() {
        let _ = writeln!(md, "## OWASP Top 10 breakdown\n\n| Category | Advisories |\n|---|---|");
        for (k, v) in owasp {
            let _ = writeln!(md, "| {k} | {v} |");
        }
        md.push('\n');
    }

    let _ = writeln!(md, "## All advisories\n\n| ID | Severity | Sources | Packages | Title |\n|---|---|---|---|---|");
    for a in &c.advisories {
        let pkgs: Vec<String> = a.packages.iter().take(3).map(|p| format!("{}:{}", p.ecosystem, p.name)).collect();
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} |",
            adv_link(a),
            a.severity.as_deref().unwrap_or("?"),
            a.sources.iter().cloned().collect::<Vec<_>>().join(", "),
            cell(&pkgs.join(", "), 80),
            cell(&a.title, 140)
        );
    }
    md
}
