//! Markdown rendering of the daily report.
use crate::feeds::{Collection, FeedStatus};
use crate::model::Advisory;
use crate::state::{State, Status, Tracked};
use crate::ticket::{target_version, top_severity};
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
        let mut groups: BTreeMap<String, Vec<&Tracked>> = BTreeMap::new();
        for t in &tracked {
            groups.entry(t.group()).or_default().push(t);
        }
        let mut rows: Vec<Vec<&Tracked>> = groups.into_values().collect();
        rows.sort_by_key(|v| {
            let done = v.iter().all(|t| t.status == Status::Resolved);
            let today = v.iter().any(|t| t.finding.new_today);
            (done, !today, v[0].finding.repo.clone(), v[0].finding.package.clone())
        });
        let _ = writeln!(md, "Grouped per repository and package ({} groups, {} findings). ⭐ = matches an advisory collected today.\n", rows.len(), tracked.len());
        let _ = writeln!(md, "| Status | Repo | Package | Installed | Upgrade to | Vulns | Severity | Ticket | PR |\n|---|---|---|---|---|---|---|---|---|");
        for v in rows {
            let f = &v[0].finding;
            let status = if v.iter().all(|t| t.status == Status::Resolved) {
                "🟢 resolved"
            } else if v.iter().any(|t| t.status == Status::FixProposed) {
                "🟡 fix proposed"
            } else {
                "🔴 open"
            };
            let mut versions: Vec<&str> = v.iter().map(|t| t.finding.version.as_str()).collect();
            versions.sort();
            versions.dedup();
            let mut ids: Vec<String> = v
                .iter()
                .map(|t| format!("[{}](https://osv.dev/vulnerability/{}){}", t.finding.vuln_id, t.finding.vuln_id, if t.finding.new_today { "⭐" } else { "" }))
                .collect();
            ids.sort();
            ids.dedup();
            let shown = if ids.len() > 4 { format!("{} +{}", ids[..4].join(" "), ids.len() - 4) } else { ids.join(" ") };
            let _ = writeln!(
                md,
                "| {status} | `{}` | `{}` ({}) | {} | {} | {} | {} | {} | {} |",
                f.repo,
                f.package,
                f.ecosystem,
                cell(&versions.join(", "), 40),
                target_version(&v).unwrap_or_else(|| "—".into()),
                shown,
                top_severity(&v),
                v.iter().find_map(|t| t.issue.as_ref()).map(|i| format!("[#{}]({})", i.number, i.url)).unwrap_or_default(),
                v.iter().find_map(|t| t.pr.as_ref()).map(|p| format!("[#{}]({})", p.number, p.url)).unwrap_or_default(),
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
