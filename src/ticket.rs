//! Issue management: one issue per (repo, ecosystem, package) in the affected
//! repository, plus one tracker issue per report day in the ops repository.
use crate::github::GitHub;
use crate::model::cmp_versions;
use crate::state::{IssueRef, State, Status, Tracked};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::hash::{Hash, Hasher};

pub const LABEL: &str = "vuln-sentinel";

pub struct TicketCfg {
    pub dry_run: bool,
    /// Cap on newly created issues per run (GitHub content-creation limits).
    pub max_new: usize,
    /// `owner/name` of the ops repository hosting reports and trackers.
    pub tracker_repo: Option<String>,
    /// Branch of the ops repo, for report links.
    pub tracker_branch: String,
    pub report_dir: String,
}

#[derive(Debug, Default)]
pub struct TicketStats {
    pub created: usize,
    pub updated: usize,
    pub closed: usize,
    pub reopened: usize,
    pub deferred: usize,
}

fn marker(group: &str) -> String {
    format!("<!-- vuln-sentinel:{group} -->")
}

fn hash(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Highest fixed version needed to clear every open vuln in the group.
pub fn target_version(items: &[&Tracked]) -> Option<String> {
    items.iter().filter(|t| t.status != Status::Resolved).filter_map(|t| t.finding.fixed.clone()).max_by(|a, b| cmp_versions(a, b))
}

fn severity_rank(s: Option<&str>) -> u8 {
    match s {
        Some("CRITICAL") => 4,
        Some("HIGH") => 3,
        Some("MEDIUM") => 2,
        Some("LOW") => 1,
        _ => 0,
    }
}

pub fn top_severity(items: &[&Tracked]) -> &'static str {
    match items.iter().map(|t| severity_rank(t.finding.severity.as_deref())).max().unwrap_or(0) {
        4 => "CRITICAL",
        3 => "HIGH",
        2 => "MEDIUM",
        1 => "LOW",
        _ => "UNKNOWN",
    }
}

fn issue_title(items: &[&Tracked]) -> String {
    let f = &items[0].finding;
    let open = items.iter().filter(|t| t.status != Status::Resolved).count();
    format!(
        "[vuln-sentinel] {} {} `{}`: {open} known vulnerabilit{}",
        top_severity(items),
        f.ecosystem,
        f.package,
        if open == 1 { "y" } else { "ies" }
    )
}

fn issue_body(group: &str, items: &[&Tracked], cfg: &TicketCfg) -> String {
    let f = &items[0].finding;
    let mut b = String::new();
    let _ = writeln!(b, "{}\n", marker(group));
    let _ = writeln!(b, "**Package:** `{}` ({})  ", f.package, f.ecosystem);
    match target_version(items) {
        Some(v) => {
            let _ = writeln!(b, "**Upgrade to:** `{v}` or later  ");
        }
        None => {
            let _ = writeln!(b, "**Upgrade to:** no fixed release published yet — consider replacing or mitigating  ");
        }
    }
    let mut files: Vec<&str> = items.iter().map(|t| t.finding.file.as_str()).collect();
    files.sort();
    files.dedup();
    let _ = writeln!(b, "**Found in:** {}\n", files.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", "));
    let _ = writeln!(b, "| | Vulnerability | Severity | Installed | Fixed in | Summary |\n|---|---|---|---|---|---|");
    let mut rows: Vec<&&Tracked> = items.iter().collect();
    rows.sort_by_key(|t| (t.status == Status::Resolved, std::cmp::Reverse(severity_rank(t.finding.severity.as_deref()))));
    for t in rows {
        let x = &t.finding;
        let _ = writeln!(
            b,
            "| {} | [{}](https://osv.dev/vulnerability/{}){} | {} | {} | {} | {} |",
            if t.status == Status::Resolved { "✅" } else { "⚠️" },
            x.vuln_id,
            x.vuln_id,
            if x.new_today { " ⭐ new" } else { "" },
            x.severity.as_deref().unwrap_or("?"),
            x.version,
            x.fixed.as_deref().unwrap_or("—"),
            x.summary.replace('|', "\\|").chars().take(120).collect::<String>()
        );
    }
    if let Some(pr) = items.iter().find_map(|t| t.pr.as_ref()) {
        let _ = writeln!(b, "\nFix PR: {}{}", pr.url, if pr.auto_merge { " (auto-merge enabled)" } else { "" });
    }
    if let Some(n) = items.iter().find_map(|t| t.note.as_ref()) {
        let _ = writeln!(b, "\n> {n}");
    }
    if let Some(r) = &cfg.tracker_repo {
        let days: HashSet<&str> = items.iter().map(|t| t.day.as_str()).collect();
        for d in days {
            let _ = writeln!(b, "\nDaily report: https://github.com/{r}/blob/{}/{}/{d}.md", cfg.tracker_branch, cfg.report_dir);
        }
    }
    let _ = writeln!(b, "\n<sub>Managed by vuln-sentinel. This issue closes automatically once the vulnerable versions are gone from the default branch.</sub>");
    b
}

/// Find existing vuln-sentinel issues in a repo, keyed by group marker.
async fn existing_issues(gh: &GitHub, repo: &str) -> Result<HashMap<String, Value>> {
    let items = gh.paginate(&format!("/repos/{repo}/issues?labels={LABEL}&state=all&per_page=100"), None, 20).await?;
    let mut m = HashMap::new();
    for i in items {
        if i.get("pull_request").is_some() {
            continue;
        }
        let body = i["body"].as_str().unwrap_or_default();
        if let Some(rest) = body.split("<!-- vuln-sentinel:").nth(1) {
            if let Some(g) = rest.split(" -->").next() {
                m.insert(g.to_string(), i.clone());
            }
        }
    }
    Ok(m)
}

/// Create/update/close per-package issues so they mirror state.
pub async fn sync(gh: &GitHub, state: &mut State, repos_with_issues: &HashSet<String>, cfg: &TicketCfg) -> Result<TicketStats> {
    let mut stats = TicketStats::default();
    let groups: Vec<(String, Vec<Tracked>)> = state.groups().into_iter().map(|(g, v)| (g, v.into_iter().cloned().collect())).collect();
    let mut cache: HashMap<String, HashMap<String, Value>> = HashMap::new();
    let mut labelled: HashSet<String> = HashSet::new();

    for (group, items) in groups {
        let refs: Vec<&Tracked> = items.iter().collect();
        let repo = items[0].finding.repo.clone();
        let open = items.iter().any(|t| t.status != Status::Resolved);
        let existing = items.iter().find_map(|t| t.issue.clone());
        if !repos_with_issues.contains(&repo) {
            continue; // issues disabled or repo out of scope; tracked in the daily tracker only
        }
        let title = issue_title(&refs);
        let body = issue_body(&group, &refs, cfg);
        let h = hash(&format!("{title}\n{body}"));

        let issue = match existing {
            Some(i) => Some(i),
            None if !open => None,
            None => {
                if cfg.dry_run {
                    tracing::info!("[dry-run] would open issue in {repo}: {title}");
                    continue;
                }
                if !cache.contains_key(&repo) {
                    cache.insert(repo.clone(), existing_issues(gh, &repo).await.unwrap_or_default());
                }
                if let Some(i) = cache[&repo].get(&group) {
                    Some(IssueRef {
                        repo: repo.clone(),
                        number: i["number"].as_u64().unwrap_or(0),
                        url: i["html_url"].as_str().unwrap_or_default().to_string(),
                        body_hash: 0,
                        open: i["state"] == "open",
                    })
                } else if stats.created >= cfg.max_new {
                    stats.deferred += 1;
                    continue;
                } else {
                    if labelled.insert(repo.clone()) {
                        let _ = gh
                            .post_idempotent(
                                &format!("/repos/{repo}/labels"),
                                &json!({"name": LABEL, "color": "b60205", "description": "Vulnerable dependency tracked by vuln-sentinel"}),
                            )
                            .await;
                    }
                    let v = gh
                        .post(&format!("/repos/{repo}/issues"), &json!({"title": title, "body": body, "labels": [LABEL, "security"]}))
                        .await;
                    match v {
                        Ok(v) => {
                            stats.created += 1;
                            let i = IssueRef {
                                repo: repo.clone(),
                                number: v["number"].as_u64().unwrap_or(0),
                                url: v["html_url"].as_str().unwrap_or_default().to_string(),
                                body_hash: h,
                                open: true,
                            };
                            for t in state.group_mut(&group) {
                                t.issue = Some(i.clone());
                            }
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!("cannot open issue in {repo}: {e:#}");
                            continue;
                        }
                    }
                }
            }
        };
        let Some(mut issue) = issue else { continue };
        if cfg.dry_run {
            continue;
        }
        let path = format!("/repos/{repo}/issues/{}", issue.number);
        let desired_state = if open { "open" } else { "closed" };
        let state_changed = issue.open != open;
        if issue.body_hash != h || state_changed {
            let mut patch = json!({"title": title, "body": body});
            if state_changed {
                patch["state"] = json!(desired_state);
                if !open {
                    patch["state_reason"] = json!("completed");
                }
            }
            match gh.patch(&path, &patch).await {
                Ok(_) => {
                    if state_changed && !open {
                        stats.closed += 1;
                        let _ = gh
                            .post(
                                &format!("{path}/comments"),
                                &json!({"body": "✅ No longer detected on the default branch — closing. (vuln-sentinel)"}),
                            )
                            .await;
                    } else if state_changed {
                        stats.reopened += 1;
                    } else {
                        stats.updated += 1;
                    }
                    issue.body_hash = h;
                    issue.open = open;
                }
                Err(e) => tracing::warn!("cannot update {path}: {e:#}"),
            }
        }
        for t in state.group_mut(&group) {
            t.issue = Some(issue.clone());
        }
    }
    Ok(stats)
}

/// Create or refresh the tracker issue for `day` in the ops repository.
pub async fn sync_tracker(gh: &GitHub, state: &mut State, day: &str, cfg: &TicketCfg, close: bool) -> Result<()> {
    let Some(repo) = &cfg.tracker_repo else { return Ok(()) };
    let mut groups: Vec<(String, Vec<&Tracked>)> = state
        .groups()
        .into_iter()
        .map(|(g, v)| (g, v.into_iter().filter(|t| t.day == day).collect::<Vec<_>>()))
        .filter(|(_, v)| !v.is_empty())
        .collect();
    groups.sort_by_key(|(g, v)| {
        (v.iter().all(|t| t.status == Status::Resolved), std::cmp::Reverse(severity_rank(Some(top_severity(v)))), g.clone())
    });
    let total: usize = groups.iter().map(|(_, v)| v.len()).sum();
    let open: usize = groups.iter().map(|(_, v)| v.iter().filter(|t| t.status != Status::Resolved).count()).sum();
    let mut body = format!(
        "Daily report: https://github.com/{repo}/blob/{}/{}/{day}.md\n\n**{open} of {total}** findings discovered on {day} remain unresolved across **{}** package groups.\n\n",
        cfg.tracker_branch,
        cfg.report_dir,
        groups.len()
    );
    for (_, v) in &groups {
        let f = &v[0].finding;
        let done = v.iter().all(|t| t.status == Status::Resolved);
        let link = v[0].issue.as_ref().map(|i| format!(" — {}", i.url)).unwrap_or_default();
        let pr = v.iter().find_map(|t| t.pr.as_ref()).map(|p| format!(" · PR {}", p.url)).unwrap_or_default();
        let line = format!(
            "- [{}] `{}` {} `{}` ({} vulns, {}){link}{pr}\n",
            if done { "x" } else { " " },
            f.repo,
            f.ecosystem,
            f.package,
            v.len(),
            top_severity(v)
        );
        if body.len() + line.len() > 60_000 {
            body.push_str("- … (truncated; see the daily report)\n");
            break;
        }
        body.push_str(&line);
    }
    let title = format!("🛡️ vuln-sentinel {day}: {open}/{total} unresolved");
    if cfg.dry_run {
        tracing::info!("[dry-run] tracker {repo}: {title}");
        return Ok(());
    }
    let d = state.days.entry(day.to_string()).or_default();
    match d.tracker_issue {
        Some(n) => {
            let mut patch = json!({"title": title, "body": body});
            if close {
                patch["state"] = json!("closed");
                patch["state_reason"] = json!("completed");
            }
            gh.patch(&format!("/repos/{repo}/issues/{n}"), &patch).await?;
        }
        None => {
            let _ = gh.post_idempotent(&format!("/repos/{repo}/labels"), &json!({"name": LABEL, "color": "b60205"})).await;
            let v = gh.post(&format!("/repos/{repo}/issues"), &json!({"title": title, "body": body, "labels": [LABEL]})).await?;
            d.tracker_issue = v["number"].as_u64();
            if close {
                if let Some(n) = d.tracker_issue {
                    gh.patch(&format!("/repos/{repo}/issues/{n}"), &json!({"state": "closed", "state_reason": "completed"})).await?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;
    use chrono::Utc;

    fn t(vuln: &str, sev: &str, fixed: Option<&str>, status: Status) -> Tracked {
        Tracked {
            finding: Finding {
                repo: "me/a".into(),
                file: "package-lock.json".into(),
                ecosystem: "npm".into(),
                package: "undici".into(),
                version: "5.22.1".into(),
                vuln_id: vuln.into(),
                aliases: vec![],
                summary: "x | y".into(),
                severity: Some(sev.into()),
                fixed: fixed.map(str::to_string),
                new_today: false,
            },
            day: "2026-10-28".into(),
            status,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            resolved_at: None,
            issue: None,
            pr: None,
            fix_attempts: 0,
            note: None,
        }
    }

    #[test]
    fn grouping_helpers() {
        let a = t("GHSA-1", "MEDIUM", Some("5.28.5"), Status::Open);
        let b = t("GHSA-2", "HIGH", Some("6.29.1"), Status::Open);
        let c = t("GHSA-3", "CRITICAL", Some("7.0.0"), Status::Resolved);
        let items = vec![&a, &b, &c];
        assert_eq!(target_version(&items).as_deref(), Some("6.29.1"));
        assert_eq!(top_severity(&items), "CRITICAL");
        assert!(issue_title(&items).contains("2 known vulnerabilities"));
        let cfg = TicketCfg {
            dry_run: true,
            max_new: 1,
            tracker_repo: Some("me/ops".into()),
            tracker_branch: "main".into(),
            report_dir: "reports".into(),
        };
        let body = issue_body("me/a|npm|undici", &items, &cfg);
        assert!(body.starts_with("<!-- vuln-sentinel:me/a|npm|undici -->"));
        assert!(body.contains("x \\| y") && body.contains("me/ops/blob/main/reports/2026-10-28.md"));
    }
}
