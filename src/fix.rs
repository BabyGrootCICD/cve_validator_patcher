//! Automated remediation: bump vulnerable dependencies with each ecosystem's
//! native tooling, open one rolling PR per repository, and merge it once CI is
//! green (GitHub auto-merge when required checks exist; otherwise by
//! inspecting check runs ourselves).
use crate::github::GitHub;
use crate::model::cmp_versions;
use crate::repos::Repo;
use crate::scan::lockfiles;
use crate::state::{PrRef, State, Status, Tracked};
use crate::ticket::{target_version, top_severity};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

pub struct FixCfg {
    pub dry_run: bool,
    /// Merge fix PRs once CI passes.
    pub auto_merge: bool,
    /// Also merge PRs in repos that have no CI checks at all.
    pub merge_without_checks: bool,
    pub max_repos: usize,
    pub max_attempts: u32,
    /// Package groups attempted per repository per run (most severe first).
    pub max_groups_per_repo: usize,
    pub workdir: PathBuf,
    pub branch: String,
}

#[derive(Debug, Default)]
pub struct FixStats {
    pub repos_attempted: usize,
    pub groups_fixed: usize,
    pub groups_failed: usize,
    pub prs_opened: usize,
    pub prs_updated: usize,
    pub auto_merge_enabled: usize,
    pub merged: usize,
    pub dependabot_enabled: usize,
}

struct Group {
    key: String,
    ecosystem: String,
    package: String,
    target: String,
    /// lockfile path → vulnerable versions present in it
    files: BTreeMap<String, Vec<String>>,
    vulns: usize,
    severity: &'static str,
}

async fn sh(dir: &Path, prog: &str, args: &[&str]) -> Result<String> {
    tracing::debug!("{}$ {prog} {}", dir.display(), args.join(" "));
    let fut = Command::new(prog)
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("CI", "true")
        .env("npm_config_ignore_scripts", "true")
        .env("COMPOSER_NO_INTERACTION", "1")
        .env("GOFLAGS", "-mod=mod")
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(900), fut)
        .await
        .with_context(|| format!("{prog} timed out"))?
        .with_context(|| format!("cannot run {prog} (is it installed?)"))?;
    if !out.status.success() {
        let err = redact(&String::from_utf8_lossy(&out.stderr));
        bail!("{prog} {}: {}", args.join(" "), err.chars().rev().take(400).collect::<String>().chars().rev().collect::<String>());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Strip credentials embedded in clone URLs from tool output.
fn redact(s: &str) -> String {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"://[^/@\s]+@").unwrap()).replace_all(s, "://***@").into_owned()
}

/// Set `name` to `^target` in package.json: as a direct dependency if it is one,
/// otherwise via the package manager's override mechanism.
fn edit_package_json(path: &Path, name: &str, target: &str, override_key: &[&str]) -> Result<()> {
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let spec = format!("^{target}");
    let mut direct = false;
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(d) = v.get_mut(section).and_then(Value::as_object_mut) {
            if let Some(cur) = d.get_mut(name) {
                let s = cur.as_str().unwrap_or_default();
                if !s.starts_with("workspace:") && !s.starts_with("file:") && !s.starts_with("link:") {
                    *cur = json!(spec);
                }
                direct = true;
            }
        }
    }
    if !direct {
        let mut node = &mut v;
        for k in override_key {
            if !node.get(*k).map(Value::is_object).unwrap_or(false) {
                node[*k] = json!({});
            }
            node = node.get_mut(*k).expect("just inserted");
        }
        node[name] = json!(spec);
    }
    let original = std::fs::read_to_string(path)?;
    let indent: String = original
        .lines()
        .find(|l| l.starts_with([' ', '\t']))
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect())
        .unwrap_or_else(|| "  ".into());
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes()));
    serde::Serialize::serialize(&v, &mut ser)?;
    buf.push(b'\n');
    std::fs::write(path, buf)?;
    Ok(())
}

/// Rewrite `name==old` pins in a requirements file.
pub fn bump_requirements(content: &str, name: &str, target: &str) -> String {
    let norm = |s: &str| s.to_lowercase().replace(['_', '.'], "-");
    content
        .lines()
        .map(|l| {
            let Some((lhs, rhs)) = l.split_once("==") else { return l.to_string() };
            let pkg = lhs.split('[').next().unwrap_or(lhs).trim();
            if norm(pkg) != norm(name) {
                return l.to_string();
            }
            let tail_at = rhs.find([' ', ';', '#', ',']).unwrap_or(rhs.len());
            format!("{lhs}=={target}{}", &rhs[tail_at..])
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if content.ends_with('\n') { "\n" } else { "" }
}

/// Apply one package bump in one lockfile's directory.
async fn apply(root: &Path, file: &str, g: &Group, old: &[String]) -> Result<()> {
    let path = root.join(file);
    let dir = path.parent().unwrap_or(root).to_path_buf();
    let (name, target) = (g.package.as_str(), g.target.as_str());
    match lockfiles::kind(file).unwrap_or_default() {
        "cargo" => {
            for o in old {
                sh(&dir, "cargo", &["update", "-p", &format!("{name}@{o}"), "--precise", target]).await?;
            }
        }
        "npm" => {
            edit_package_json(&dir.join("package.json"), name, target, &["overrides"])?;
            sh(&dir, "npm", &["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]).await?;
        }
        "yarn" => {
            edit_package_json(&dir.join("package.json"), name, target, &["resolutions"])?;
            let berry = std::fs::read_to_string(&path)?.contains("__metadata:");
            if berry {
                sh(&dir, "yarn", &["install", "--mode=update-lockfile"]).await?;
            } else {
                sh(&dir, "yarn", &["install", "--ignore-scripts", "--non-interactive", "--ignore-engines"]).await?;
            }
        }
        "pnpm" => {
            edit_package_json(&dir.join("package.json"), name, target, &["pnpm", "overrides"])?;
            sh(&dir, "pnpm", &["install", "--lockfile-only", "--ignore-scripts"]).await?;
        }
        "go" => {
            sh(&dir, "go", &["get", &format!("{name}@{target}")]).await?;
            sh(&dir, "go", &["mod", "tidy"]).await?;
        }
        "requirements" => {
            let c = std::fs::read_to_string(&path)?;
            std::fs::write(&path, bump_requirements(&c, name, target))?;
        }
        "poetry" => {
            if sh(&dir, "poetry", &["update", "--lock", name]).await.is_err() || still_vulnerable(root, file, g, old) {
                sh(&dir, "poetry", &["add", "--lock", &format!("{name}>={target}")]).await?;
            }
        }
        "uv" => {
            sh(&dir, "uv", &["lock", "--upgrade-package", name]).await?;
            if still_vulnerable(root, file, g, old) {
                sh(&dir, "uv", &["add", "--no-sync", &format!("{name}>={target}")]).await?;
            }
        }
        "bundler" => {
            sh(&dir, "bundle", &["lock", "--update", name]).await?;
        }
        "composer" => {
            let flags = ["--no-install", "--no-scripts", "--no-plugins", "--ignore-platform-reqs"];
            let mut args = vec!["update", name, "--with-dependencies"];
            args.extend(flags);
            sh(&dir, "composer", &args).await?;
            if still_vulnerable(root, file, g, old) {
                let req = format!("{name}:^{target}");
                let mut args = vec!["require", req.as_str()];
                args.extend(flags);
                sh(&dir, "composer", &args).await?;
            }
        }
        "pub" => {
            sh(&dir, "dart", &["pub", "upgrade", name]).await?;
        }
        other => bail!("no automated fixer for {other} lockfiles"),
    }
    Ok(())
}

/// True if any of the vulnerable versions below the target remain in the lockfile.
fn still_vulnerable(root: &Path, file: &str, g: &Group, old: &[String]) -> bool {
    let Ok(c) = std::fs::read_to_string(root.join(file)) else { return true };
    lockfiles::parse(file, &c).iter().any(|d| {
        d.name.eq_ignore_ascii_case(&g.package)
            && old.iter().any(|o| o == &d.version)
            && cmp_versions(&d.version, &g.target) == Ordering::Less
    })
}

fn groups_for(repo: &str, items: &[&Tracked], max_attempts: u32) -> (Vec<Group>, Vec<String>) {
    let mut by: BTreeMap<String, Vec<&Tracked>> = BTreeMap::new();
    for t in items.iter().filter(|t| t.finding.repo == repo) {
        by.entry(t.group()).or_default().push(t);
    }
    let mut fixable = Vec::new();
    let mut unfixable = Vec::new();
    for (key, v) in by {
        let pending = v.iter().any(|t| t.status == Status::Open && t.fix_attempts < max_attempts);
        if !pending {
            continue;
        }
        let Some(target) = target_version(&v) else {
            unfixable.push(key);
            continue;
        };
        let mut files: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for t in v.iter().filter(|t| t.status != Status::Resolved) {
            let e = files.entry(t.finding.file.clone()).or_default();
            if !e.contains(&t.finding.version) {
                e.push(t.finding.version.clone());
            }
        }
        fixable.push(Group {
            key,
            ecosystem: v[0].finding.ecosystem.clone(),
            package: v[0].finding.package.clone(),
            target,
            files,
            vulns: v.iter().filter(|t| t.status != Status::Resolved).count(),
            severity: top_severity(&v),
        });
    }
    fixable.sort_by_key(|g| (std::cmp::Reverse(severity_rank(g.severity)), std::cmp::Reverse(g.vulns)));
    (fixable, unfixable)
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Whether the default branch requires status checks (classic protection or rulesets).
async fn has_required_checks(gh: &GitHub, repo: &Repo) -> bool {
    let b = &repo.default_branch;
    if let Ok(Some(v)) = gh.get_opt::<Value>(&format!("/repos/{}/branches/{b}/protection/required_status_checks", repo.full_name)).await {
        let n = v["checks"].as_array().map(Vec::len).unwrap_or(0) + v["contexts"].as_array().map(Vec::len).unwrap_or(0);
        if n > 0 {
            return true;
        }
    }
    if let Ok(Some(Value::Array(rules))) = gh.get_opt::<Value>(&format!("/repos/{}/rules/branches/{b}", repo.full_name)).await {
        return rules.iter().any(|r| r["type"] == "required_status_checks");
    }
    false
}

async fn enable_auto_merge(gh: &GitHub, repo: &Repo, pr_node_id: &str) -> Result<()> {
    if repo.admin {
        let _ = gh.patch(&format!("/repos/{}", repo.full_name), &json!({"allow_auto_merge": true})).await;
    }
    let q = "mutation($id: ID!, $m: PullRequestMergeMethod!) { enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: $m}) { clientMutationId } }";
    let mut last = None;
    for m in ["SQUASH", "MERGE", "REBASE"] {
        match gh.graphql(q, json!({"id": pr_node_id, "m": m})).await {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap())
}

/// Delegate to Dependabot where we cannot fix ourselves.
async fn enable_dependabot(gh: &GitHub, repo: &str) -> bool {
    let a = gh.put_status(&format!("/repos/{repo}/vulnerability-alerts")).await;
    let b = gh.put_status(&format!("/repos/{repo}/automated-security-fixes")).await;
    matches!((a, b), (Ok(x), Ok(y)) if x.is_success() && y.is_success())
}

fn note_group(state: &mut State, key: &str, note: String) {
    for t in state.group_mut(key) {
        if t.status != Status::Resolved {
            t.note = Some(note.clone());
        }
    }
}

pub async fn run(gh: &GitHub, state: &mut State, repos: &HashMap<String, Repo>, cfg: &FixCfg) -> Result<FixStats> {
    let mut stats = FixStats::default();
    let items: Vec<Tracked> = state.unresolved().cloned().collect();
    let refs: Vec<&Tracked> = items.iter().collect();
    let mut repo_names: Vec<&String> = refs.iter().filter(|t| t.status == Status::Open).map(|t| &t.finding.repo).collect();
    repo_names.sort();
    repo_names.dedup();

    for name in repo_names.into_iter().take(cfg.max_repos) {
        let Some(repo) = repos.get(name) else { continue };
        if repo.archived {
            continue;
        }
        let (mut groups, unfixable) = groups_for(name, &refs, cfg.max_attempts);
        groups.truncate(cfg.max_groups_per_repo);
        if !unfixable.is_empty() && !cfg.dry_run {
            let ok = enable_dependabot(gh, name).await;
            stats.dependabot_enabled += ok as usize;
            for k in &unfixable {
                note_group(
                    state,
                    k,
                    "No fixed release is published yet; Dependabot security updates enabled to pick one up automatically.".into(),
                );
            }
        }
        if groups.is_empty() {
            continue;
        }
        stats.repos_attempted += 1;
        if cfg.dry_run {
            for g in &groups {
                tracing::info!(
                    "[dry-run] {name}: bump {} {} → {} in {:?}",
                    g.ecosystem,
                    g.package,
                    g.target,
                    g.files.keys().collect::<Vec<_>>()
                );
            }
            continue;
        }
        match fix_repo(gh, state, repo, groups, cfg, &mut stats).await {
            Ok(()) => {}
            Err(e) => tracing::warn!("fix {name}: {e:#}"),
        }
    }
    Ok(stats)
}

async fn fix_repo(gh: &GitHub, state: &mut State, repo: &Repo, groups: Vec<Group>, cfg: &FixCfg, stats: &mut FixStats) -> Result<()> {
    let name = &repo.full_name;
    let dir = cfg.workdir.join(name.replace('/', "__"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&cfg.workdir)?;
    let owner = name.split('/').next().unwrap_or_default();
    let open_prs: Vec<Value> = gh.get(&format!("/repos/{name}/pulls?head={owner}:{}&state=open", cfg.branch)).await?;
    let existing = open_prs.into_iter().next();
    // Continue an open fix PR's branch; otherwise start fresh from the default branch.
    let base = if existing.is_some() { cfg.branch.as_str() } else { repo.default_branch.as_str() };
    let url = format!("https://x-access-token:{}@github.com/{name}.git", gh.token());
    sh(&cfg.workdir, "git", &["clone", "--quiet", "--depth", "1", "--branch", base, &url, &dir.display().to_string()]).await?;
    sh(&dir, "git", &["config", "user.name", "vuln-sentinel[bot]"]).await?;
    sh(&dir, "git", &["config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"]).await?;
    sh(&dir, "git", &["checkout", "-q", "-B", &cfg.branch]).await?;

    // (group key, lockfile) pairs that were fixed and committed.
    let mut fixed: Vec<(String, String)> = Vec::new();
    for g in &groups {
        for (file, old) in &g.files {
            let res = apply(&dir, file, g, old).await;
            let ok = !still_vulnerable(&dir, file, g, old);
            let changed = !sh(&dir, "git", &["status", "--porcelain"]).await?.trim().is_empty();
            if ok && changed {
                sh(&dir, "git", &["add", "-A"]).await?;
                let msg = format!("fix(deps): bump {} to {} in {file} ({} {})", g.package, g.target, g.ecosystem, g.severity);
                sh(&dir, "git", &["commit", "-q", "-m", &msg]).await?;
                fixed.push((g.key.clone(), file.clone()));
            } else {
                sh(&dir, "git", &["reset", "-q", "--hard"]).await?;
                sh(&dir, "git", &["clean", "-qfd"]).await?;
                let why = match res {
                    Err(e) => format!("{e:#}"),
                    Ok(()) => "the upgrade did not remove the vulnerable version (version constraint conflict)".into(),
                };
                let note = format!("Automatic upgrade to {} failed in `{file}`: {}", g.target, why.chars().take(400).collect::<String>());
                for t in state.group_mut(&g.key) {
                    if t.status == Status::Open && &t.finding.file == file {
                        t.note = Some(note.clone());
                    }
                }
            }
        }
        for t in state.group_mut(&g.key) {
            if t.status == Status::Open {
                t.fix_attempts += 1;
            }
        }
        if fixed.iter().any(|(k, _)| k == &g.key) {
            stats.groups_fixed += 1;
        } else {
            stats.groups_failed += 1;
        }
    }
    if fixed.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
        return Ok(());
    }
    sh(&dir, "git", &["push", "--quiet", "--force", "origin", &cfg.branch]).await?;
    let _ = std::fs::remove_dir_all(&dir);

    let pr: Value = match existing {
        Some(p) => {
            stats.prs_updated += 1;
            p
        }
        None => {
            stats.prs_opened += 1;
            gh.post(
                &format!("/repos/{name}/pulls"),
                &json!({"title": "fix(security): upgrade vulnerable dependencies", "head": cfg.branch, "base": repo.default_branch,
                    "body": "Preparing…", "maintainer_can_modify": true}),
            )
            .await?
        }
    };
    let number = pr["number"].as_u64().unwrap_or(0);
    let _ = gh.post(&format!("/repos/{name}/issues/{number}/labels"), &json!({"labels": [crate::ticket::LABEL, "security"]})).await;
    let mut auto = state
        .findings
        .values()
        .any(|t| t.pr.as_ref().map(|p| p.number == number && p.auto_merge).unwrap_or(false) && &t.finding.repo == name);
    if !auto && cfg.auto_merge && has_required_checks(gh, repo).await {
        match enable_auto_merge(gh, repo, pr["node_id"].as_str().unwrap_or_default()).await {
            Ok(()) => {
                auto = true;
                stats.auto_merge_enabled += 1;
            }
            Err(e) => tracing::warn!("auto-merge {name}#{number}: {e:#}"),
        }
    }
    let pr_ref = PrRef { number, url: pr["html_url"].as_str().unwrap_or_default().to_string(), auto_merge: auto };
    for (key, file) in &fixed {
        for t in state.group_mut(key) {
            if t.status == Status::Open && &t.finding.file == file {
                t.status = Status::FixProposed;
                t.pr = Some(pr_ref.clone());
                t.note = None;
            }
        }
    }
    let (title, body) = pr_text(state, name, number, auto);
    gh.patch(&format!("/repos/{name}/pulls/{number}"), &json!({"title": title, "body": body})).await?;
    Ok(())
}

/// PR title/body listing everything the PR currently fixes.
fn pr_text(state: &State, repo: &str, number: u64, auto: bool) -> (String, String) {
    let mut rows: BTreeMap<String, (String, String, String, usize, Option<u64>)> = BTreeMap::new();
    for t in state.findings.values() {
        if t.finding.repo != repo || t.status != Status::FixProposed || t.pr.as_ref().map(|p| p.number) != Some(number) {
            continue;
        }
        let f = &t.finding;
        let e =
            rows.entry(t.group()).or_insert((f.package.clone(), f.ecosystem.clone(), String::new(), 0, t.issue.as_ref().map(|i| i.number)));
        if let Some(fx) = &f.fixed {
            if e.2.is_empty() || cmp_versions(fx, &e.2) == Ordering::Greater {
                e.2 = fx.clone();
            }
        }
        e.3 += 1;
    }
    let mut body = String::from(
        "Automated security upgrades from **vuln-sentinel**.\n\n| Package | Ecosystem | Upgrade to | Vulns fixed |\n|---|---|---|---|\n",
    );
    for (pkg, eco, target, n, _) in rows.values() {
        let _ = writeln!(body, "| `{pkg}` | {eco} | `{target}` | {n} |");
    }
    body.push('\n');
    for (_, _, _, _, issue) in rows.values() {
        if let Some(n) = issue {
            let _ = writeln!(body, "Closes #{n}");
        }
    }
    body.push_str(if auto {
        "\nAuto-merge is enabled: this PR merges once the required checks pass."
    } else {
        "\nvuln-sentinel merges this PR once all CI checks pass. If the repository has no CI, it waits for a manual merge."
    });
    body.push_str(" Lockfiles were regenerated with each ecosystem's own tool, with install scripts disabled.\n");
    let n = rows.len();
    (format!("fix(security): upgrade {n} vulnerable dependenc{}", if n == 1 { "y" } else { "ies" }), body)
}

/// For open fix PRs: merge when CI is green (repos without required checks),
/// and return findings to `Open` when a PR was closed without merging.
pub async fn advance_prs(gh: &GitHub, state: &mut State, cfg: &FixCfg) -> Result<FixStats> {
    let mut stats = FixStats::default();
    let mut prs: BTreeMap<(String, u64), bool> = BTreeMap::new();
    for t in state.unresolved().filter(|t| t.status == Status::FixProposed) {
        if let Some(p) = &t.pr {
            prs.insert((t.finding.repo.clone(), p.number), p.auto_merge);
        }
    }
    for ((repo, number), auto) in prs {
        let pr: Value = match gh.get_opt(&format!("/repos/{repo}/pulls/{number}")).await? {
            Some(p) => p,
            None => continue,
        };
        let merged = pr["merged"].as_bool().unwrap_or(false);
        if pr["state"] == "closed" && !merged {
            for t in state.findings.values_mut() {
                if t.finding.repo == repo && t.pr.as_ref().map(|p| p.number) == Some(number) && t.status == Status::FixProposed {
                    t.status = Status::Open;
                    t.pr = None;
                    t.note = Some(format!("Fix PR #{number} was closed without merging."));
                }
            }
            continue;
        }
        if merged || auto || !cfg.auto_merge || cfg.dry_run {
            continue;
        }
        let sha = pr["head"]["sha"].as_str().unwrap_or_default();
        let runs: Value = gh.get(&format!("/repos/{repo}/commits/{sha}/check-runs?per_page=100")).await?;
        let runs = runs["check_runs"].as_array().cloned().unwrap_or_default();
        let statuses: Value = gh.get(&format!("/repos/{repo}/commits/{sha}/status")).await?;
        let legacy = statuses["statuses"].as_array().cloned().unwrap_or_default();
        let verdict = ci_verdict(&runs, &legacy, cfg.merge_without_checks);
        if verdict != Some(true) {
            if verdict == Some(false) {
                tracing::info!("{repo}#{number}: CI failing; leaving PR for review");
            }
            continue;
        }
        if pr["mergeable"] == false {
            continue;
        }
        for method in ["squash", "merge", "rebase"] {
            let r = gh.put_json(&format!("/repos/{repo}/pulls/{number}/merge"), &json!({"merge_method": method, "sha": sha})).await;
            if r.map(|s| s.is_success()).unwrap_or(false) {
                stats.merged += 1;
                let _ = gh.delete(&format!("/repos/{repo}/git/refs/heads/{}", cfg.branch)).await;
                break;
            }
        }
    }
    Ok(stats)
}

/// `Some(true)` = all CI green, `Some(false)` = something failed, `None` = pending / no CI.
pub fn ci_verdict(check_runs: &[Value], statuses: &[Value], merge_without_checks: bool) -> Option<bool> {
    if check_runs.is_empty() && statuses.is_empty() {
        return merge_without_checks.then_some(true);
    }
    for r in check_runs {
        if r["status"] != "completed" {
            return None;
        }
        match r["conclusion"].as_str() {
            Some("success" | "neutral" | "skipped") => {}
            _ => return Some(false),
        }
    }
    for s in statuses {
        match s["state"].as_str() {
            Some("success") => {}
            Some("pending") => return None,
            _ => return Some(false),
        }
    }
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_tokens() {
        assert_eq!(redact("fatal: https://x-access-token:ghp_abc@github.com/a/b"), "fatal: https://***@github.com/a/b");
    }

    #[test]
    fn requirements_bump_keeps_markers() {
        let c = "Django==4.2.1 ; python_version > '3'\nflask==2.0.0\nrequests_toolbelt==0.9.1  # pinned\n";
        let out = bump_requirements(c, "requests-toolbelt", "1.0.0");
        assert_eq!(out, "Django==4.2.1 ; python_version > '3'\nflask==2.0.0\nrequests_toolbelt==1.0.0  # pinned\n");
        assert!(bump_requirements(c, "django", "4.2.9").starts_with("Django==4.2.9 ;"));
    }

    #[test]
    fn package_json_direct_and_override() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("package.json");
        std::fs::write(&p, "{\n  \"name\": \"x\",\n  \"dependencies\": {\n    \"undici\": \"^5.0.0\"\n  }\n}\n").unwrap();
        edit_package_json(&p, "undici", "6.29.1", &["overrides"]).unwrap();
        edit_package_json(&p, "minimist", "1.2.8", &["pnpm", "overrides"]).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["dependencies"]["undici"], "^6.29.1");
        assert_eq!(v["pnpm"]["overrides"]["minimist"], "^1.2.8");
        assert!(std::fs::read_to_string(&p).unwrap().starts_with("{\n  \"name\""));
    }

    #[test]
    fn ci_verdicts() {
        let ok = json!({"status":"completed","conclusion":"success"});
        let bad = json!({"status":"completed","conclusion":"failure"});
        let pending = json!({"status":"in_progress"});
        assert_eq!(ci_verdict(std::slice::from_ref(&ok), &[], false), Some(true));
        assert_eq!(ci_verdict(&[ok.clone(), bad], &[], false), Some(false));
        assert_eq!(ci_verdict(&[ok, pending], &[], false), None);
        assert_eq!(ci_verdict(&[], &[], false), None);
        assert_eq!(ci_verdict(&[], &[], true), Some(true));
        assert_eq!(ci_verdict(&[], &[json!({"state":"pending"})], false), None);
    }
}
