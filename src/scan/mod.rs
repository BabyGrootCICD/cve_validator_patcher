//! Repository exposure scanning: find lockfiles via the git tree API, parse
//! dependencies and match them against OSV.
pub mod lockfiles;
pub mod osv_match;

use crate::github::GitHub;
use crate::model::{Dep, Finding};
use crate::repos::Repo;
use anyhow::Result;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

const MAX_LOCKFILES_PER_REPO: usize = 60;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    pub repos_scanned: usize,
    pub repos_with_lockfiles: usize,
    pub dependencies: usize,
    pub errors: Vec<String>,
    pub findings: Vec<Finding>,
}

/// List dependency files on the default branch and parse them.
pub async fn repo_deps(gh: &GitHub, repo: &Repo) -> Result<Vec<Dep>> {
    let tree: Option<Value> = gh.get_opt(&format!("/repos/{}/git/trees/{}?recursive=1", repo.full_name, repo.default_branch)).await?;
    let Some(tree) = tree else { return Ok(vec![]) }; // empty repository
    let paths: Vec<String> = tree["tree"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["type"] == "blob")
        .filter_map(|e| e["path"].as_str())
        .filter(|p| lockfiles::kind(p).is_some())
        .take(MAX_LOCKFILES_PER_REPO)
        .map(str::to_string)
        .collect();
    let mut deps = Vec::new();
    for p in paths {
        if let Some(content) = gh.raw_file(&repo.full_name, &p, &repo.default_branch).await? {
            deps.extend(lockfiles::parse(&p, &content));
        }
    }
    Ok(deps)
}

/// Scan repositories concurrently. `today_ids` marks findings whose vuln (or
/// alias) was among today's collected advisories.
pub async fn scan(gh: &GitHub, http: &reqwest::Client, repos: &[Repo], today_ids: &HashSet<String>, concurrency: usize) -> ScanResult {
    let per_repo: Vec<(String, Result<Vec<Dep>>)> = stream::iter(repos.iter())
        .map(|r| async move { (r.full_name.clone(), repo_deps(gh, r).await) })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    let mut res = ScanResult { repos_scanned: repos.len(), ..Default::default() };
    let mut all: Vec<(String, Dep)> = Vec::new();
    for (name, r) in per_repo {
        match r {
            Ok(deps) => {
                if !deps.is_empty() {
                    res.repos_with_lockfiles += 1;
                }
                all.extend(deps.into_iter().map(|d| (name.clone(), d)));
            }
            Err(e) => res.errors.push(format!("{name}: {e:#}")),
        }
    }
    res.dependencies = all.len();
    match osv_match::match_deps(http, &all, today_ids).await {
        Ok(f) => res.findings = f,
        Err(e) => res.errors.push(format!("osv match: {e:#}")),
    }
    res.findings.sort_by_key(|f| f.key());
    res
}
