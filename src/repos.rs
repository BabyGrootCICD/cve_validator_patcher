//! Enumerate repositories owned by the authenticated user and the
//! organizations they belong to.
use crate::github::GitHub;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    pub full_name: String,
    pub default_branch: String,
    pub archived: bool,
    pub fork: bool,
    pub private: bool,
    pub has_issues: bool,
    pub admin: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RepoFilter {
    /// Restrict to these owners (user or org logins); empty = all.
    pub owners: Vec<String>,
    /// Restrict to these exact `owner/name`s; empty = all.
    pub only: Vec<String>,
    pub include_forks: bool,
    pub include_archived: bool,
    pub exclude: Vec<String>,
    pub limit: Option<usize>,
}

pub async fn list(gh: &GitHub, f: &RepoFilter) -> Result<Vec<Repo>> {
    let raw = gh
        .paginate("/user/repos?affiliation=owner,organization_member&per_page=100&sort=full_name", None, 100)
        .await?;
    let mut repos: Vec<Repo> = raw
        .iter()
        .filter_map(|r| {
            Some(Repo {
                full_name: r["full_name"].as_str()?.to_string(),
                default_branch: r["default_branch"].as_str().unwrap_or("main").to_string(),
                archived: r["archived"].as_bool().unwrap_or(false),
                fork: r["fork"].as_bool().unwrap_or(false),
                private: r["private"].as_bool().unwrap_or(true),
                has_issues: r["has_issues"].as_bool().unwrap_or(true),
                admin: r["permissions"]["admin"].as_bool().unwrap_or(false),
            })
        })
        .filter(|r| keep(r, f))
        .collect();
    repos.sort_by_key(|r| r.full_name.to_lowercase());
    repos.dedup_by(|a, b| a.full_name == b.full_name);
    if let Some(n) = f.limit {
        repos.truncate(n);
    }
    Ok(repos)
}

fn keep(r: &Repo, f: &RepoFilter) -> bool {
    let owner = r.full_name.split('/').next().unwrap_or_default();
    (f.include_archived || !r.archived)
        && (f.include_forks || !r.fork)
        && (f.owners.is_empty() || f.owners.iter().any(|o| o.eq_ignore_ascii_case(owner)))
        && (f.only.is_empty() || f.only.iter().any(|o| o.eq_ignore_ascii_case(&r.full_name)))
        && !f.exclude.iter().any(|o| o.eq_ignore_ascii_case(&r.full_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(name: &str, archived: bool, fork: bool) -> Repo {
        Repo { full_name: name.into(), default_branch: "main".into(), archived, fork, private: false, has_issues: true, admin: true }
    }

    #[test]
    fn filtering() {
        let f = RepoFilter { owners: vec!["Org".into()], ..Default::default() };
        assert!(keep(&repo("org/a", false, false), &f));
        assert!(!keep(&repo("org/a", true, false), &f));
        assert!(!keep(&repo("org/a", false, true), &f));
        assert!(!keep(&repo("me/a", false, false), &f));
        let f = RepoFilter { include_forks: true, exclude: vec!["me/b".into()], ..Default::default() };
        assert!(keep(&repo("me/a", false, true), &f));
        assert!(!keep(&repo("me/b", false, false), &f));
    }
}
