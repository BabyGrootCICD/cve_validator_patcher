use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

/// A package coordinate in OSV ecosystem terms (`crates.io`, `npm`, `PyPI`, `Go`, ...).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PkgRef {
    pub ecosystem: String,
    pub name: String,
}

/// One advisory as collected from any intel source. Records from different
/// sources describing the same issue are merged by [`dedupe`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub aliases: BTreeSet<String>,
    pub sources: BTreeSet<String>,
    pub title: String,
    pub published: Option<DateTime<Utc>>,
    pub severity: Option<String>,
    pub score: Option<f64>,
    pub url: Option<String>,
    pub packages: BTreeSet<PkgRef>,
    pub cwes: BTreeSet<String>,
    pub owasp: BTreeSet<String>,
    pub exploits: BTreeSet<String>,
}

impl Advisory {
    pub fn new(source: &str, id: impl Into<String>) -> Self {
        let mut a = Advisory { id: id.into(), ..Default::default() };
        a.sources.insert(source.to_string());
        a
    }

    /// The id plus every alias.
    pub fn all_ids(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.id).chain(self.aliases.iter())
    }

    fn absorb(&mut self, other: Advisory) {
        if other.id != self.id {
            self.aliases.insert(other.id);
        }
        self.aliases.extend(other.aliases);
        self.aliases.remove(&self.id.clone());
        self.sources.extend(other.sources);
        if self.title.is_empty() {
            self.title = other.title;
        }
        self.published = match (self.published, other.published) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if self.score.unwrap_or(0.0) < other.score.unwrap_or(0.0) {
            self.score = other.score;
            self.severity = other.severity.or(self.severity.take());
        } else if self.severity.is_none() {
            self.severity = other.severity;
        }
        if self.url.is_none() {
            self.url = other.url;
        }
        self.packages.extend(other.packages);
        self.cwes.extend(other.cwes);
        self.owasp.extend(other.owasp);
        self.exploits.extend(other.exploits);
    }
}

/// Preference order for the primary id of a merged advisory.
fn id_rank(id: &str) -> u8 {
    match id.split('-').next().unwrap_or("") {
        "CVE" => 0,
        "GHSA" => 1,
        "EUVD" => 3,
        "SPLOITUS" | "AKB" | "VULNERS" => 9,
        _ => 2,
    }
}

/// Merge advisories that share any id or alias (transitively).
pub fn dedupe(input: Vec<Advisory>) -> Vec<Advisory> {
    let n = input.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], mut i: usize) -> usize {
        while p[i] != i {
            p[i] = p[p[i]];
            i = p[i];
        }
        i
    }
    let mut owner: HashMap<String, usize> = HashMap::new();
    for (i, a) in input.iter().enumerate() {
        for id in a.all_ids() {
            match owner.get(id) {
                Some(&j) => {
                    let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                    if ri != rj {
                        parent[ri] = rj;
                    }
                }
                None => {
                    owner.insert(id.clone(), i);
                }
            }
        }
    }
    let mut groups: HashMap<usize, Vec<Advisory>> = HashMap::new();
    for (i, a) in input.into_iter().enumerate() {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(a);
    }
    let mut out: Vec<Advisory> = groups
        .into_values()
        .map(|mut g| {
            g.sort_by_key(|a| (id_rank(&a.id), a.id.clone()));
            let mut it = g.into_iter();
            let mut head = it.next().expect("non-empty group");
            for a in it {
                head.absorb(a);
            }
            head
        })
        .collect();
    out.sort_by(|a, b| {
        b.score
            .unwrap_or(0.0)
            .partial_cmp(&a.score.unwrap_or(0.0))
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// Map a CVSS base score to a qualitative severity.
pub fn severity_from_score(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        s if s > 0.0 => "LOW",
        _ => "NONE",
    }
}

/// A dependency found in a repository lockfile/manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dep {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub file: String,
}

/// A vulnerable dependency in a repository.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub repo: String,
    pub file: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub vuln_id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Option<String>,
    pub fixed: Option<String>,
    pub new_today: bool,
}

impl Finding {
    /// Stable identity used for state tracking and issue markers.
    pub fn key(&self) -> String {
        format!("{}:{}:{}:{}:{}", self.repo, self.file, self.ecosystem, self.package, self.vuln_id)
    }
}

/// Loose version comparison that works well enough across semver, PEP 440-ish,
/// Go (`v1.2.3`), and Maven-style dotted versions. Numeric segments compare
/// numerically; a pre-release suffix sorts before the release.
pub fn cmp_versions(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (Vec<String>, Option<String>) {
        let v = v.trim().trim_start_matches(['v', 'V', '=']);
        let v = v.split('+').next().unwrap_or(v);
        let (core, pre) = match v.find(|c: char| c == '-' || c.is_ascii_alphabetic()) {
            Some(i) => (&v[..i], Some(v[i..].trim_start_matches('-').to_string())),
            None => (v, None),
        };
        (core.split(['.', '_']).filter(|s| !s.is_empty()).map(str::to_string).collect(), pre)
    }
    let (ca, pa) = split(a);
    let (cb, pb) = split(b);
    for i in 0..ca.len().max(cb.len()) {
        let x = ca.get(i).map(String::as_str).unwrap_or("0");
        let y = cb.get(i).map(String::as_str).unwrap_or("0");
        let o = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(&y),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert_eq!(cmp_versions("1.2.10", "1.2.9"), Ordering::Greater);
        assert_eq!(cmp_versions("v1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp_versions("1.2.3-rc1", "1.2.3"), Ordering::Less);
        assert_eq!(cmp_versions("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(cmp_versions("2.0.0", "10.0.0"), Ordering::Less);
    }

    #[test]
    fn dedupe_merges_transitively() {
        let mut a = Advisory::new("NVD", "CVE-2026-1");
        a.score = Some(9.8);
        let mut b = Advisory::new("GHSA", "GHSA-xxxx");
        b.aliases.insert("CVE-2026-1".into());
        let mut c = Advisory::new("EUVD", "EUVD-2026-5");
        c.aliases.insert("GHSA-xxxx".into());
        let d = Advisory::new("NVD", "CVE-2026-2");
        let out = dedupe(vec![c, b, a, d]);
        assert_eq!(out.len(), 2);
        let m = &out[0];
        assert_eq!(m.id, "CVE-2026-1");
        assert!(m.aliases.contains("GHSA-xxxx") && m.aliases.contains("EUVD-2026-5"));
        assert_eq!(m.sources.len(), 3);
    }
}
