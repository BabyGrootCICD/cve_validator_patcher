//! Batch-match dependencies against OSV and compute the minimal fixed version.
use crate::model::{cmp_versions, Dep, Finding};
use anyhow::Result;
use futures::{stream, StreamExt};
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

const BATCH: usize = 1000;

fn query_version(d: &Dep) -> String {
    if d.ecosystem == "Go" {
        d.version.trim_start_matches('v').to_string()
    } else {
        d.version.clone()
    }
}

pub async fn match_deps(http: &reqwest::Client, deps: &[(String, Dep)], today_ids: &HashSet<String>) -> Result<Vec<Finding>> {
    // Query each unique (ecosystem, name, version) once.
    let mut uniq: Vec<(String, String, String)> =
        deps.iter().map(|(_, d)| (d.ecosystem.clone(), d.name.clone(), query_version(d))).collect();
    uniq.sort();
    uniq.dedup();
    let mut hits: HashMap<(String, String, String), Vec<String>> = HashMap::new();
    for chunk in uniq.chunks(BATCH) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|(e, n, v)| json!({"package": {"ecosystem": e, "name": n}, "version": v}))
            .collect();
        let resp: Value = http
            .post("https://api.osv.dev/v1/querybatch")
            .json(&json!({ "queries": queries }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        for (q, r) in chunk.iter().zip(resp["results"].as_array().into_iter().flatten()) {
            let ids: Vec<String> =
                r["vulns"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str().map(str::to_string)).collect();
            if !ids.is_empty() {
                hits.insert(q.clone(), ids);
            }
        }
    }
    let mut ids: Vec<&String> = hits.values().flatten().collect();
    ids.sort();
    ids.dedup();
    let details: HashMap<String, Value> = stream::iter(ids)
        .map(|id| async move {
            let v = http.get(format!("https://api.osv.dev/v1/vulns/{id}")).send().await.ok()?.json::<Value>().await.ok()?;
            Some((id.clone(), v))
        })
        .buffer_unordered(24)
        .filter_map(|x| async { x })
        .collect()
        .await;

    let mut out = Vec::new();
    for (repo, d) in deps {
        let key = (d.ecosystem.clone(), d.name.clone(), query_version(d));
        for id in hits.get(&key).into_iter().flatten() {
            let v = details.get(id).cloned().unwrap_or(Value::Null);
            if v["withdrawn"].is_string() {
                continue;
            }
            let aliases: Vec<String> =
                v["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
            let new_today = today_ids.contains(id) || aliases.iter().any(|a| today_ids.contains(a));
            out.push(Finding {
                repo: repo.clone(),
                file: d.file.clone(),
                ecosystem: d.ecosystem.clone(),
                package: d.name.clone(),
                version: d.version.clone(),
                vuln_id: id.clone(),
                aliases,
                summary: v["summary"].as_str().or(v["details"].as_str()).unwrap_or_default().lines().next().unwrap_or_default().to_string(),
                severity: crate::feeds::osv::osv_severity(&v),
                fixed: fixed_version(&v, d),
                new_today,
            });
        }
    }
    Ok(out)
}

fn same_pkg(eco: &str, a: &str, b: &str) -> bool {
    if eco == "PyPI" {
        let norm = |s: &str| s.to_lowercase().replace(['_', '.'], "-");
        norm(a) == norm(b)
    } else {
        a == b
    }
}

/// Smallest `fixed` event above the installed version among ranges that
/// contain it. `None` if no fix exists (or only `last_affected` is known).
pub fn fixed_version(vuln: &Value, dep: &Dep) -> Option<String> {
    let installed = query_version(dep);
    let mut best: Option<String> = None;
    for aff in vuln["affected"].as_array().into_iter().flatten() {
        let eco = aff["package"]["ecosystem"].as_str().unwrap_or_default();
        let name = aff["package"]["name"].as_str().unwrap_or_default();
        if eco.split(':').next() != Some(dep.ecosystem.as_str()) || !same_pkg(&dep.ecosystem, name, &dep.name) {
            continue;
        }
        for range in aff["ranges"].as_array().into_iter().flatten() {
            if range["type"] == "GIT" {
                continue;
            }
            let mut introduced: Option<String> = None;
            for ev in range["events"].as_array().into_iter().flatten() {
                if let Some(i) = ev["introduced"].as_str() {
                    introduced = Some(i.to_string());
                }
                if let Some(f) = ev["fixed"].as_str() {
                    let intro_ok = introduced
                        .as_deref()
                        .map(|i| i == "0" || cmp_versions(i, &installed) != Ordering::Greater)
                        .unwrap_or(true);
                    if intro_ok && cmp_versions(f, &installed) == Ordering::Greater {
                        let better = best.as_deref().map(|b| cmp_versions(f, b) == Ordering::Less).unwrap_or(true);
                        if better {
                            best = Some(f.to_string());
                        }
                    }
                    introduced = None;
                }
            }
        }
    }
    best.map(|b| if dep.ecosystem == "Go" && !b.starts_with('v') { format!("v{b}") } else { b })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(eco: &str, name: &str, v: &str) -> Dep {
        Dep { ecosystem: eco.into(), name: name.into(), version: v.into(), file: "x".into() }
    }

    #[test]
    fn picks_fix_in_matching_range() {
        let v = json!({"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[
            {"introduced":"0"},{"fixed":"3.0.0"},{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]});
        assert_eq!(fixed_version(&v, &dep("npm", "lodash", "4.17.20")).as_deref(), Some("4.17.21"));
        assert_eq!(fixed_version(&v, &dep("npm", "lodash", "2.0.0")).as_deref(), Some("3.0.0"));
        assert_eq!(fixed_version(&v, &dep("npm", "other", "2.0.0")), None);
    }

    #[test]
    fn go_and_pypi_normalisation() {
        let v = json!({"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[
            {"introduced":"0"},{"fixed":"0.23.0"}]}]},
            {"package":{"ecosystem":"PyPI","name":"Jinja2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.3"}]}]}]});
        assert_eq!(fixed_version(&v, &dep("Go", "golang.org/x/net", "v0.17.0")).as_deref(), Some("v0.23.0"));
        assert_eq!(fixed_version(&v, &dep("PyPI", "jinja2", "3.1.2")).as_deref(), Some("3.1.3"));
    }

    #[test]
    fn no_fix_when_only_last_affected() {
        let v = json!({"affected":[{"package":{"ecosystem":"npm","name":"x"},"ranges":[{"type":"SEMVER","events":[
            {"introduced":"0"},{"last_affected":"1.0.0"}]}]}]});
        assert_eq!(fixed_version(&v, &dep("npm", "x", "1.0.0")), None);
    }
}
