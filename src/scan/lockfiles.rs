//! Dependency extraction from lockfiles and pinned manifests.
use crate::model::Dep;
use serde_json::Value;

/// Returns the parser ecosystem for a path, if we understand that file.
pub fn kind(path: &str) -> Option<&'static str> {
    if path.split('/').any(|seg| matches!(seg, "node_modules" | "vendor" | ".git" | "target" | "dist")) {
        return None;
    }
    let file = path.rsplit('/').next().unwrap_or(path);
    Some(match file {
        "Cargo.lock" => "cargo",
        "package-lock.json" | "npm-shrinkwrap.json" => "npm",
        "yarn.lock" => "yarn",
        "pnpm-lock.yaml" => "pnpm",
        "go.mod" => "go",
        "poetry.lock" => "poetry",
        "uv.lock" => "uv",
        "Pipfile.lock" => "pipfile",
        "Gemfile.lock" => "bundler",
        "composer.lock" => "composer",
        "pubspec.lock" => "pub",
        f if f.starts_with("requirements") && f.ends_with(".txt") => "requirements",
        _ => return None,
    })
}

pub fn parse(path: &str, content: &str) -> Vec<Dep> {
    let Some(k) = kind(path) else { return vec![] };
    let raw: Vec<(&str, String, String)> = match k {
        "cargo" => toml_packages(content, true).into_iter().map(|(n, v)| ("crates.io", n, v)).collect(),
        "poetry" | "uv" => toml_packages(content, false).into_iter().map(|(n, v)| ("PyPI", n, v)).collect(),
        "npm" => npm(content).into_iter().map(|(n, v)| ("npm", n, v)).collect(),
        "yarn" => yarn(content).into_iter().map(|(n, v)| ("npm", n, v)).collect(),
        "pnpm" => pnpm(content).into_iter().map(|(n, v)| ("npm", n, v)).collect(),
        "go" => gomod(content).into_iter().map(|(n, v)| ("Go", n, v)).collect(),
        "pipfile" => pipfile(content).into_iter().map(|(n, v)| ("PyPI", n, v)).collect(),
        "requirements" => requirements(content).into_iter().map(|(n, v)| ("PyPI", n, v)).collect(),
        "bundler" => gemfile(content).into_iter().map(|(n, v)| ("RubyGems", n, v)).collect(),
        "composer" => composer(content).into_iter().map(|(n, v)| ("Packagist", n, v)).collect(),
        "pub" => pubspec(content).into_iter().map(|(n, v)| ("Pub", n, v)).collect(),
        _ => vec![],
    };
    let mut deps: Vec<Dep> = raw
        .into_iter()
        .filter(|(_, n, v)| !n.is_empty() && !v.is_empty())
        .map(|(e, name, version)| Dep { ecosystem: e.into(), name, version, file: path.into() })
        .collect();
    deps.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    deps.dedup();
    deps
}

fn toml_packages(content: &str, registry_only: bool) -> Vec<(String, String)> {
    let Ok(v) = content.parse::<toml::Table>() else { return vec![] };
    v.get("package")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter(|p| !registry_only || p.get("source").and_then(|s| s.as_str()).map(|s| s.starts_with("registry+")).unwrap_or(false))
        .filter(|p| {
            // uv.lock marks workspace members with `source = { editable/virtual = ... }`
            !p.get("source").and_then(|s| s.as_table()).map(|t| t.contains_key("editable") || t.contains_key("virtual")).unwrap_or(false)
        })
        .filter_map(|p| Some((p.get("name")?.as_str()?.to_string(), p.get("version")?.as_str()?.to_string())))
        .collect()
}

fn npm(content: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<Value>(content) else { return vec![] };
    let mut out = Vec::new();
    if let Some(pkgs) = v["packages"].as_object() {
        for (path, p) in pkgs {
            let Some(idx) = path.rfind("node_modules/") else { continue };
            if p["link"] == true {
                continue;
            }
            let name = p["name"].as_str().map(str::to_string).unwrap_or_else(|| path[idx + 13..].to_string());
            if let Some(ver) = p["version"].as_str() {
                out.push((name, ver.to_string()));
            }
        }
    } else {
        fn walk(deps: &Value, out: &mut Vec<(String, String)>) {
            for (name, d) in deps.as_object().into_iter().flatten() {
                if let Some(v) = d["version"].as_str() {
                    out.push((name.clone(), v.to_string()));
                }
                walk(&d["dependencies"], out);
            }
        }
        walk(&v["dependencies"], &mut out);
    }
    out
}

/// Split `@scope/name@range` / `name@npm:x@range` into the package name.
fn yarn_name(spec: &str) -> &str {
    let spec = spec.trim().trim_matches('"');
    let at = if let Some(rest) = spec.strip_prefix('@') { rest.find('@').map(|i| i + 1) } else { spec.find('@') };
    at.map(|i| &spec[..i]).unwrap_or(spec)
}

fn yarn(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            current = line.trim_end_matches(':').split(", ").next().map(|s| yarn_name(s).to_string());
            if current.as_deref() == Some("__metadata") {
                current = None;
            }
            continue;
        }
        let t = line.trim();
        let ver = t.strip_prefix("version ").or_else(|| t.strip_prefix("version: "));
        if let (Some(name), Some(v)) = (&current, ver) {
            out.push((name.clone(), v.trim_matches('"').to_string()));
        }
    }
    out
}

fn pnpm(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for line in content.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_packages = line.trim_end() == "packages:" || line.trim_end() == "snapshots:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let key = line.trim().trim_end_matches(':').trim_matches(|c| c == '\'' || c == '"');
        let key = key.split('(').next().unwrap_or(key); // peer suffixes: name@1.0.0(react@18)
        let key = key.strip_prefix('/').unwrap_or(key);
        // v6+: name@ver, v5: name/ver
        // Skip a scope prefix (`@scope/`), then the first `@` or `/` ends the name.
        let name_start = if key.starts_with('@') { key.find('/').map(|i| i + 1).unwrap_or(key.len()) } else { 0 };
        let split = key[name_start..].find(['@', '/']).map(|i| i + name_start);
        if let Some(i) = split {
            let (n, v) = (&key[..i], &key[i + 1..]);
            if v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                out.push((n.to_string(), v.split('_').next().unwrap_or(v).to_string()));
            }
        }
    }
    out
}

fn gomod(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let l = line.split("//").next().unwrap_or("").trim();
        if l.starts_with("require (") {
            in_block = true;
            continue;
        }
        if in_block && l == ")" {
            in_block = false;
            continue;
        }
        let spec = if in_block { Some(l) } else { l.strip_prefix("require ") };
        if let Some(s) = spec {
            let mut it = s.split_whitespace();
            if let (Some(m), Some(v)) = (it.next(), it.next()) {
                out.push((m.to_string(), v.trim_end_matches("+incompatible").to_string()));
            }
        }
    }
    out
}

fn pipfile(content: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<Value>(content) else { return vec![] };
    ["default", "develop"]
        .iter()
        .flat_map(|s| v[*s].as_object().cloned().unwrap_or_default())
        .filter_map(|(n, d)| Some((n, d["version"].as_str()?.trim_start_matches("==").to_string())))
        .collect()
}

fn requirements(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.split(';').next()?.trim();
            let (name, ver) = l.split_once("==")?;
            let name = name.split('[').next()?.trim();
            let ver = ver.split([',', ' ']).next()?.trim();
            (!name.is_empty() && !name.starts_with('-')).then(|| (name.to_string(), ver.to_string()))
        })
        .collect()
}

fn gemfile(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_specs = false;
    for line in content.lines() {
        if !line.starts_with(' ') {
            in_specs = false;
        }
        if line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        // exactly 4 spaces = a resolved gem; 6 = its requirements
        if in_specs && line.starts_with("    ") && !line.starts_with("     ") {
            if let Some((n, rest)) = line.trim().split_once(" (") {
                let v = rest.trim_end_matches(')');
                let v = v.split('-').next().unwrap_or(v); // platform suffix: 1.2.3-x86_64-linux
                out.push((n.to_string(), v.to_string()));
            }
        }
    }
    out
}

fn composer(content: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<Value>(content) else { return vec![] };
    ["packages", "packages-dev"]
        .iter()
        .flat_map(|k| v[*k].as_array().cloned().unwrap_or_default())
        .filter_map(|p| Some((p["name"].as_str()?.to_string(), p["version"].as_str()?.trim_start_matches('v').to_string())))
        .filter(|(_, v)| !v.starts_with("dev-"))
        .collect()
}

fn pubspec(content: &str) -> Vec<(String, String)> {
    // sdk/path packages are included too; they simply produce no OSV matches.
    let mut out = Vec::new();
    let mut in_packages = false;
    let mut current: Option<String> = None;
    for line in content.lines() {
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        if line.starts_with("  ") && !line.starts_with("   ") {
            current = Some(line.trim().trim_end_matches(':').trim_matches('"').to_string());
        } else if let Some(v) = line.trim().strip_prefix("version: ") {
            if let Some(n) = current.take() {
                out.push((n, v.trim_matches('"').to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(path: &str, content: &str) -> Vec<String> {
        parse(path, content).into_iter().map(|d| format!("{}@{}", d.name, d.version)).collect()
    }

    #[test]
    fn skips_vendored_paths() {
        assert_eq!(kind("node_modules/x/package-lock.json"), None);
        assert_eq!(kind("svc/requirements-dev.txt"), Some("requirements"));
    }

    #[test]
    fn cargo_lock() {
        let c = r#"
[[package]]
name = "mycrate"
version = "0.1.0"

[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        assert_eq!(names("Cargo.lock", c), vec!["tokio@1.0.0"]);
    }

    #[test]
    fn npm_v3_and_v1() {
        let v3 = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},
            "node_modules/a/node_modules/@s/b":{"version":"1.0.0"},"node_modules/local":{"link":true}}}"#;
        assert_eq!(names("package-lock.json", v3), vec!["@s/b@1.0.0", "lodash@4.17.20"]);
        let v1 = r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}"#;
        assert_eq!(names("package-lock.json", v1), vec!["a@1.0.0", "b@2.0.0"]);
    }

    #[test]
    fn yarn_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.2.0\"\n  resolved \"x\"\n\nlodash@^4.17.0:\n  version \"4.17.20\"\n";
        assert_eq!(names("yarn.lock", classic), vec!["@babel/core@7.2.0", "lodash@4.17.20"]);
        let berry = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n";
        assert_eq!(names("yarn.lock", berry), vec!["lodash@4.17.21"]);
    }

    #[test]
    fn pnpm_versions() {
        let c = "lockfileVersion: '9.0'\n\npackages:\n\n  '@types/node@20.1.0':\n    resolution: {}\n\n  lodash@4.17.20:\n    resolution: {}\n\nsnapshots:\n\n  react-dom@18.2.0(react@18.2.0):\n    dependencies: {}\n";
        assert_eq!(names("pnpm-lock.yaml", c), vec!["@types/node@20.1.0", "lodash@4.17.20", "react-dom@18.2.0"]);
        let v5 = "packages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@scope/pkg/1.0.0_react@18:\n    dev: false\n";
        assert_eq!(names("pnpm-lock.yaml", v5), vec!["@scope/pkg@1.0.0", "lodash@4.17.20"]);
    }

    #[test]
    fn go_mod() {
        let c = "module x\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/c/d v2.0.0+incompatible\n)\n";
        assert_eq!(names("go.mod", c), vec!["github.com/a/b@v1.2.3", "github.com/c/d@v2.0.0", "golang.org/x/net@v0.17.0"]);
    }

    #[test]
    fn python_files() {
        let req = "# c\nDjango[argon2]==4.2.1 ; python_version>'3'\nrequests>=2\n-r other.txt\nflask==2.0.0 # pin\n";
        assert_eq!(names("requirements.txt", req), vec!["Django@4.2.1", "flask@2.0.0"]);
        let pip = r#"{"default":{"requests":{"version":"==2.25.0"}},"develop":{"pytest":{"version":"==7.0.0"}}}"#;
        assert_eq!(names("Pipfile.lock", pip), vec!["pytest@7.0.0", "requests@2.25.0"]);
        let poetry = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.2\"\n";
        assert_eq!(names("poetry.lock", poetry), vec!["jinja2@3.1.2"]);
    }

    #[test]
    fn ruby_php_dart() {
        let gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n";
        assert_eq!(names("Gemfile.lock", gem), vec!["nokogiri@1.15.0", "rack@2.2.3"]);
        let comp = r#"{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.0"}],"packages-dev":[{"name":"x/y","version":"dev-main"}]}"#;
        assert_eq!(names("composer.lock", comp), vec!["guzzlehttp/guzzle@7.4.0"]);
        let pubs = "packages:\n  http:\n    dependency: \"direct main\"\n    source: hosted\n    version: \"0.13.5\"\nsdks:\n  dart: \">=3.0.0\"\n";
        assert_eq!(names("pubspec.lock", pubs), vec!["http@0.13.5"]);
    }
}
