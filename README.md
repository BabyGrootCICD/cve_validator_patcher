# Vuln Sentinel

A GitHub Action, written in Rust, that runs every day and:

1. **Collects** the newest advisories from CVE (NVD), OSV, ENISA EUVD, the GitHub Advisory Database, OpenSSF Malicious Packages, Vulners, Sploitus and AttackerKB. Each advisory is mapped to the OWASP Top 10 through its CWE. The results go into `reports/{date}.md`.
2. **Scans** every repository you own or reach through your organizations: lockfiles on the default branch are matched against the full OSV database, and hits that come from that day's advisories are highlighted.
3. **Opens tickets**: one issue per vulnerable package in the affected repo, plus a daily tracker issue in your ops repo.
4. **Fixes**: upgrades each package to the minimal fixed version with the ecosystem's own tool and opens one PR per repo. The PR merges automatically once CI is green.
5. **Verifies** again until every finding from that day is resolved, then **archives** the report, the raw advisories and the resolution metrics into `archive/{date}/`.

## Quick start

Create a **private** ops repository; reports list private repos and their vulnerabilities. Then:

```bash
gh secret set SENTINEL_TOKEN   # classic PAT: repo, workflow, read:org (authorize SSO for orgs if required)
# optional feeds
gh secret set VULNERS_API_KEY
gh secret set ATTACKERKB_API_KEY
gh secret set NVD_API_KEY
```

Copy [`examples/daily.yml`](examples/daily.yml) and [`examples/verify.yml`](examples/verify.yml) into `.github/workflows/`.

```yaml
- uses: actions/checkout@v4
- uses: dennislee928/vuln-sentinel@v1
  with:
    token: ${{ secrets.SENTINEL_TOKEN }}
    mode: run          # run | collect | scan | ticket | fix | verify | archive
```

The workflow needs `permissions: contents: write, issues: write`. The action commits `reports/`, `state/` and `archive/` back to the ops repository.

## Sources

| Source | How | Key |
|---|---|---|
| CVE (NVD) | NVD CVE API 2.0, by publish date | optional `NVD_API_KEY` |
| OSV | `modified_id.csv` per ecosystem, newly published records | – |
| ENISA EUVD | `euvdservices.enisa.europa.eu/api/search` | – |
| GitHub Advisory Database | `GET /advisories` | – |
| OpenSSF | `ossf/malicious-packages` new reports | – |
| OWASP | CWE → OWASP Top 10:2025 classification of everything collected | – |
| Vulners | Lucene search API (CVEs + exploits) | `VULNERS_API_KEY` |
| AttackerKB | Topics API (exploitability assessments) | `ATTACKERKB_API_KEY` |
| Sploitus | Exploit search (best effort, no official API) | – |

A source that is missing its key, or that errors, is shown in the report as *skipped* or *error*. It never fails the run.

## Supported lockfiles and fixers

| Ecosystem | Files | Fix |
|---|---|---|
| Rust | `Cargo.lock` | `cargo update -p name@old --precise fixed` |
| npm / Yarn / pnpm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | bump the direct dependency, or add `overrides` / `resolutions` / `pnpm.overrides`, then regenerate the lockfile with scripts disabled |
| Go | `go.mod` | `go get mod@fixed && go mod tidy` |
| Python | `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`* | rewrite the pin / `poetry update --lock` / `uv lock --upgrade-package` |
| Ruby | `Gemfile.lock` | `bundle lock --update name` |
| PHP | `composer.lock` | `composer update name --with-dependencies --no-install` |
| Dart | `pubspec.lock` | `dart pub upgrade name` |

\* Scanned only. When no fix exists, or the fixer can't apply one, the issue gets a note and Dependabot security updates are switched on for that repository.

A change is committed only after re-parsing the lockfile confirms the vulnerable version is gone.

## Merge policy

- If the default branch has **required status checks** (branch protection or rulesets), GitHub auto-merge is enabled on the fix PR.
- Otherwise vuln-sentinel inspects the PR's check runs on every `verify` and merges once **all of them pass**.
- Repositories with no CI are left for a manual merge, unless you set `merge-without-checks: true`.
- If a fix PR is closed without merging, its findings go back to *open* and are retried. After `max-fix-attempts` tries the package is left to a human.

## Lifecycle

```
collect ─► scan ─► ticket ─► fix ─► (wait) ─► verify ─► fix ─► … ─► archive
                                     ▲________________________________│ every 4h
```

A day is archived once every finding first seen on it is resolved, meaning it no longer appears on the default branch. `archive/{date}/` then holds `report.md`, `advisories.json`, `findings.json`, `metrics.json` and `metrics.md`: counts per source and severity, tickets, PRs, auto-merges, and mean/max time to resolve.

## Inputs

See [`action.yml`](action.yml). The main ones: `owners`, `repos`, `exclude`, `include-forks`, `include-archived`, `auto-merge`, `merge-without-checks`, `dry-run`, `window-hours`, `max-new-issues`, `max-fix-repos`, `max-fix-groups`, `max-iterations`, `poll-minutes`.

## Local use

```bash
cargo build --release
VS_TOKEN=$(gh auth token) ./target/release/vuln-sentinel run --dry-run --limit 5
```

## License

MIT
