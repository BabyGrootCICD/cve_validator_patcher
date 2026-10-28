mod archive;
mod feeds;
mod fix;
mod github;
mod model;
mod report;
mod repos;
mod scan;
mod state;
mod ticket;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use feeds::{Collection, FeedCtx};
use github::GitHub;
use state::State;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Daily vulnerability intel → exposure scan → tickets → auto-fix → archive")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[command(flatten)]
    opts: Opts,
}

#[derive(Subcommand, Clone, Copy, PartialEq)]
enum Cmd {
    /// Collect advisories from all intel sources into the daily report.
    Collect,
    /// Scan repositories and record findings.
    Scan,
    /// Open, update and close issues to mirror the findings.
    Ticket,
    /// Open fix PRs for open findings.
    Fix,
    /// Re-check unresolved findings, advance fix PRs and sync tickets.
    Verify,
    /// Archive every day whose findings are all resolved.
    Archive,
    /// Run the whole pipeline.
    Run,
}

#[derive(clap::Args, Clone)]
pub struct Opts {
    /// GitHub token with repo, workflow and read:org scopes (falls back to GITHUB_TOKEN).
    #[arg(long, env = "VS_TOKEN", hide_env_values = true, global = true)]
    token: Option<String>,
    /// Comma-separated owners (user/org logins) to scan; default: you + all your orgs.
    #[arg(long, value_delimiter = ',', global = true)]
    owners: Vec<String>,
    /// Comma-separated `owner/name` repos to restrict to.
    #[arg(long, value_delimiter = ',', global = true)]
    repos: Vec<String>,
    /// Comma-separated `owner/name` repos to skip.
    #[arg(long, value_delimiter = ',', global = true)]
    exclude: Vec<String>,
    #[arg(long, global = true)]
    include_forks: bool,
    #[arg(long, global = true)]
    include_archived: bool,
    /// Scan at most N repositories (for testing).
    #[arg(long, global = true)]
    limit: Option<usize>,
    #[arg(long, default_value = "reports", global = true)]
    report_dir: PathBuf,
    #[arg(long, default_value = "archive", global = true)]
    archive_dir: PathBuf,
    #[arg(long, default_value = "state/findings.json", global = true)]
    state_file: PathBuf,
    /// Report date (UTC, YYYY-MM-DD); default today.
    #[arg(long, global = true)]
    date: Option<NaiveDate>,
    /// Collection window ending now.
    #[arg(long, default_value_t = 24, global = true)]
    window_hours: i64,
    /// Do not create issues, branches or PRs.
    #[arg(long, global = true)]
    dry_run: bool,
    #[arg(long, default_value_t = 8, global = true)]
    concurrency: usize,
    /// Ops repository (`owner/name`) for tracker issues and report links.
    #[arg(long, env = "GITHUB_REPOSITORY", global = true)]
    tracker_repo: Option<String>,
    #[arg(long, default_value = "main", global = true)]
    tracker_branch: String,
    /// Maximum issues to create per run.
    #[arg(long, default_value_t = 150, global = true)]
    max_new_issues: usize,
    /// Merge fix PRs automatically once CI passes.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, global = true)]
    auto_merge: bool,
    /// Also merge fix PRs in repositories that have no CI at all.
    #[arg(long, global = true)]
    merge_without_checks: bool,
    /// Maximum repositories to open fix PRs in per run.
    #[arg(long, default_value_t = 40, global = true)]
    max_fix_repos: usize,
    /// Give up automatic fixing of a package after this many attempts.
    #[arg(long, default_value_t = 3, global = true)]
    max_fix_attempts: u32,
    /// Package groups to attempt per repository per run.
    #[arg(long, default_value_t = 25, global = true)]
    max_fix_groups: usize,
    /// `run`: verify→fix rounds to wait for PRs to merge within one run.
    #[arg(long, default_value_t = 3, global = true)]
    max_iterations: u32,
    /// `run`: minutes to wait between verify rounds.
    #[arg(long, default_value_t = 10, global = true)]
    poll_minutes: u64,
    #[arg(long, default_value = "vuln-sentinel/security-fixes", global = true)]
    fix_branch: String,
    /// Scratch directory for clones (default: $RUNNER_TEMP or ./.vs-work).
    #[arg(long, global = true)]
    workdir: Option<PathBuf>,
    #[arg(long, env = "NVD_API_KEY", hide_env_values = true, global = true)]
    nvd_api_key: Option<String>,
    #[arg(long, env = "VULNERS_API_KEY", hide_env_values = true, global = true)]
    vulners_api_key: Option<String>,
    #[arg(long, env = "ATTACKERKB_API_KEY", hide_env_values = true, global = true)]
    attackerkb_api_key: Option<String>,
}

pub struct App {
    pub opts: Opts,
    pub http: reqwest::Client,
    pub gh: GitHub,
    pub date: String,
    pub now: DateTime<Utc>,
    pub state: State,
    repos: Option<Vec<repos::Repo>>,
}

impl App {
    fn report_md(&self, date: &str) -> PathBuf {
        self.opts.report_dir.join(format!("{date}.md"))
    }

    fn collection_json(&self, date: &str) -> PathBuf {
        self.opts.report_dir.join(format!("{date}.json"))
    }

    fn load_collection(&self, date: &str) -> Collection {
        std::fs::read_to_string(self.collection_json(date)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn save_state(&self) -> Result<()> {
        self.state.save(&self.opts.state_file)
    }

    /// Re-render the markdown report for `date` unless it was already archived.
    fn write_report(&self, date: &str) -> Result<()> {
        if self.state.days.get(date).map(|d| d.archived).unwrap_or(false) {
            return Ok(());
        }
        let c = self.load_collection(date);
        std::fs::create_dir_all(&self.opts.report_dir)?;
        std::fs::write(self.report_md(date), report::render(date, &c, &self.state))?;
        Ok(())
    }

    async fn collect(&mut self) -> Result<()> {
        let ctx = FeedCtx {
            http: self.http.clone(),
            gh: self.gh.clone(),
            since: self.now - Duration::hours(self.opts.window_hours),
            until: self.now,
            nvd_key: self.opts.nvd_api_key.clone(),
            vulners_key: self.opts.vulners_api_key.clone(),
            attackerkb_key: self.opts.attackerkb_api_key.clone(),
        };
        let c = feeds::collect(&ctx).await;
        for f in &c.feeds {
            tracing::info!("feed {}: {:?}", f.source, f.status);
        }
        std::fs::create_dir_all(&self.opts.report_dir)?;
        std::fs::write(self.collection_json(&self.date), serde_json::to_string_pretty(&c)?)?;
        let day = self.state.days.entry(self.date.clone()).or_default();
        day.advisories = c.advisories.len();
        day.feeds = c.feeds.clone();
        self.save_state()?;
        self.write_report(&self.date.clone())?;
        output("report-path", &self.report_md(&self.date).display().to_string());
        Ok(())
    }

    fn filter(&self) -> repos::RepoFilter {
        repos::RepoFilter {
            owners: self.opts.owners.clone(),
            only: self.opts.repos.clone(),
            include_forks: self.opts.include_forks,
            include_archived: self.opts.include_archived,
            exclude: self.opts.exclude.clone(),
            limit: self.opts.limit,
        }
    }

    async fn repos(&mut self) -> Result<Vec<repos::Repo>> {
        if self.repos.is_none() {
            self.repos = Some(repos::list(&self.gh, &self.filter()).await?);
        }
        Ok(self.repos.clone().unwrap_or_default())
    }

    /// Scan `targets` (or every matching repo) and reconcile into state.
    async fn scan(&mut self, targets: Option<HashSet<String>>) -> Result<()> {
        let mut list = self.repos().await?;
        if let Some(t) = &targets {
            list.retain(|r| t.contains(&r.full_name));
        }
        tracing::info!("scanning {} repositories", list.len());
        let c = self.load_collection(&self.date);
        let today_ids: HashSet<String> = c.advisories.iter().flat_map(|a| a.all_ids().cloned()).collect();
        let res = scan::scan(&self.gh, &self.http, &list, &today_ids, self.opts.concurrency).await;
        for e in &res.errors {
            tracing::warn!("scan error: {e}");
        }
        let failed: HashSet<&str> = res.errors.iter().filter_map(|e| e.split(':').next()).collect();
        let scanned: HashSet<String> =
            list.iter().map(|r| r.full_name.clone()).filter(|n| !failed.contains(n.as_str()) && !failed.contains("osv match")).collect();
        let r = self.state.reconcile(&res.findings, &scanned, &self.date, Utc::now());
        tracing::info!(
            "scan: {} repos, {} deps, {} findings ({} new, {} resolved, {} reopened)",
            res.repos_scanned,
            res.dependencies,
            res.findings.len(),
            r.new,
            r.resolved,
            r.reopened
        );
        if targets.is_none() {
            let day = self.state.days.entry(self.date.clone()).or_default();
            day.repos_scanned = res.repos_scanned;
            day.dependencies = res.dependencies;
            day.scan_errors = res.errors.len();
        }
        self.save_state()?;
        self.refresh_reports()?;
        output("findings", &self.state.findings.len().to_string());
        output("unresolved", &self.state.unresolved().count().to_string());
        Ok(())
    }

    fn ticket_cfg(&self) -> ticket::TicketCfg {
        ticket::TicketCfg {
            dry_run: self.opts.dry_run,
            max_new: self.opts.max_new_issues,
            tracker_repo: self.opts.tracker_repo.clone(),
            tracker_branch: self.opts.tracker_branch.clone(),
            report_dir: self.opts.report_dir.display().to_string(),
        }
    }

    fn fix_cfg(&self) -> fix::FixCfg {
        fix::FixCfg {
            dry_run: self.opts.dry_run,
            auto_merge: self.opts.auto_merge,
            merge_without_checks: self.opts.merge_without_checks,
            max_repos: self.opts.max_fix_repos,
            max_attempts: self.opts.max_fix_attempts,
            max_groups_per_repo: self.opts.max_fix_groups,
            workdir: self.opts.workdir.clone().unwrap_or_else(|| {
                std::env::var("RUNNER_TEMP").map(|t| PathBuf::from(t).join("vuln-sentinel")).unwrap_or_else(|_| PathBuf::from(".vs-work"))
            }),
            branch: self.opts.fix_branch.clone(),
        }
    }

    async fn tickets(&mut self) -> Result<()> {
        let with_issues: HashSet<String> =
            self.repos().await?.into_iter().filter(|r| r.has_issues && !r.archived).map(|r| r.full_name).collect();
        let cfg = self.ticket_cfg();
        let st = ticket::sync(&self.gh, &mut self.state, &with_issues, &cfg).await?;
        tracing::info!("tickets: {st:?}");
        self.save_state()?;
        let days: Vec<String> = self.state.days.iter().filter(|(_, d)| !d.archived).map(|(k, _)| k.clone()).collect();
        for d in days {
            if self.state.for_day(&d).next().is_some() {
                if let Err(e) = ticket::sync_tracker(&self.gh, &mut self.state, &d, &cfg, false).await {
                    tracing::warn!("tracker {d}: {e:#}");
                }
            }
        }
        self.save_state()?;
        self.refresh_reports()
    }

    async fn fix(&mut self) -> Result<()> {
        let repos: HashMap<String, repos::Repo> = self.repos().await?.into_iter().map(|r| (r.full_name.clone(), r)).collect();
        let cfg = self.fix_cfg();
        let st = fix::run(&self.gh, &mut self.state, &repos, &cfg).await?;
        tracing::info!("fix: {st:?}");
        self.save_state()?;
        Ok(())
    }

    async fn verify(&mut self) -> Result<()> {
        let cfg = self.fix_cfg();
        let st = fix::advance_prs(&self.gh, &mut self.state, &cfg).await?;
        tracing::info!("advance PRs: {st:?}");
        let targets: HashSet<String> = self.state.unresolved().map(|t| t.finding.repo.clone()).collect();
        if !targets.is_empty() {
            self.scan(Some(targets)).await?;
        }
        self.tickets().await
    }

    async fn archive(&mut self) -> Result<()> {
        let days = archive::archivable(&self.state);
        let cfg = self.ticket_cfg();
        for d in &days {
            self.write_report(d)?;
            if self.state.for_day(d).next().is_some() || self.state.days[d].tracker_issue.is_some() {
                if let Err(e) = ticket::sync_tracker(&self.gh, &mut self.state, d, &cfg, true).await {
                    tracing::warn!("tracker {d}: {e:#}");
                }
            }
            archive::archive_day(&mut self.state, d, &self.opts.report_dir, &self.opts.archive_dir, Utc::now())?;
            tracing::info!("archived {d}");
        }
        self.save_state()?;
        output("archived-dates", &days.join(","));
        Ok(())
    }

    /// Full pipeline, waiting a bounded time for fix PRs to merge.
    async fn run(&mut self) -> Result<()> {
        self.collect().await?;
        self.scan(None).await?;
        self.tickets().await?;
        self.fix().await?;
        self.tickets().await?;
        for round in 1..=self.opts.max_iterations {
            let pending = self.state.unresolved().filter(|t| t.status == state::Status::FixProposed).count();
            if self.state.unresolved().next().is_none() || pending == 0 || self.opts.dry_run {
                break;
            }
            tracing::info!("round {round}: waiting {} min for {pending} findings with fix PRs", self.opts.poll_minutes);
            tokio::time::sleep(std::time::Duration::from_secs(self.opts.poll_minutes * 60)).await;
            self.verify().await?;
            self.fix().await?;
        }
        self.archive().await
    }

    /// Re-render every non-archived day that has a report.
    fn refresh_reports(&self) -> Result<()> {
        let days: Vec<String> = self.state.days.iter().filter(|(_, d)| !d.archived).map(|(k, _)| k.clone()).collect();
        for d in days {
            self.write_report(&d)?;
        }
        Ok(())
    }
}

/// Write a step output when running inside GitHub Actions.
pub fn output(key: &str, value: &str) {
    if let Ok(p) = std::env::var("GITHUB_OUTPUT") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(p) {
            let _ = writeln!(f, "{key}={value}");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let token = cli
        .opts
        .token
        .clone()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .filter(|t| !t.is_empty())
        .context("a GitHub token is required (--token, VS_TOKEN or GITHUB_TOKEN)")?;
    let http = reqwest::Client::builder()
        .user_agent(concat!("vuln-sentinel/", env!("CARGO_PKG_VERSION"), " (+https://github.com/dennislee928/vuln-sentinel)"))
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let now = Utc::now();
    let date = cli.opts.date.unwrap_or_else(|| now.date_naive()).format("%Y-%m-%d").to_string();
    let state = State::load(&cli.opts.state_file)?;
    let mut app = App { gh: GitHub::new(http.clone(), token), http, date, now, state, opts: cli.opts, repos: None };

    match cli.cmd {
        Cmd::Collect => app.collect().await?,
        Cmd::Scan => app.scan(None).await?,
        Cmd::Ticket => app.tickets().await?,
        Cmd::Fix => app.fix().await?,
        Cmd::Verify => app.verify().await?,
        Cmd::Archive => app.archive().await?,
        Cmd::Run => app.run().await?,
    }
    Ok(())
}
