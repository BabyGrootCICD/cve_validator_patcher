use anyhow::{bail, Context, Result};
use reqwest::{header, Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;

const API: &str = "https://api.github.com";

/// Thin GitHub REST/GraphQL client with pagination and rate-limit backoff.
#[derive(Clone)]
pub struct GitHub {
    http: reqwest::Client,
    token: String,
}

impl GitHub {
    pub fn new(http: reqwest::Client, token: String) -> Self {
        GitHub { http, token }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        let url = if path.starts_with("http") { path.to_string() } else { format!("{API}{path}") };
        self.http
            .request(method, url)
            .bearer_auth(&self.token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    /// Send with retries on secondary rate limits / transient errors.
    async fn send(&self, method: Method, path: &str, body: Option<&Value>, accept: Option<&str>) -> Result<Response> {
        let mut delay = Duration::from_secs(5);
        for attempt in 0..6 {
            let mut rb = self.req(method.clone(), path);
            if let Some(a) = accept {
                rb = rb.header(header::ACCEPT, a);
            }
            if let Some(b) = body {
                rb = rb.json(b);
            }
            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) if attempt < 5 => {
                    tracing::warn!("github {path}: {e}; retrying");
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let s = resp.status();
            let limited = s == StatusCode::TOO_MANY_REQUESTS
                || (s == StatusCode::FORBIDDEN && resp.headers().get("x-ratelimit-remaining").map(|v| v == "0").unwrap_or(false))
                || (s == StatusCode::FORBIDDEN && resp.headers().contains_key(header::RETRY_AFTER));
            if (limited || s.is_server_error()) && attempt < 5 {
                let wait = resp
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .or_else(|| {
                        let reset = resp.headers().get("x-ratelimit-reset")?.to_str().ok()?.parse::<i64>().ok()?;
                        let secs = (reset - chrono::Utc::now().timestamp()).clamp(1, 900);
                        Some(Duration::from_secs(secs as u64))
                    })
                    .unwrap_or(delay);
                tracing::warn!("github {path}: {s}; backing off {wait:?}");
                tokio::time::sleep(wait).await;
                delay *= 2;
                continue;
            }
            return Ok(resp);
        }
        unreachable!()
    }

    async fn check(resp: Response, what: &str) -> Result<Response> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let s = resp.status();
        let t = resp.text().await.unwrap_or_default();
        bail!("{what}: HTTP {s}: {}", t.chars().take(300).collect::<String>())
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let r = self.send(Method::GET, path, None, None).await?;
        Ok(Self::check(r, path).await?.json().await?)
    }

    /// GET returning `None` on 404.
    pub async fn get_opt<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let r = self.send(Method::GET, path, None, None).await?;
        if r.status() == StatusCode::NOT_FOUND || r.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        Ok(Some(Self::check(r, path).await?.json().await?))
    }

    /// Raw file contents at `ref`, or `None` if missing.
    pub async fn raw_file(&self, repo: &str, path: &str, git_ref: &str) -> Result<Option<String>> {
        let p = format!("/repos/{repo}/contents/{}?ref={git_ref}", encode_path(path));
        let r = self.send(Method::GET, &p, None, Some("application/vnd.github.raw+json")).await?;
        if r.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(Self::check(r, &p).await?.text().await?))
    }

    /// GET all pages following `Link: rel="next"`. `pick` extracts the array
    /// from envelope responses (e.g. search results); default is the body itself.
    pub async fn paginate(&self, path: &str, pick: Option<&str>, max_pages: usize) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut next = Some(path.to_string());
        let mut pages = 0;
        while let Some(p) = next.take() {
            let r = Self::check(self.send(Method::GET, &p, None, None).await?, &p).await?;
            next = r.headers().get(header::LINK).and_then(|v| v.to_str().ok()).and_then(parse_next_link);
            let v: Value = r.json().await?;
            let arr = match pick {
                Some(k) => v.get(k).cloned().unwrap_or(Value::Null),
                None => v,
            };
            match arr {
                Value::Array(a) => out.extend(a),
                other => bail!("{p}: expected array, got {other}"),
            }
            pages += 1;
            if pages >= max_pages {
                break;
            }
        }
        Ok(out)
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let r = self.send(Method::POST, path, Some(body), None).await?;
        let r = Self::check(r, path).await?;
        Ok(r.json().await.unwrap_or(Value::Null))
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        let r = self.send(Method::PATCH, path, Some(body), None).await?;
        let r = Self::check(r, path).await?;
        Ok(r.json().await.unwrap_or(Value::Null))
    }

    /// PUT with an empty body; returns the status code (callers decide what is fatal).
    pub async fn put_status(&self, path: &str) -> Result<StatusCode> {
        Ok(self.send(Method::PUT, path, None, None).await?.status())
    }

    /// PUT with a JSON body; returns the status code.
    pub async fn put_json(&self, path: &str, body: &Value) -> Result<StatusCode> {
        Ok(self.send(Method::PUT, path, Some(body), None).await?.status())
    }

    pub async fn delete(&self, path: &str) -> Result<StatusCode> {
        Ok(self.send(Method::DELETE, path, None, None).await?.status())
    }

    /// POST that tolerates "already exists" (422).
    pub async fn post_idempotent(&self, path: &str, body: &Value) -> Result<()> {
        let r = self.send(Method::POST, path, Some(body), None).await?;
        if r.status() == StatusCode::UNPROCESSABLE_ENTITY || r.status().is_success() {
            return Ok(());
        }
        Self::check(r, path).await.map(|_| ())
    }

    pub async fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        let body = serde_json::json!({ "query": query, "variables": variables });
        let v = self.post("/graphql", &body).await.context("graphql")?;
        if let Some(errs) = v.get("errors") {
            bail!("graphql errors: {errs}");
        }
        Ok(v["data"].clone())
    }
}

fn parse_next_link(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (url, rel) = part.split_once(';')?;
        rel.contains("rel=\"next\"").then(|| url.trim().trim_matches(['<', '>']).to_string())
    })
}

fn encode_path(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            seg.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                    _ => format!("%{b:02X}"),
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_link() {
        let l = r#"<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last""#;
        assert_eq!(parse_next_link(l).as_deref(), Some("https://api.github.com/x?page=2"));
        assert_eq!(parse_next_link(r#"<https://a>; rel="prev""#), None);
    }

    #[test]
    fn path_encoding() {
        assert_eq!(encode_path("a b/c+d.txt"), "a%20b/c%2Bd.txt");
    }
}
