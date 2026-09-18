use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Deserialize)]
pub struct HttpProbeRequest {
    pub targets: Vec<String>,
    pub ports: Option<Vec<u16>>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
    pub server: Option<String>,
    pub content_length: Option<u64>,
    pub tech: Vec<String>,
}

static TITLE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());

fn detect_tech(headers: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut tech = Vec::new();
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("");

    let server = get("server").to_lowercase();
    let powered = get("x-powered-by").to_lowercase();

    if server.contains("nginx") { tech.push("nginx".into()); }
    if server.contains("apache") { tech.push("apache".into()); }
    if server.contains("cloudflare") { tech.push("cloudflare".into()); }
    if server.contains("iis") { tech.push("iis".into()); }
    if powered.contains("php") { tech.push("php".into()); }
    if powered.contains("express") { tech.push("express".into()); }
    if powered.contains("asp.net") { tech.push("asp.net".into()); }

    let b = body.to_lowercase();
    if b.contains("wp-content") || b.contains("wp-includes") { tech.push("wordpress".into()); }
    if b.contains("drupal-settings-json") { tech.push("drupal".into()); }
    if b.contains("joomla") { tech.push("joomla".into()); }
    if b.contains("__next_data__") { tech.push("next.js".into()); }
    if b.contains("data-reactroot") || b.contains("__reactcontainer") { tech.push("react".into()); }
    if b.contains("ng-version") { tech.push("angular".into()); }
    if b.contains("window.laravel") || b.contains("laravel_session") { tech.push("laravel".into()); }

    tech
}

async fn probe_one(client: &reqwest::Client, url: String) -> Option<HttpProbeResult> {
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let content_length = resp.content_length();
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let body = resp.text().await.unwrap_or_default();
    let title = TITLE_RE
        .captures(&body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty());

    let tech = detect_tech(&headers, &body);

    Some(HttpProbeResult { url, status, title, server, content_length, tech })
}

pub async fn http_probe(
    app: AppHandle,
    req: HttpProbeRequest,
) -> Result<Vec<HttpProbeResult>, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent("Mozilla/5.0 (PocketPentester)")
        .build()
        .map_err(|e| e.to_string())?;

    let ports = req.ports.unwrap_or_else(|| vec![80, 443, 8080, 8443]);

    let mut urls: Vec<String> = Vec::new();
    for t in &req.targets {
        let t = t.trim();
        if t.starts_with("http://") || t.starts_with("https://") {
            urls.push(t.to_string());
            continue;
        }
        for p in &ports {
            let scheme = if matches!(p, 443 | 8443) { "https" } else { "http" };
            if *p == 80 || *p == 443 {
                urls.push(format!("{scheme}://{t}"));
            } else {
                urls.push(format!("{scheme}://{t}:{p}"));
            }
        }
    }

    let total = urls.len();
    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = Arc::new(client);

    let results: Vec<HttpProbeResult> = stream::iter(urls.into_iter())
        .map(|url| {
            let sem = sem.clone();
            let done = done.clone();
            let client = client.clone();
            let app = app.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let res = probe_one(&client, url).await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("httpx:progress", serde_json::json!({"done": n, "total": total}));
                if let Some(ref r) = res {
                    let _ = app.emit("httpx:hit", r.clone());
                }
                res
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let _ = app.emit("httpx:done", results.len());
    Ok(results)
}
