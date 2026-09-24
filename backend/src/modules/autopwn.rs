// ===================================================================
// AutoPwn — one-shot orchestrator: subdomain → probe → exploit.
//
// Stage 1: passive crt.sh + optional DNS brute
// Stage 2: live-host HTTP/S probe (concurrent)
// Stage 3: xploit all selected templates on every alive host
//
// Emits `autopwn:*` events so the UI dashboard can track each stage
// independently without colliding with standalone tool events.
// ===================================================================

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

use super::xploiter::{parse_templates, run_template_against_target, Finding};

#[derive(Debug, Clone, Deserialize)]
pub struct AutopwnRequest {
    pub domain: String,
    pub use_passive: bool,
    pub brute_wordlist: Vec<String>,
    pub templates_yaml: Vec<String>,
    pub probe_ports: Option<Vec<u16>>,
    pub concurrency: usize,
    pub timeout_ms: u64,

    /// Status codes considered "alive" for the exploit stage.
    /// Default: 200-299, 301, 302, 307, 308, 401, 403, 405.
    /// Explicitly rejects 400 (bad req / wrong SNI), 404 (no vhost),
    /// 5xx (backend dead).
    #[serde(default)]
    pub accept_status: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutopwnSubHit {
    pub host: String,
    pub source: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutopwnProbeHit {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
    pub server: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutopwnReport {
    pub domain: String,
    pub subdomains: Vec<AutopwnSubHit>,
    pub alive: Vec<AutopwnProbeHit>,
    pub findings: Vec<Finding>,
}

// --------------------------------------------------------------
// stage 1: subdomain enum
// --------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct CrtRow { name_value: String }

async fn passive_crtsh(domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("PocketPentester-AutoPwn/0.1")
        .build()?;
    let rows: Vec<CrtRow> = client.get(&url).send().await?.json().await?;
    let mut set = HashSet::new();
    for r in rows {
        for line in r.name_value.split('\n') {
            let host = line.trim().trim_start_matches("*.").to_lowercase();
            if host.ends_with(domain) && !host.is_empty() { set.insert(host); }
        }
    }
    Ok(set)
}

fn rand_label() -> String {
    use rand::Rng;
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..16).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

/// Detect wildcard DNS by resolving 2 random non-existent subs.
/// Returns the set of IPs that appear to be catch-all answers.
async fn detect_wildcard(resolver: &TokioAsyncResolver, domain: &str) -> HashSet<String> {
    let mut ips: HashSet<String> = HashSet::new();
    for _ in 0..2 {
        let probe = format!("{}.{}", rand_label(), domain);
        if let Ok(lookup) = resolver.lookup_ip(probe.as_str()).await {
            for ip in lookup.iter() {
                ips.insert(ip.to_string());
            }
        }
    }
    ips
}

async fn enum_subdomains(
    app: &AppHandle,
    domain: &str,
    use_passive: bool,
    brute: &[String],
    concurrency: usize,
) -> Vec<AutopwnSubHit> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    let resolver = Arc::new(TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts));

    // wildcard detection BEFORE brute
    let wildcard = detect_wildcard(&resolver, domain).await;
    if !wildcard.is_empty() {
        let _ = app.emit(
            "autopwn:status",
            format!("wildcard DNS detected ({} IPs) — results pointing only to these will be filtered",
                wildcard.iter().cloned().collect::<Vec<_>>().join(","))
        );
    }

    let mut candidates: HashSet<(String, String)> = HashSet::new();
    candidates.insert((domain.to_string(), "root".into()));

    if use_passive {
        let _ = app.emit("autopwn:stage", "recon:passive");
        match passive_crtsh(domain).await {
            Ok(hosts) => {
                let _ = app.emit("autopwn:status", format!("crt.sh: +{} subs", hosts.len()));
                for h in hosts { candidates.insert((h, "crtsh".into())); }
            }
            Err(e) => { let _ = app.emit("autopwn:status", format!("crt.sh error: {e}")); }
        }
    }

    for w in brute {
        candidates.insert((format!("{}.{}", w.trim(), domain), "brute".into()));
    }

    let total = candidates.len();
    let _ = app.emit("autopwn:stage", "recon:resolve");
    let _ = app.emit("autopwn:status", format!("resolving {total} candidates"));

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let wildcard_arc = Arc::new(wildcard);

    let hits: Vec<AutopwnSubHit> = stream::iter(candidates.into_iter())
        .map(|(host, source)| {
            let resolver = resolver.clone();
            let sem = sem.clone();
            let done = done.clone();
            let app = app.clone();
            let wildcard = wildcard_arc.clone();
            async move {
                let _p = sem.acquire().await.unwrap();
                let result = resolver.lookup_ip(host.as_str()).await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("autopwn:progress", serde_json::json!({
                    "stage": "recon", "done": n, "total": total
                }));
                match result {
                    Ok(lookup) => {
                        let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                        if ips.is_empty() { return None; }

                        // wildcard filter: skip if ALL ips match the wildcard set
                        // (keep root domain regardless)
                        if !wildcard.is_empty() && source != "root"
                            && ips.iter().all(|ip| wildcard.contains(ip))
                        {
                            return None;
                        }

                        let hit = AutopwnSubHit { host, source, ips };
                        let _ = app.emit("autopwn:sub", hit.clone());
                        Some(hit)
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    hits
}

/// Default HTTP status codes treated as "alive & worth exploiting".
fn default_accept_statuses() -> Vec<u16> {
    vec![
        200, 201, 202, 203, 204, 206,
        301, 302, 303, 307, 308,
        401, 403, 405, 418, // 418 = sometimes WAF, but still shows alive service
    ]
}

// --------------------------------------------------------------
// stage 2: HTTP probe
// --------------------------------------------------------------

async fn probe_hosts(
    app: &AppHandle,
    hosts: &[AutopwnSubHit],
    ports: &[u16],
    concurrency: usize,
    timeout_ms: u64,
    accept_status: &[u16],
) -> Vec<AutopwnProbeHit> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (PocketPentester-AutoPwn)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut urls: Vec<String> = Vec::new();
    for h in hosts {
        for p in ports {
            let scheme = if matches!(p, 443 | 8443) { "https" } else { "http" };
            if *p == 80 || *p == 443 {
                urls.push(format!("{scheme}://{}", h.host));
            } else {
                urls.push(format!("{scheme}://{}:{}", h.host, p));
            }
        }
    }

    let total = urls.len();
    let _ = app.emit("autopwn:stage", "probe");
    let _ = app.emit("autopwn:status", format!("probing {total} urls"));

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = Arc::new(client);

    let title_re = regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap();
    // regex that recognizes "nothing useful" responses — default pages, error placeholders, etc.
    let junk_re = regex::Regex::new(
        r"(?i)(?:welcome to nginx|it works|apache2 ubuntu default page|test page for the (?:apache|nginx)|site not found|default backend - 404|403 forbidden</center>|bad request</h1>|invalid hostname)"
    ).unwrap();
    let accept: HashSet<u16> = accept_status.iter().copied().collect();

    let alive: Vec<AutopwnProbeHit> = stream::iter(urls.into_iter())
        .map(|url| {
            let sem = sem.clone();
            let done = done.clone();
            let client = client.clone();
            let app = app.clone();
            let title_re = title_re.clone();
            let junk_re = junk_re.clone();
            let accept = accept.clone();
            async move {
                let _p = sem.acquire().await.unwrap();
                let result = client.get(&url).send().await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("autopwn:progress", serde_json::json!({
                    "stage": "probe", "done": n, "total": total
                }));
                let resp = match result { Ok(r) => r, Err(_) => return None };
                let status = resp.status().as_u16();

                // ---- status whitelist ----
                if !accept.contains(&status) {
                    let _ = app.emit("autopwn:status",
                        format!("skip {} ({}): status not in accept-list", url, status));
                    return None;
                }

                let server = resp.headers().get("server")
                    .and_then(|v| v.to_str().ok()).map(String::from);
                let body = resp.text().await.unwrap_or_default();

                // ---- junk-body filter ----
                if junk_re.is_match(&body) {
                    let _ = app.emit("autopwn:status",
                        format!("skip {} ({}): default/placeholder page", url, status));
                    return None;
                }

                let title = title_re.captures(&body)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string())
                    .filter(|s| !s.is_empty());
                let hit = AutopwnProbeHit { url, status, title, server };
                let _ = app.emit("autopwn:alive", hit.clone());
                Some(hit)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    alive
}

// --------------------------------------------------------------
// stage 3: exploit
// --------------------------------------------------------------

async fn exploit_alive(
    app: &AppHandle,
    alive: &[AutopwnProbeHit],
    templates_yaml: &[String],
    concurrency: usize,
    timeout_ms: u64,
) -> Vec<Finding> {
    let templates = parse_templates(templates_yaml, app, "autopwn:status");
    if templates.is_empty() { return Vec::new(); }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Mozilla/5.0 (PocketPentester-AutoPwn)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let tasks: Vec<(String, super::xploiter::Template)> = alive.iter()
        .flat_map(|a| templates.iter().map(move |t| (a.url.clone(), t.clone())))
        .collect();
    let total = tasks.len();
    let _ = app.emit("autopwn:stage", "exploit");
    let _ = app.emit("autopwn:status", format!("exploiting: {total} target×template combos"));

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let client = Arc::new(client);
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    stream::iter(tasks.into_iter())
        .map(|(target, tpl)| {
            let sem = sem.clone();
            let client = client.clone();
            let done = done.clone();
            let app = app.clone();
            async move {
                let _p = sem.acquire().await.unwrap();
                let v = run_template_against_target(&client, &target, &tpl, &app, "autopwn:xpl").await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("autopwn:progress", serde_json::json!({
                    "stage": "exploit", "done": n, "total": total
                }));
                v
            }
        })
        .buffer_unordered(concurrency.max(1))
        .flat_map(|v| stream::iter(v.into_iter()))
        .collect()
        .await
}

// --------------------------------------------------------------
// command
// --------------------------------------------------------------

pub async fn autopwn_run(app: AppHandle, req: AutopwnRequest) -> Result<AutopwnReport, String> {
    let ports = req.probe_ports.clone().unwrap_or_else(|| vec![80, 443, 8080, 8443]);
    let accept_status = req.accept_status.clone().unwrap_or_else(default_accept_statuses);

    // stage 1 ---------------------------------------------------
    let subs = enum_subdomains(&app, &req.domain, req.use_passive, &req.brute_wordlist, req.concurrency).await;
    let _ = app.emit("autopwn:stage-done", serde_json::json!({ "stage": "recon", "count": subs.len() }));

    if subs.is_empty() {
        return Err("no live subdomains resolved".into());
    }

    // stage 2 ---------------------------------------------------
    let alive = probe_hosts(&app, &subs, &ports, req.concurrency, req.timeout_ms, &accept_status).await;
    let _ = app.emit("autopwn:stage-done", serde_json::json!({ "stage": "probe", "count": alive.len() }));

    if alive.is_empty() {
        let _ = app.emit("autopwn:done", 0);
        return Ok(AutopwnReport {
            domain: req.domain,
            subdomains: subs, alive: vec![], findings: vec![],
        });
    }

    // stage 3 ---------------------------------------------------
    let findings = if req.templates_yaml.is_empty() {
        let _ = app.emit("autopwn:status", "no templates selected — skipping exploit stage");
        Vec::new()
    } else {
        exploit_alive(&app, &alive, &req.templates_yaml, req.concurrency, req.timeout_ms).await
    };

    let _ = app.emit("autopwn:stage-done", serde_json::json!({
        "stage": "exploit", "count": findings.len()
    }));
    let _ = app.emit("autopwn:done", findings.len());

    Ok(AutopwnReport {
        domain: req.domain,
        subdomains: subs,
        alive,
        findings,
    })
}
