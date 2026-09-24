// ===================================================================
// Subdomain enumeration — subfinder-style multi-source aggregator.
//
// Sources (default-on, no API key needed):
//   - crt.sh                  — certificate transparency
//   - certspotter             — certificate transparency (parallel)
//   - hackertarget            — passive DNS (rate-limited 50/day per IP)
//   - alienvault OTX          — passive DNS
//   - anubis-db               — community subdomain DB
//   - rapiddns                — HTML scrape
//   - wayback (web.archive.org)— historical URLs → extract hosts
//   - urlscan                 — domain search
//   - threatcrowd             — passive DNS
//
// Key-based sources (opt-in, user supplies API key):
//   - c99.nl                  — fast commercial source
//   - virustotal              — domain relations
//   - securitytrails          — premium passive
//   - chaos (projectdiscovery)— curated dataset
//   - shodan                  — host search
//   - binaryedge              — passive DNS
//   - fullhunt                — attack-surface DB
// ===================================================================

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Deserialize)]
pub struct SubdomainRequest {
    pub domain: String,
    /// Source names to enable. If None/empty, all default-on sources run.
    /// Available: crtsh, certspotter, hackertarget, alienvault, anubis,
    /// rapiddns, wayback, urlscan, threatcrowd, c99, virustotal,
    /// securitytrails, chaos, shodan, binaryedge, fullhunt.
    #[serde(default)]
    pub sources: Option<Vec<String>>,

    /// Optional brute-force wordlist (in addition to passive).
    #[serde(default)]
    pub wordlist: Option<Vec<String>>,

    pub concurrency: usize,

    /// API keys for key-based sources. Map of source-name → key.
    #[serde(default)]
    pub api_keys: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubdomainHit {
    pub host: String,
    pub source: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStat {
    pub source: String,
    pub count: usize,
    pub error: Option<String>,
    pub took_ms: u128,
}

// ------------------------------------------------------------------
// HTTP client
// ------------------------------------------------------------------

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent("Mozilla/5.0 (PocketPentester/0.1)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn norm_host(s: &str, root: &str) -> Option<String> {
    let h = s.trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_lowercase();
    let h = h.split_whitespace().next()?.to_string();
    if h.is_empty() { return None; }
    if !h.ends_with(root) { return None; }
    if h.contains('@') { return None; }
    if h.starts_with("xn--") && h.len() < 6 { return None; }
    Some(h)
}

// ------------------------------------------------------------------
// passive sources (no key)
// ------------------------------------------------------------------

async fn fetch_json(client: &reqwest::Client, url: &str) -> anyhow::Result<serde_json::Value> {
    fetch_json_with_headers(client, url, &[]).await
}

async fn fetch_json_with_headers(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, &str)],
) -> anyhow::Result<serde_json::Value> {
    let mut req = client.get(url);
    for (k, v) in headers { req = req.header(*k, *v); }
    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("HTTP {} (body: {})", status, body.chars().take(120).collect::<String>());
    }
    if body.trim().is_empty() {
        anyhow::bail!("empty response");
    }
    serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("json parse: {e}"))
}

fn values_from_array<'a>(v: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    v.get(key).and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[])
}

async fn src_crtsh(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let val = fetch_json(client, &url).await?;
    let arr = val.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let mut set = HashSet::new();
    for r in arr {
        if let Some(nv) = r.get("name_value").and_then(|v| v.as_str()) {
            for line in nv.split('\n') {
                if let Some(h) = norm_host(line, domain) { set.insert(h); }
            }
        }
    }
    Ok(set)
}

async fn src_certspotter(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", domain);
    let val = fetch_json(client, &url).await?;
    let arr = val.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let mut set = HashSet::new();
    for r in arr {
        for n in values_from_array(r, "dns_names") {
            if let Some(s) = n.as_str() {
                if let Some(h) = norm_host(s, domain) { set.insert(h); }
            }
        }
    }
    Ok(set)
}

async fn src_hackertarget(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() { anyhow::bail!("HTTP {status}"); }
    if body.contains("API count exceeded") || body.contains("error check your search parameter") {
        anyhow::bail!("rate limited");
    }
    let mut set = HashSet::new();
    for line in body.lines() {
        if let Some((host, _)) = line.split_once(',') {
            if let Some(h) = norm_host(host, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_alienvault(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    let val = fetch_json(client, &url).await?;
    let mut set = HashSet::new();
    for entry in values_from_array(&val, "passive_dns") {
        if let Some(host) = entry.get("hostname").and_then(|v| v.as_str()) {
            if let Some(h) = norm_host(host, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_anubis(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://jonlu.ca/anubis/subdomains/{}", domain);
    let val = fetch_json(client, &url).await?;
    let arr = val.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let mut set = HashSet::new();
    for s in arr {
        if let Some(host) = s.as_str() {
            if let Some(h) = norm_host(host, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_rapiddns(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://rapiddns.io/subdomain/{}?full=1", domain);
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let html = resp.text().await?;
    if !status.is_success() { anyhow::bail!("HTTP {status}"); }
    let re = Regex::new(r#"<td>([a-zA-Z0-9_.\-]+\.[a-zA-Z]{2,})</td>"#)?;
    let mut set = HashSet::new();
    for cap in re.captures_iter(&html) {
        if let Some(m) = cap.get(1) {
            if let Some(h) = norm_host(m.as_str(), domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_wayback(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}&output=json&fl=original&collapse=urlkey&limit=10000", domain);
    let val = fetch_json(client, &url).await?;
    let arr = val.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let mut set = HashSet::new();
    for (i, row) in arr.iter().enumerate() {
        if i == 0 { continue; } // header row
        if let Some(u) = row.as_array().and_then(|r| r.first()).and_then(|v| v.as_str()) {
            if let Some(host) = url::Url::parse(u).ok().and_then(|p| p.host_str().map(String::from)) {
                if let Some(h) = norm_host(&host, domain) { set.insert(h); }
            }
        }
    }
    Ok(set)
}

async fn src_urlscan(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}&size=10000", domain);
    let val = fetch_json(client, &url).await?;
    let mut set = HashSet::new();
    for r in values_from_array(&val, "results") {
        if let Some(d) = r.get("page").and_then(|p| p.get("domain")).and_then(|v| v.as_str()) {
            if let Some(h) = norm_host(d, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_threatcrowd(client: &reqwest::Client, domain: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain);
    let val = fetch_json(client, &url).await?;
    let mut set = HashSet::new();
    for s in values_from_array(&val, "subdomains") {
        if let Some(host) = s.as_str() {
            if let Some(h) = norm_host(host, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

// ------------------------------------------------------------------
// key-based sources
// ------------------------------------------------------------------

async fn src_c99(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://api.c99.nl/subdomainfinder?key={key}&domain={domain}&json");
    let val = fetch_json(client, &url).await?;
    if let Some(e) = val.get("error").and_then(|v| v.as_str()) { anyhow::bail!("{e}"); }
    let mut set = HashSet::new();
    for r in values_from_array(&val, "subdomains") {
        if let Some(s) = r.get("subdomain").and_then(|v| v.as_str()) {
            if let Some(h) = norm_host(s, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_virustotal(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=40", domain);
    let val = fetch_json_with_headers(client, &url, &[("x-apikey", key)]).await?;
    let mut set = HashSet::new();
    for r in values_from_array(&val, "data") {
        if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
            if let Some(h) = norm_host(id, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_securitytrails(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false", domain);
    let val = fetch_json_with_headers(client, &url, &[("APIKEY", key)]).await?;
    let mut set = HashSet::new();
    for s in values_from_array(&val, "subdomains") {
        if let Some(sub) = s.as_str() {
            let full = format!("{}.{}", sub, domain);
            if let Some(h) = norm_host(&full, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_chaos(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://dns.projectdiscovery.io/dns/{}/subdomains", domain);
    let val = fetch_json_with_headers(client, &url, &[("Authorization", key)]).await?;
    let mut set = HashSet::new();
    for s in values_from_array(&val, "subdomains") {
        if let Some(sub) = s.as_str() {
            let full = format!("{}.{}", sub, domain);
            if let Some(h) = norm_host(&full, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_shodan(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://api.shodan.io/dns/domain/{}?key={}", domain, key);
    let val = fetch_json(client, &url).await?;
    let mut set = HashSet::new();
    for s in values_from_array(&val, "subdomains") {
        if let Some(sub) = s.as_str() {
            let full = format!("{}.{}", sub, domain);
            if let Some(h) = norm_host(&full, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_binaryedge(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://api.binaryedge.io/v2/query/domains/subdomain/{}", domain);
    let val = fetch_json_with_headers(client, &url, &[("X-Key", key)]).await?;
    let mut set = HashSet::new();
    for s in values_from_array(&val, "events") {
        if let Some(host) = s.as_str() {
            if let Some(h) = norm_host(host, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

async fn src_fullhunt(client: &reqwest::Client, domain: &str, key: &str) -> anyhow::Result<HashSet<String>> {
    let url = format!("https://fullhunt.io/api/v1/domain/{}/subdomains", domain);
    let val = fetch_json_with_headers(client, &url, &[("X-API-KEY", key)]).await?;
    let mut set = HashSet::new();
    for s in values_from_array(&val, "hosts") {
        if let Some(host) = s.as_str() {
            if let Some(h) = norm_host(host, domain) { set.insert(h); }
        }
    }
    Ok(set)
}

// ------------------------------------------------------------------
// orchestrator
// ------------------------------------------------------------------

const FREE_SOURCES: &[&str] = &[
    "crtsh", "certspotter", "hackertarget", "alienvault", "anubis",
    "rapiddns", "wayback", "urlscan", "threatcrowd",
];

const KEY_SOURCES: &[&str] = &[
    "c99", "virustotal", "securitytrails", "chaos", "shodan", "binaryedge", "fullhunt",
];

pub fn subdomain_sources() -> serde_json::Value {
    serde_json::json!({
        "free": FREE_SOURCES,
        "key_based": KEY_SOURCES,
    })
}

async fn fetch_source(
    name: &str,
    client: &reqwest::Client,
    domain: &str,
    keys: &HashMap<String, String>,
) -> anyhow::Result<HashSet<String>> {
    match name {
        "crtsh"          => src_crtsh(client, domain).await,
        "certspotter"    => src_certspotter(client, domain).await,
        "hackertarget"   => src_hackertarget(client, domain).await,
        "alienvault"     => src_alienvault(client, domain).await,
        "anubis"         => src_anubis(client, domain).await,
        "rapiddns"       => src_rapiddns(client, domain).await,
        "wayback"        => src_wayback(client, domain).await,
        "urlscan"        => src_urlscan(client, domain).await,
        "threatcrowd"    => src_threatcrowd(client, domain).await,
        "c99"            => src_c99(client, domain, keys.get("c99").ok_or_else(|| anyhow::anyhow!("missing c99 api key"))?).await,
        "virustotal"     => src_virustotal(client, domain, keys.get("virustotal").ok_or_else(|| anyhow::anyhow!("missing virustotal api key"))?).await,
        "securitytrails" => src_securitytrails(client, domain, keys.get("securitytrails").ok_or_else(|| anyhow::anyhow!("missing securitytrails api key"))?).await,
        "chaos"          => src_chaos(client, domain, keys.get("chaos").ok_or_else(|| anyhow::anyhow!("missing chaos api key"))?).await,
        "shodan"         => src_shodan(client, domain, keys.get("shodan").ok_or_else(|| anyhow::anyhow!("missing shodan api key"))?).await,
        "binaryedge"     => src_binaryedge(client, domain, keys.get("binaryedge").ok_or_else(|| anyhow::anyhow!("missing binaryedge api key"))?).await,
        "fullhunt"       => src_fullhunt(client, domain, keys.get("fullhunt").ok_or_else(|| anyhow::anyhow!("missing fullhunt api key"))?).await,
        _ => Err(anyhow::anyhow!("unknown source: {name}")),
    }
}

fn resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
}

pub async fn subdomain_enum(
    app: AppHandle,
    req: SubdomainRequest,
) -> Result<Vec<SubdomainHit>, String> {
    let client = build_client();
    let resolver = Arc::new(resolver());
    let keys = req.api_keys.clone().unwrap_or_default();

    let enabled: Vec<String> = req.sources.clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| FREE_SOURCES.iter().map(|s| s.to_string()).collect());

    let _ = app.emit("subenum:status", format!("running {} source(s) in parallel", enabled.len()));

    // ---- run all sources concurrently ----
    let mut all: HashMap<String, String> = HashMap::new(); // host → first-seen source
    let stats: Arc<tokio::sync::Mutex<Vec<SourceStat>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let source_results = futures::future::join_all(enabled.iter().map(|name| {
        let client = client.clone();
        let keys = keys.clone();
        let domain = req.domain.clone();
        let app = app.clone();
        let stats = stats.clone();
        let name = name.clone();
        async move {
            let started = std::time::Instant::now();
            let res = fetch_source(&name, &client, &domain, &keys).await;
            let took = started.elapsed().as_millis();
            match res {
                Ok(set) => {
                    let stat = SourceStat { source: name.clone(), count: set.len(), error: None, took_ms: took };
                    let _ = app.emit("subenum:source", stat.clone());
                    stats.lock().await.push(stat);
                    (name, set)
                }
                Err(e) => {
                    let stat = SourceStat { source: name.clone(), count: 0, error: Some(e.to_string()), took_ms: took };
                    let _ = app.emit("subenum:source", stat.clone());
                    stats.lock().await.push(stat);
                    (name, HashSet::new())
                }
            }
        }
    })).await;

    for (src_name, set) in source_results {
        for h in set {
            all.entry(h).or_insert(src_name.clone());
        }
    }

    // ---- bruteforce additions ----
    if let Some(words) = &req.wordlist {
        for w in words {
            let host = format!("{}.{}", w.trim(), req.domain);
            all.entry(host).or_insert("brute".into());
        }
    }

    let total = all.len();
    let _ = app.emit("subenum:status", format!("aggregated {total} candidates — resolving"));

    // ---- DNS resolve all candidates concurrently ----
    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let hits: Vec<SubdomainHit> = stream::iter(all.into_iter())
        .map(|(host, source)| {
            let resolver = resolver.clone();
            let sem = sem.clone();
            let done = done.clone();
            let app = app.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let result = resolver.lookup_ip(host.as_str()).await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("subenum:progress", serde_json::json!({"done": n, "total": total}));
                match result {
                    Ok(lookup) => {
                        let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                        if ips.is_empty() { None } else {
                            let hit = SubdomainHit { host, source, ips };
                            let _ = app.emit("subenum:hit", hit.clone());
                            Some(hit)
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let _ = app.emit("subenum:done", hits.len());
    Ok(hits)
}
