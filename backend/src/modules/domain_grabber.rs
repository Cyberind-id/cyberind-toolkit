// ===================================================================
// Domain Grabber — mass-harvest real domains by TLD extension.
//
// Sources (researched for reliability, free, no API key):
//   - crt.sh           — cert transparency (needs keyword for bulk)
//   - commoncrawl      — CDX index over billions of crawled URLs
//   - rapiddns         — 3B+ DNS records, HTML-scrape endpoint
//   - hackertarget     — 50/day/IP hostsearch
//   - certspotter      — CT issuances (keyword required)
//   - wordlist-id      — 4k Indonesian common words + DNS resolve (bundled)
//   - wordlist-id-full — 18k KBBI dictionary + DNS resolve (bundled)
//
// IANA catalog integration: fetch iana.org/domains/root/db → 1500+ TLDs.
// ===================================================================

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

// ------------------------------------------------------------------
// Bundled Indonesian wordlists (embedded at compile time)
// ------------------------------------------------------------------

const WORDLIST_ID_KOMPAS: &str = include_str!("../../wordlists/id-kompas.lst");
const WORDLIST_ID_KBBI: &str   = include_str!("../../wordlists/id-kbbi.lst");
const WORDLIST_EN_COMMON: &str = include_str!("../../wordlists/en-common.lst");
const WORDLIST_SUBS: &str      = include_str!("../../wordlists/subs-top5k.lst");

fn parse_wordlist(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        // only DNS-valid labels: a-z 0-9 - (no spaces, no unicode)
        .filter(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .filter(|l| !l.starts_with('-') && !l.ends_with('-') && l.len() >= 2 && l.len() <= 63)
        .collect()
}

static WL_KOMPAS: Lazy<Vec<String>>    = Lazy::new(|| parse_wordlist(WORDLIST_ID_KOMPAS));
static WL_KBBI: Lazy<Vec<String>>      = Lazy::new(|| parse_wordlist(WORDLIST_ID_KBBI));
static WL_EN_COMMON: Lazy<Vec<String>> = Lazy::new(|| parse_wordlist(WORDLIST_EN_COMMON));
static WL_SUBS: Lazy<Vec<String>>      = Lazy::new(|| parse_wordlist(WORDLIST_SUBS));

pub fn wordlist_info() -> serde_json::Value {
    serde_json::json!({
        "id-kompas":  { "name": "Indonesian common (Kompas corpus)", "count": WL_KOMPAS.len() },
        "id-kbbi":    { "name": "Indonesian KBBI dictionary",        "count": WL_KBBI.len() },
        "en-common":  { "name": "English common words",              "count": WL_EN_COMMON.len() },
        "subs-top5k": { "name": "Top 5k subdomain prefixes",         "count": WL_SUBS.len() },
    })
}

// ------------------------------------------------------------------
// IANA TLD list
// ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct IanaTld {
    pub tld: String,         // e.g. ".com"
    pub kind: String,        // generic / country-code / sponsored / generic-restricted / infrastructure
    pub sponsor: String,     // registry manager
}

pub async fn iana_tld_list() -> Result<Vec<IanaTld>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent("Mozilla/5.0 (PocketPentester-DomainGrabber)")
        .build()
        .map_err(|e| e.to_string())?;

    let html = client
        .get("https://www.iana.org/domains/root/db")
        .send().await.map_err(|e| e.to_string())?
        .error_for_status().map_err(|e| e.to_string())?
        .text().await.map_err(|e| e.to_string())?;

    let row_re = Regex::new(r"(?s)<tr>(.*?)</tr>").unwrap();
    let td_re = Regex::new(r"(?s)<td[^>]*>(.*?)</td>").unwrap();
    let tag_re = Regex::new(r"<[^>]+>").unwrap();
    let ws_re = Regex::new(r"\s+").unwrap();

    let mut out: Vec<IanaTld> = Vec::new();
    for row in row_re.captures_iter(&html) {
        let row_html = &row[1];
        let cells: Vec<String> = td_re.captures_iter(row_html)
            .map(|c| {
                let plain = tag_re.replace_all(&c[1], "");
                ws_re.replace_all(plain.trim(), " ").to_string()
            })
            .collect();
        if cells.len() != 3 { continue; }
        let tld_raw = cells[0].trim().to_string();
        // skip header rows, empties, and non-TLD entries
        if !tld_raw.starts_with('.') || tld_raw.len() < 2 { continue; }
        out.push(IanaTld {
            tld: tld_raw.to_lowercase(),
            kind: cells[1].clone(),
            sponsor: cells[2].clone(),
        });
    }

    out.sort_by(|a, b| a.tld.cmp(&b.tld));
    Ok(out)
}

// ------------------------------------------------------------------
// Domain grabbing
// ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct GrabRequest {
    pub tld: String,                  // ".id" / "id" / "co.id" / "gov.uk"
    #[serde(default)]
    pub keyword: Option<String>,      // optional narrowing string
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,         // "crtsh" "urlscan" "wayback"
    #[serde(default = "default_max")]
    pub max_per_source: usize,
    #[serde(default = "default_true")]
    pub apex_only: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_wl_conc")]
    pub wordlist_concurrency: usize,
}

fn default_wl_conc() -> usize { 80 }

fn default_sources() -> Vec<String> { vec!["crtsh".into(), "rapiddns".into(), "hackertarget".into()] }
fn default_max() -> usize { 1000 }
fn default_true() -> bool { true }
fn default_timeout() -> u64 { 30_000 }

#[derive(Debug, Clone, Serialize)]
pub struct GrabHit {
    pub domain: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStat {
    pub source: String,
    pub count: usize,
    pub error: Option<String>,
    pub took_ms: u128,
}

// Known multi-label public suffixes by TLD — minimal curated list.
// For proper support you'd use the full PSL; this handles common cases.
static MULTI_SUFFIXES: Lazy<Vec<&'static str>> = Lazy::new(|| vec![
    // Indonesia
    "co.id", "ac.id", "go.id", "or.id", "mil.id", "sch.id", "net.id", "web.id", "ponpes.id", "my.id", "biz.id", "desa.id",
    // UK
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "ltd.uk", "plc.uk",
    // Japan
    "co.jp", "ac.jp", "ne.jp", "or.jp", "go.jp", "ed.jp", "lg.jp",
    // Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    // Generic
    "com.br", "com.mx", "com.ar", "com.tr", "com.sg", "com.my", "com.ph", "com.vn", "com.hk", "com.tw",
    "edu.my", "gov.my", "gov.sg",
]);

fn normalize_tld(t: &str) -> String {
    t.trim().trim_start_matches('.').to_lowercase()
}

fn apex_of(host: &str, tld: &str) -> String {
    let h = host.trim_end_matches('.').to_lowercase();
    let tld = tld.trim_start_matches('.');
    if !h.ends_with(&format!(".{}", tld)) && h != tld { return h; }

    // Check multi-label suffix: if TLD itself includes a dot (e.g. co.id input) use as-is.
    let parts: Vec<&str> = h.split('.').collect();
    // find effective suffix
    let mut eff_labels: usize = tld.split('.').count();
    for suf in MULTI_SUFFIXES.iter() {
        if h.ends_with(&format!(".{}", suf)) || h == *suf {
            eff_labels = suf.split('.').count();
            break;
        }
    }
    // apex = last (eff_labels + 1) labels
    let total = parts.len();
    let take = (eff_labels + 1).min(total);
    parts[total - take..].join(".")
}

fn host_from_url(u: &str) -> Option<String> {
    url::Url::parse(u).ok().and_then(|p| p.host_str().map(|s| s.to_lowercase()))
}

fn clean_host(s: &str, tld: &str) -> Option<String> {
    let h = s.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
    let h = h.split_whitespace().next()?.to_string();
    if h.is_empty() { return None; }
    if h.contains('@') || h.contains(' ') || h.contains('/') { return None; }
    if !h.ends_with(&format!(".{}", tld)) && h != tld { return None; }
    Some(h)
}

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

async fn fetch_with_retry(
    client: &reqwest::Client,
    url: &str,
    extra_headers: &[(&str, &str)],
    attempts: u32,
) -> anyhow::Result<String> {
    let mut last_err: Option<String> = None;
    for attempt in 1..=attempts {
        let mut req = client.get(url)
            .header("User-Agent", BROWSER_UA)
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate");
        for (k, v) in extra_headers { req = req.header(*k, *v); }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() { return Ok(body); }
                let snippet: String = body.chars().take(160).collect();
                last_err = Some(format!("HTTP {status} — {}", snippet));
                if status.as_u16() == 429 || status.is_server_error() {
                    tokio::time::sleep(Duration::from_millis(1000 * attempt as u64)).await;
                    continue;
                } else {
                    break; // 4xx other than 429 — no point retrying
                }
            }
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
            }
        }
    }
    Err(anyhow::anyhow!(last_err.unwrap_or_else(|| "unknown".into())))
}

// ---- source: crt.sh ----
async fn src_crtsh(
    client: &reqwest::Client, tld: &str, keyword: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    // crt.sh uses SQL LIKE patterns. `%` must be URL-encoded as %25.
    let q = match keyword {
        Some(k) if !k.is_empty() => format!("%25{}%25.{}", k, tld),
        _ => format!("%25.{}", tld),
    };
    let url = format!("https://crt.sh/?q={}&output=json", q);
    let body = fetch_with_retry(client, &url, &[("Referer", "https://crt.sh/")], 3).await?;
    if body.trim().is_empty() {
        anyhow::bail!("empty body (query too broad or server busy — try with a keyword)");
    }
    let val: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("json: {e} — got HTML maybe (body snippet: {})", body.chars().take(80).collect::<String>()))?;
    let arr = val.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let mut out: Vec<String> = Vec::new();
    for r in arr {
        if let Some(nv) = r.get("name_value").and_then(|v| v.as_str()) {
            for line in nv.split('\n') {
                if let Some(h) = clean_host(line, tld) { out.push(h); }
            }
        }
    }
    Ok(out)
}

// ---- source: Common Crawl CDX (billions of crawled URLs) ----
async fn src_commoncrawl(
    client: &reqwest::Client, tld: &str, keyword: Option<&str>, max: usize,
) -> anyhow::Result<Vec<String>> {
    // 1. Fetch latest collection ID
    let info_body = fetch_with_retry(client, "https://index.commoncrawl.org/collinfo.json", &[], 2).await?;
    let info: serde_json::Value = serde_json::from_str(&info_body)
        .map_err(|e| anyhow::anyhow!("collinfo json: {e}"))?;
    let collection_id = info.as_array()
        .and_then(|a| a.first())
        .and_then(|c| c.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no CC collection found"))?;

    // 2. Query CDX index for URLs matching *.{tld}
    let url_pat = match keyword {
        Some(k) if !k.is_empty() => format!("*{k}*.{tld}"),
        _ => format!("*.{tld}"),
    };
    let lim = max.min(5_000).to_string();
    let cdx_url = format!("https://index.commoncrawl.org/{}-index", collection_id);
    let url_obj = reqwest::Url::parse_with_params(
        &cdx_url,
        &[
            ("url", url_pat.as_str()),
            ("output", "json"),
            ("fl", "url"),
            ("limit", lim.as_str()),
        ],
    ).map_err(|e| anyhow::anyhow!("url build: {e}"))?;
    let body = fetch_with_retry(client, url_obj.as_str(), &[], 2).await?;
    if body.trim().is_empty() { return Ok(vec![]); }

    // NDJSON response (one JSON obj per line)
    let mut out = Vec::new();
    for line in body.lines() {
        if line.trim().is_empty() { continue; }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(u) = val.get("url").and_then(|v| v.as_str()) {
                if let Some(h) = host_from_url(u) {
                    if let Some(cleaned) = clean_host(&h, tld) { out.push(cleaned); }
                }
            }
        }
    }
    Ok(out)
}

// ---- source: rapiddns.io (3B+ DNS records, HTML scrape) ----
async fn src_rapiddns(
    client: &reqwest::Client, tld: &str, keyword: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    // rapiddns supports: /subdomain/DOMAIN (needs full domain) or /s/KEYWORD?full=1
    let url = match keyword {
        Some(k) if !k.is_empty() => {
            // keyword-based search returns domains matching a substring
            format!("https://rapiddns.io/s/{}.{}?full=1", k, tld)
        }
        _ => format!("https://rapiddns.io/s/{}?full=1", tld),
    };
    let html = fetch_with_retry(client, &url, &[
        ("Referer", "https://rapiddns.io/"),
    ], 2).await?;

    // parse HTML table rows: <td>domain.tld</td>
    let re = Regex::new(r#"<td[^>]*>([a-zA-Z0-9_.\-]+\.[a-zA-Z]{2,})</td>"#)?;
    let mut out = Vec::new();
    for cap in re.captures_iter(&html) {
        if let Some(m) = cap.get(1) {
            if let Some(h) = clean_host(m.as_str(), tld) { out.push(h); }
        }
    }
    Ok(out)
}

// ---- source: hackertarget (50 queries/day per IP, no key) ----
async fn src_hackertarget(
    client: &reqwest::Client, tld: &str, keyword: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let domain = match keyword {
        Some(k) if !k.is_empty() => format!("{k}.{tld}"),
        _ => anyhow::bail!("hackertarget needs a keyword (e.g. 'gov' + 'id' → 'gov.id'); TLD-only not supported"),
    };
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let body = fetch_with_retry(client, &url, &[], 2).await?;
    if body.contains("API count exceeded") || body.contains("error check your search") {
        anyhow::bail!("rate limited (50/day/IP exhausted)");
    }
    let mut out = Vec::new();
    for line in body.lines() {
        if let Some((host, _)) = line.split_once(',') {
            if let Some(h) = clean_host(host, tld) { out.push(h); }
        }
    }
    Ok(out)
}

// ---- source: wordlist DNS brute + HTTP alive check ----
//
// For each word generates multiple candidate patterns, then two-stage verify:
//   1. DNS resolve (fast-fail if NXDOMAIN)
//   2. HTTP GET https:// or http:// — must respond with status 200-599
//      (treating ANY HTTP response as alive proof, even 4xx/5xx)
//
// Kills false positives from parking pages / wildcard DNS domains that
// resolve but serve nothing.
async fn src_wordlist(
    tld: &str, keyword: Option<&str>, words: &[String], concurrency: usize,
    app: &AppHandle, source_name: &str,
) -> anyhow::Result<Vec<String>> {
    // --- stage 0: build unique candidate set ---
    let mut cand_set: HashSet<String> = HashSet::new();
    for w in words {
        let w = w.trim();
        if w.is_empty() { continue; }
        match keyword {
            Some(k) if !k.is_empty() => {
                cand_set.insert(format!("{w}.{k}.{tld}"));
                cand_set.insert(format!("www.{w}.{k}.{tld}"));
                cand_set.insert(format!("{w}-{k}.{tld}"));
                cand_set.insert(format!("{k}-{w}.{tld}"));
            }
            _ => {
                cand_set.insert(format!("{w}.{tld}"));
                cand_set.insert(format!("www.{w}.{tld}"));
            }
        }
    }
    let candidates: Vec<String> = cand_set.into_iter().collect();
    let total = candidates.len();
    let _ = app.emit("grab:status",
        format!("[{source_name}] {total} patterns to brute (dns + http check)"));

    // --- shared resolver + http client ---
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(1500);
    opts.attempts = 1;
    let resolver = Arc::new(TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts));

    let http = Arc::new(
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(2500))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Mozilla/5.0 (PocketPentester-DomainGrabber)")
            .build()
            .map_err(|e| anyhow::anyhow!("http client: {e}"))?,
    );

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let src_name = source_name.to_string();

    let resolved: Vec<String> = stream::iter(candidates.into_iter())
        .map(|host| {
            let resolver = resolver.clone();
            let http = http.clone();
            let sem = sem.clone();
            let done = done.clone();
            let app = app.clone();
            let src_name = src_name.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();

                // stage 1: DNS — fast fail
                let dns_ok = resolver.lookup_ip(host.as_str()).await.is_ok();
                let host_out = if dns_ok {
                    // stage 2: HTTP alive — try https then http
                    let mut alive = false;
                    for scheme in ["https", "http"] {
                        let url = format!("{scheme}://{host}");
                        if let Ok(resp) = http.get(&url).send().await {
                            let s = resp.status().as_u16();
                            if (200..600).contains(&s) { alive = true; break; }
                        }
                    }
                    if alive { Some(host) } else { None }
                } else { None };

                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if n % 100 == 0 || n == total {
                    let _ = app.emit("grab:wl-progress",
                        serde_json::json!({ "source": src_name, "done": n, "total": total }));
                }
                host_out
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    Ok(resolved)
}

// ---- source: certspotter (fallback — CT log, very reliable) ----
async fn src_certspotter(
    client: &reqwest::Client, tld: &str, keyword: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    // certspotter doesn't support TLD wildcard natively, but we can query a
    // well-known keyword+TLD (e.g. "gov.id") to pull all matching certs.
    let domain = match keyword {
        Some(k) if !k.is_empty() => format!("{k}.{tld}"),
        _ => anyhow::bail!("certspotter needs a keyword (e.g. gov, bank) — tld-only not supported"),
    };
    let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", domain);
    let body = fetch_with_retry(client, &url, &[], 2).await?;
    let val: serde_json::Value = serde_json::from_str(&body)?;
    let arr = val.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let mut out = Vec::new();
    for r in arr {
        if let Some(names) = r.get("dns_names").and_then(|v| v.as_array()) {
            for n in names {
                if let Some(s) = n.as_str() {
                    if let Some(h) = clean_host(s, tld) { out.push(h); }
                }
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------
// Orchestrator
// ------------------------------------------------------------------

pub async fn domain_grab(app: AppHandle, req: GrabRequest) -> Result<Vec<GrabHit>, String> {
    let tld = normalize_tld(&req.tld);
    if tld.is_empty() { return Err("empty tld".into()); }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(req.timeout_ms))
        .user_agent("Mozilla/5.0 (PocketPentester-DomainGrabber)")
        .build()
        .map_err(|e| e.to_string())?;

    let _ = app.emit("grab:status",
        format!("grabbing .{tld}{} from {} source(s)",
            req.keyword.as_deref().map(|k| format!(" /keyword={k}")).unwrap_or_default(),
            req.sources.len()));

    let seen: Arc<tokio::sync::Mutex<HashSet<String>>> = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let mut all: Vec<GrabHit> = Vec::new();

    let results = futures::future::join_all(req.sources.iter().map(|name| {
        let client = client.clone();
        let tld = tld.clone();
        let keyword = req.keyword.clone();
        let name = name.clone();
        let app = app.clone();
        let max = req.max_per_source;
        let wl_conc = req.wordlist_concurrency;
        async move {
            let started = std::time::Instant::now();
            let res = match name.as_str() {
                "crtsh"             => src_crtsh(&client, &tld, keyword.as_deref()).await,
                "commoncrawl"       => src_commoncrawl(&client, &tld, keyword.as_deref(), max).await,
                "rapiddns"          => src_rapiddns(&client, &tld, keyword.as_deref()).await,
                "hackertarget"      => src_hackertarget(&client, &tld, keyword.as_deref()).await,
                "certspotter"       => src_certspotter(&client, &tld, keyword.as_deref()).await,
                "wordlist-id"       => src_wordlist(&tld, keyword.as_deref(), &WL_KOMPAS,    wl_conc, &app, &name).await,
                "wordlist-id-full"  => src_wordlist(&tld, keyword.as_deref(), &WL_KBBI,      wl_conc, &app, &name).await,
                "wordlist-en"       => src_wordlist(&tld, keyword.as_deref(), &WL_EN_COMMON, wl_conc, &app, &name).await,
                "wordlist-subs"     => src_wordlist(&tld, keyword.as_deref(), &WL_SUBS,      wl_conc, &app, &name).await,
                other               => Err(anyhow::anyhow!("unknown source: {other}")),
            };
            let took = started.elapsed().as_millis();
            let stat = match &res {
                Ok(list) => SourceStat { source: name.clone(), count: list.len(), error: None, took_ms: took },
                Err(e) => SourceStat { source: name.clone(), count: 0, error: Some(e.to_string()), took_ms: took },
            };
            let _ = app.emit("grab:source", stat);
            (name, res)
        }
    })).await;

    for (name, res) in results {
        if let Ok(list) = res {
            let mut added = 0usize;
            for host in list.into_iter().take(req.max_per_source * 4) {
                let key = if req.apex_only { apex_of(&host, &tld) } else { host.clone() };
                let mut guard = seen.lock().await;
                if guard.insert(key.clone()) {
                    drop(guard);
                    let hit = GrabHit { domain: key, source: name.clone() };
                    let _ = app.emit("grab:hit", hit.clone());
                    all.push(hit);
                    added += 1;
                    if added >= req.max_per_source { break; }
                }
            }
        }
    }

    let _ = app.emit("grab:done", all.len());
    Ok(all)
}
