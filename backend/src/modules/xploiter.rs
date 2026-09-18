// ===================================================================
// Xploiter — pure-Rust template-driven vulnerability scanner
// Author: imtaqin / PocketPentester
//
// Template format (YAML) — compatible with most Nuclei patterns plus
// our own extensions. Covers: RCE, SQLi patterns, LFI, SSRF, open
// redirect, info-exposure, CVE chains, and user-authored templates.
//
// TODO(backend): community template registry with signed/curated
//                sharing is planned as a subscription-gated cloud
//                service. For now, templates are local-only.
// TODO(backend): OOB interaction server (interact.sh-lite) for blind
//                RCE/SSRF/XXE detection. To be shipped with cloud tier.
// ===================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

// ------------------------------------------------------------------
// Template schema
// ------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub id: String,
    pub info: TemplateInfo,

    #[serde(default)]
    pub variables: HashMap<String, String>,

    /// Global payload sets shared across requests (referenced by name).
    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,

    /// Sequential HTTP requests. Extractors in step N populate variables
    /// available to step N+1 (basic workflow chaining).
    #[serde(default)]
    pub http: Vec<HttpRequest>,

    /// Alias for `http` (Nuclei compatibility).
    #[serde(default)]
    pub requests: Vec<HttpRequest>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TemplateInfo {
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default = "default_sev")]
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub reference: Vec<String>,
    #[serde(default)]
    pub classification: Option<Classification>,
    #[serde(default)]
    pub remediation: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Classification {
    #[serde(default)]
    pub cvss_score: Option<f32>,
    #[serde(default)]
    pub cve_id: Option<String>,
    #[serde(default)]
    pub cwe_id: Option<Vec<String>>,
}

fn default_sev() -> String { "info".into() }

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct HttpRequest {
    #[serde(default = "default_method")]
    pub method: String,

    /// Path list — each path is templated. Each entry spawns one sub-request
    /// (unless payload-substitution expands it further).
    pub path: Vec<String>,

    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(default)]
    pub body: Option<String>,

    /// Request-local variables (merged with template-global + extracted).
    #[serde(default)]
    pub variables: HashMap<String, String>,

    /// Payload injection: each key is a `{{placeholder}}` replaced by each
    /// value from the list (cartesian unless `attack: pitchfork|clusterbomb`).
    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,

    #[serde(default = "default_attack")]
    pub attack: String, // "batteringram" (single list) or "clusterbomb"

    #[serde(default = "default_match_cond")]
    pub matchers_condition: String,

    #[serde(default)]
    pub matchers: Vec<Matcher>,

    #[serde(default)]
    pub extractors: Vec<Extractor>,

    #[serde(default)]
    pub stop_at_first_match: bool,

    #[serde(default = "default_true")]
    pub redirects: bool,

    /// Raw HTTP for smuggling / control-char testing (optional).
    #[serde(default)]
    pub raw: Option<String>,
}

fn default_method() -> String { "GET".into() }
fn default_match_cond() -> String { "or".into() }
fn default_attack() -> String { "batteringram".into() }
fn default_true() -> bool { true }

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub kind: String, // word | regex | status | size | dsl | binary
    #[serde(default)]
    pub part: Option<String>, // body | header | all | interactsh_protocol
    #[serde(default)]
    pub words: Option<Vec<String>>,
    #[serde(default)]
    pub regex: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    #[serde(default)]
    pub size: Option<Vec<u64>>,
    #[serde(default)]
    pub binary: Option<Vec<String>>, // hex
    #[serde(default)]
    pub dsl: Option<Vec<String>>, // simple DSL: see eval_dsl
    #[serde(default = "default_match_cond")]
    pub condition: String,
    #[serde(default)]
    pub negative: bool,
    #[serde(default)]
    pub name: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub kind: String, // regex | kval | json
    #[serde(default)]
    pub part: Option<String>,
    #[serde(default)]
    pub regex: Option<Vec<String>>,
    #[serde(default)]
    pub kval: Option<Vec<String>>, // header/cookie keys
    #[serde(default)]
    pub json: Option<Vec<String>>, // dotted path e.g. "token.access"
    #[serde(default)]
    pub group: Option<usize>,
    #[serde(default)]
    pub name: Option<String>,
    /// If set, extracted values become template variables for next requests.
    #[serde(default)]
    pub internal: bool,
}

// ------------------------------------------------------------------
// Runtime
// ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct RunRequest {
    pub targets: Vec<String>,
    pub templates_yaml: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub target: String,
    pub matched_url: String,
    pub status: u16,
    pub matcher_names: Vec<String>,
    pub extracted: HashMap<String, Vec<String>>,
    pub description: String,
    pub remediation: Option<String>,
    pub reference: Vec<String>,
    pub cvss: Option<f32>,
    pub cve_id: Option<String>,
}

// helpers ----------------------------------------------------------

fn randstr(n: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..n).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Expand `{{var}}` and helper placeholders inside a template string.
fn expand(s: &str, vars: &HashMap<String, String>) -> String {
    let mut out = s.to_string();
    // helpers
    out = out.replace("{{randstr}}", &randstr(10));
    out = out.replace("{{rand_int}}", &rand::thread_rng().gen_range(1000..9999).to_string());
    out = out.replace("{{unix_time}}", &now_unix().to_string());
    // user variables
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

fn part_of(part: &str, status: u16, headers: &reqwest::header::HeaderMap, body: &str) -> String {
    match part {
        "header" | "headers" => headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n"),
        "body" | "" => body.to_string(),
        "all" => format!(
            "HTTP/1.1 {}\n{}\n\n{}",
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or(""))).collect::<Vec<_>>().join("\n"),
            body
        ),
        _ => body.to_string(),
    }
}

fn check_matcher(m: &Matcher, status: u16, headers: &reqwest::header::HeaderMap, body: &str, duration_ms: u128) -> bool {
    let part = m.part.as_deref().unwrap_or("body");
    let haystack = part_of(part, status, headers, body);

    let result = match m.kind.as_str() {
        "status" => m.status.as_ref().is_some_and(|s| s.contains(&status)),
        "word" => {
            if let Some(words) = &m.words {
                if m.condition == "and" {
                    words.iter().all(|w| haystack.contains(w))
                } else {
                    words.iter().any(|w| haystack.contains(w))
                }
            } else { false }
        }
        "regex" => {
            if let Some(patterns) = &m.regex {
                let regs: Vec<Regex> = patterns.iter().filter_map(|p| Regex::new(p).ok()).collect();
                if m.condition == "and" {
                    regs.iter().all(|re| re.is_match(&haystack))
                } else {
                    regs.iter().any(|re| re.is_match(&haystack))
                }
            } else { false }
        }
        "size" => m.size.as_ref().is_some_and(|s| s.contains(&(body.len() as u64))),
        "binary" => {
            // hex bytes match anywhere in body
            if let Some(patterns) = &m.binary {
                patterns.iter().any(|hex| {
                    let bytes: Vec<u8> = (0..hex.len())
                        .step_by(2)
                        .filter_map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("00"), 16).ok())
                        .collect();
                    body.as_bytes().windows(bytes.len()).any(|w| w == bytes.as_slice())
                })
            } else { false }
        }
        "dsl" => {
            // minimal DSL: `duration > 5000`, `status == 200`, `contains(body, "foo")`
            if let Some(exprs) = &m.dsl {
                let ok = |e: &str| eval_dsl(e, status, body, duration_ms);
                if m.condition == "and" { exprs.iter().all(|e| ok(e)) }
                else { exprs.iter().any(|e| ok(e)) }
            } else { false }
        }
        _ => false,
    };
    if m.negative { !result } else { result }
}

fn eval_dsl(expr: &str, status: u16, body: &str, duration_ms: u128) -> bool {
    // SUPER minimal DSL — extend as needed. Supports:
    //   status == N | status != N | status >= N | status <= N
    //   duration > N | duration < N  (milliseconds)
    //   size > N | size < N
    //   contains(body, "text")
    //   regex(body, "pat")
    let e = expr.trim();

    if let Some(rest) = e.strip_prefix("contains(body,") {
        let t = rest.trim_end_matches(')').trim().trim_matches('"');
        return body.contains(t);
    }
    if let Some(rest) = e.strip_prefix("regex(body,") {
        let t = rest.trim_end_matches(')').trim().trim_matches('"');
        return Regex::new(t).map(|re| re.is_match(body)).unwrap_or(false);
    }

    let parse_binop = |lhs: &str, input: &str| -> Option<(u128, &'static str, u128)> {
        let cleaned = input.trim();
        let rest = cleaned.strip_prefix(lhs)?.trim_start();
        for op in [">=", "<=", "==", "!=", ">", "<"] {
            if let Some(r) = rest.strip_prefix(op) {
                if let Ok(n) = r.trim().parse::<u128>() {
                    let lhs_val = match lhs {
                        "status" => status as u128,
                        "duration" => duration_ms,
                        "size" => body.len() as u128,
                        _ => return None,
                    };
                    let op_tag: &'static str = match op {
                        ">=" => ">=", "<=" => "<=", "==" => "==",
                        "!=" => "!=", ">" => ">", "<" => "<", _ => "==",
                    };
                    return Some((lhs_val, op_tag, n));
                }
            }
        }
        None
    };

    for lhs in ["status", "duration", "size"] {
        if let Some((a, op, b)) = parse_binop(lhs, e) {
            return match op {
                "==" => a == b, "!=" => a != b,
                ">" => a > b, "<" => a < b,
                ">=" => a >= b, "<=" => a <= b,
                _ => false,
            };
        }
    }
    false
}

fn run_extractors(extractors: &[Extractor], status: u16, headers: &reqwest::header::HeaderMap, body: &str)
    -> HashMap<String, Vec<String>>
{
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for ex in extractors {
        let part = ex.part.as_deref().unwrap_or("body");
        let name = ex.name.clone().unwrap_or_else(|| "extracted".into());
        match ex.kind.as_str() {
            "regex" => {
                let Some(patterns) = &ex.regex else { continue };
                let haystack = part_of(part, status, headers, body);
                let group = ex.group.unwrap_or(0);
                for p in patterns {
                    if let Ok(re) = Regex::new(p) {
                        for cap in re.captures_iter(&haystack) {
                            if let Some(m) = cap.get(group) {
                                out.entry(name.clone()).or_default().push(m.as_str().to_string());
                            }
                        }
                    }
                }
            }
            "kval" => {
                let Some(keys) = &ex.kval else { continue };
                for k in keys {
                    if let Some(v) = headers.get(k).and_then(|v| v.to_str().ok()) {
                        out.entry(k.clone()).or_default().push(v.to_string());
                    }
                }
            }
            "json" => {
                let Some(paths) = &ex.json else { continue };
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
                    for p in paths {
                        if let Some(v) = json_lookup(&val, p) {
                            out.entry(p.clone()).or_default().push(
                                v.as_str().map(String::from).unwrap_or_else(|| v.to_string())
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn json_lookup<'a>(val: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = val;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn expand_payloads(path: &str, payloads: &HashMap<String, Vec<String>>, attack: &str) -> Vec<HashMap<String, String>> {
    // returns list of var-substitution maps — one per payload combination
    let used: Vec<(&String, &Vec<String>)> = payloads.iter()
        .filter(|(k, _)| path.contains(&format!("{{{{{k}}}}}")))
        .collect();
    if used.is_empty() { return vec![HashMap::new()]; }

    match attack {
        "batteringram" => {
            // single-list: all placeholders get same index value
            if let Some(max) = used.iter().map(|(_, v)| v.len()).max() {
                (0..max).map(|i| {
                    used.iter().map(|(k, v)| {
                        let s = v.get(i).or_else(|| v.first()).cloned().unwrap_or_default();
                        ((*k).clone(), s)
                    }).collect()
                }).collect()
            } else { vec![HashMap::new()] }
        }
        "pitchfork" => {
            // parallel — each list iterates in lockstep
            if let Some(min) = used.iter().map(|(_, v)| v.len()).min() {
                (0..min).map(|i| {
                    used.iter().map(|(k, v)| ((*k).clone(), v[i].clone())).collect()
                }).collect()
            } else { vec![HashMap::new()] }
        }
        _ => {
            // clusterbomb (cartesian)
            let mut results: Vec<HashMap<String, String>> = vec![HashMap::new()];
            for (k, vals) in &used {
                let mut next: Vec<HashMap<String, String>> = Vec::new();
                for base in &results {
                    for v in vals.iter() {
                        let mut m = base.clone();
                        m.insert((*k).clone(), v.clone());
                        next.push(m);
                    }
                }
                results = next;
            }
            results
        }
    }
}

pub async fn run_template_against_target(
    client: &reqwest::Client,
    target: &str,
    tpl: &Template,
    app: &AppHandle,
    event_prefix: &str,
) -> Vec<Finding> {
    let ev_status = format!("{event_prefix}:status");
    let ev_hit = format!("{event_prefix}:hit");
    let mut out: Vec<Finding> = Vec::new();

    // runtime variables (template globals + extracted from prior requests)
    let mut rt_vars: HashMap<String, String> = tpl.variables.clone();
    rt_vars.insert("BaseURL".into(), target.trim_end_matches('/').to_string());
    rt_vars.insert("Hostname".into(), target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .split('/').next().unwrap_or("").to_string());

    let requests: Vec<&HttpRequest> = tpl.http.iter().chain(tpl.requests.iter()).collect();

    'per_request: for rq in requests {
        // merge request-local variables
        let mut vars = rt_vars.clone();
        for (k, v) in &rq.variables { vars.insert(k.clone(), v.clone()); }

        // combine template-level + request-level payloads
        let mut all_payloads = tpl.payloads.clone();
        for (k, v) in &rq.payloads { all_payloads.insert(k.clone(), v.clone()); }

        for raw_path in &rq.path {
            let payload_sets = expand_payloads(raw_path, &all_payloads, &rq.attack);

            for pset in &payload_sets {
                let mut iter_vars = vars.clone();
                for (k, v) in pset { iter_vars.insert(k.clone(), v.clone()); }

                let final_path = expand(raw_path, &iter_vars);
                let method = reqwest::Method::from_bytes(rq.method.as_bytes())
                    .unwrap_or(reqwest::Method::GET);
                let mut builder = client.request(method, &final_path);
                for (k, v) in &rq.headers {
                    builder = builder.header(expand(k, &iter_vars), expand(v, &iter_vars));
                }
                if let Some(body) = &rq.body {
                    builder = builder.body(expand(body, &iter_vars));
                }

                let start = Instant::now();
                let resp = match builder.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = app.emit(ev_status.as_str(), format!("req err [{}]: {e}", tpl.id));
                        continue;
                    }
                };
                let status = resp.status().as_u16();
                let hdrs = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();
                let duration = start.elapsed().as_millis();

                // matchers
                let cond = rq.matchers_condition.as_str();
                let results: Vec<(bool, String)> = rq.matchers.iter()
                    .map(|m| (check_matcher(m, status, &hdrs, &body, duration),
                              m.name.clone().unwrap_or_else(|| m.kind.clone())))
                    .collect();
                let matched = if results.is_empty() { false }
                    else if cond == "and" { results.iter().all(|(r, _)| *r) }
                    else { results.iter().any(|(r, _)| *r) };

                // extractors (always run — populate variables for chained reqs)
                let extracted = run_extractors(&rq.extractors, status, &hdrs, &body);
                for ex in &rq.extractors {
                    if ex.internal {
                        if let Some(name) = &ex.name {
                            if let Some(vals) = extracted.get(name) {
                                if let Some(first) = vals.first() {
                                    rt_vars.insert(name.clone(), first.clone());
                                }
                            }
                        }
                    }
                }

                if matched {
                    let finding = Finding {
                        template_id: tpl.id.clone(),
                        template_name: tpl.info.name.clone(),
                        severity: tpl.info.severity.clone(),
                        tags: tpl.info.tags.clone(),
                        target: target.to_string(),
                        matched_url: final_path,
                        status,
                        matcher_names: results.into_iter().filter(|(r, _)| *r).map(|(_, n)| n).collect(),
                        extracted,
                        description: tpl.info.description.clone(),
                        remediation: tpl.info.remediation.clone(),
                        reference: tpl.info.reference.clone(),
                        cvss: tpl.info.classification.as_ref().and_then(|c| c.cvss_score),
                        cve_id: tpl.info.classification.as_ref().and_then(|c| c.cve_id.clone()),
                    };
                    let _ = app.emit(ev_hit.as_str(), finding.clone());
                    out.push(finding);
                    if rq.stop_at_first_match { break 'per_request; }
                }
            }
        }
    }
    out
}

pub fn parse_templates(yamls: &[String], app: &AppHandle, error_event: &str) -> Vec<Template> {
    yamls.iter()
        .filter_map(|y| match serde_yaml::from_str::<Template>(y) {
            Ok(t) => Some(t),
            Err(e) => {
                let _ = app.emit(error_event, format!("template parse error: {e}"));
                None
            }
        })
        .collect()
}

pub async fn xploit_run(app: AppHandle, req: RunRequest) -> Result<Vec<Finding>, String> {
    let templates = parse_templates(&req.templates_yaml, &app, "xpl:status");

    if templates.is_empty() {
        return Err("no valid templates loaded".into());
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Mozilla/5.0 (Xploiter)")
        .build()
        .map_err(|e| e.to_string())?;

    let tasks: Vec<(String, Template)> = req.targets.iter()
        .flat_map(|t| templates.iter().map(move |tpl| (t.clone(), tpl.clone())))
        .collect();
    let total = tasks.len();
    let _ = app.emit("xpl:status", format!("running {} target×template combo(s)", total));

    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let client = Arc::new(client);
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let all: Vec<Finding> = stream::iter(tasks.into_iter())
        .map(|(target, tpl)| {
            let sem = sem.clone();
            let client = client.clone();
            let done = done.clone();
            let app = app.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let v = run_template_against_target(&client, &target, &tpl, &app, "xpl").await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("xpl:progress", serde_json::json!({"done": n, "total": total}));
                v
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .flat_map(|v| stream::iter(v.into_iter()))
        .collect()
        .await;

    let _ = app.emit("xpl:done", all.len());
    Ok(all)
}
