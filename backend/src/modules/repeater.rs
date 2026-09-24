// ===================================================================
// Repeater — Burp-style manual HTTP request sender.
// Full control: method, URL, headers, body. Returns full response.
// ===================================================================

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct RepeaterRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub ignore_tls: bool,
}

fn default_timeout() -> u64 { 15_000 }

#[derive(Debug, Clone, Serialize)]
pub struct RepeaterResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub body_len: usize,
    pub content_type: Option<String>,
    pub time_ms: u128,
    pub final_url: String,
    pub redirected: bool,
    pub is_text: bool,
}

pub async fn repeater_send(req: RepeaterRequest) -> Result<RepeaterResponse, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(req.ignore_tls)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent("Mozilla/5.0 (PocketPentester-Repeater)")
        .build()
        .map_err(|e| e.to_string())?;

    let method = reqwest::Method::from_bytes(req.method.to_uppercase().as_bytes())
        .map_err(|e| format!("bad method: {e}"))?;

    let mut builder = client.request(method, &req.url);
    for (k, v) in &req.headers {
        if k.trim().is_empty() { continue; }
        builder = builder.header(k.trim(), v);
    }
    if let Some(body) = &req.body {
        if !body.is_empty() {
            builder = builder.body(body.clone());
        }
    }

    let start = Instant::now();
    let resp = builder.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let version = format!("{:?}", resp.version());
    let final_url = resp.url().to_string();
    let redirected = final_url != req.url;

    let headers: Vec<(String, String)> = resp.headers().iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let content_type = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok()).map(String::from);

    let is_text = content_type.as_deref().map(|c| {
        c.starts_with("text/") || c.contains("json") || c.contains("xml")
            || c.contains("javascript") || c.contains("html") || c.contains("form-urlencoded")
    }).unwrap_or(true);

    let body = resp.text().await.unwrap_or_default();
    let elapsed = start.elapsed().as_millis();

    Ok(RepeaterResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or("").into(),
        http_version: version,
        headers,
        body_len: body.len(),
        body,
        content_type,
        time_ms: elapsed,
        final_url,
        redirected,
        is_text,
    })
}

pub fn repeater_to_curl(req: RepeaterRequest) -> String {
    let mut parts: Vec<String> = vec!["curl".into(), "-i".into()];
    if req.ignore_tls { parts.push("-k".into()); }
    if req.follow_redirects { parts.push("-L".into()); }
    if req.method.to_uppercase() != "GET" {
        parts.push("-X".into());
        parts.push(req.method.to_uppercase());
    }
    for (k, v) in &req.headers {
        if k.trim().is_empty() { continue; }
        parts.push("-H".into());
        parts.push(format!("'{}: {}'", k.trim(), v.replace('\'', "'\\''")));
    }
    if let Some(body) = &req.body {
        if !body.is_empty() {
            parts.push("--data-raw".into());
            parts.push(format!("'{}'", body.replace('\'', "'\\''")));
        }
    }
    parts.push(format!("'{}'", req.url));
    parts.join(" ")
}
