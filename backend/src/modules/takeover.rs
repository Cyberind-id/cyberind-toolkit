use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub service: &'static str,
    pub cname_patterns: &'static [&'static str],
    pub body_match: &'static [&'static str],
    pub http_status: Option<u16>,
    pub vulnerable: bool,
    pub confidence: &'static str,
}

static FINGERPRINTS: Lazy<Vec<Fingerprint>> = Lazy::new(|| {
    vec![
        Fingerprint {
            service: "AWS/S3",
            cname_patterns: &["s3.amazonaws.com", "s3-website"],
            body_match: &["NoSuchBucket", "The specified bucket does not exist"],
            http_status: Some(404),
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "GitHub Pages",
            cname_patterns: &["github.io", "github.map.fastly.net"],
            body_match: &["There isn't a GitHub Pages site here", "For root URLs"],
            http_status: Some(404),
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Heroku",
            cname_patterns: &["herokuapp.com", "herokussl.com"],
            body_match: &["no-such-app", "No such app"],
            http_status: Some(404),
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Shopify",
            cname_patterns: &["myshopify.com"],
            body_match: &["Sorry, this shop is currently unavailable"],
            http_status: None,
            vulnerable: true,
            confidence: "MEDIUM",
        },
        Fingerprint {
            service: "Azure",
            cname_patterns: &[
                "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                "trafficmanager.net", "blob.core.windows.net", "azureedge.net",
                "azure-api.net", "azurecontainer.io",
            ],
            body_match: &["404 Web Site not found", "Error 404 - Web app not found"],
            http_status: Some(404),
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Fastly",
            cname_patterns: &["fastly.net"],
            body_match: &["Fastly error: unknown domain"],
            http_status: None,
            vulnerable: true,
            confidence: "MEDIUM",
        },
        Fingerprint {
            service: "Readme.io",
            cname_patterns: &["readme.io"],
            body_match: &["Project doesnt exist... yet!"],
            http_status: None,
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Tumblr",
            cname_patterns: &["domains.tumblr.com"],
            body_match: &["Whatever you were looking for doesn't currently exist"],
            http_status: None,
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Unbounce",
            cname_patterns: &["unbouncepages.com"],
            body_match: &["The requested URL was not found on this server"],
            http_status: None,
            vulnerable: true,
            confidence: "MEDIUM",
        },
        Fingerprint {
            service: "Ghost",
            cname_patterns: &["ghost.io"],
            body_match: &["The thing you were looking for is no longer here"],
            http_status: None,
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Pantheon",
            cname_patterns: &["pantheonsite.io"],
            body_match: &["The gods are wise, but do not know of the site which you seek"],
            http_status: None,
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Zendesk",
            cname_patterns: &["zendesk.com"],
            body_match: &["Help Center Closed"],
            http_status: None,
            vulnerable: true,
            confidence: "LOW",
        },
        Fingerprint {
            service: "Surge.sh",
            cname_patterns: &["surge.sh"],
            body_match: &["project not found"],
            http_status: None,
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Bitbucket",
            cname_patterns: &["bitbucket.io"],
            body_match: &["Repository not found"],
            http_status: None,
            vulnerable: true,
            confidence: "HIGH",
        },
        Fingerprint {
            service: "Netlify",
            cname_patterns: &["netlify.app", "netlify.com"],
            body_match: &["Not Found - Request ID"],
            http_status: Some(404),
            vulnerable: true,
            confidence: "MEDIUM",
        },
        Fingerprint {
            service: "Vercel",
            cname_patterns: &["vercel.app", "now.sh"],
            body_match: &["The deployment could not be found"],
            http_status: Some(404),
            vulnerable: true,
            confidence: "MEDIUM",
        },
        Fingerprint {
            service: "Cargo",
            cname_patterns: &["cargocollective.com"],
            body_match: &["404 Not Found"],
            http_status: None,
            vulnerable: true,
            confidence: "LOW",
        },
        Fingerprint {
            service: "Statuspage",
            cname_patterns: &["statuspage.io"],
            body_match: &["You are being redirected"],
            http_status: None,
            vulnerable: false,
            confidence: "LOW",
        },
    ]
});

#[derive(Debug, Clone, Deserialize)]
pub struct TakeoverRequest {
    pub hosts: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TakeoverFinding {
    pub host: String,
    pub cname: Option<String>,
    pub service: Option<String>,
    pub vulnerable: bool,
    pub confidence: String,
    pub evidence: String,
    pub http_status: Option<u16>,
}

async fn check_host(
    host: &str,
    resolver: &TokioAsyncResolver,
    client: &reqwest::Client,
) -> Option<TakeoverFinding> {
    // 1. lookup CNAME
    let cname = resolver
        .lookup(host.to_string(), hickory_resolver::proto::rr::RecordType::CNAME)
        .await
        .ok()
        .and_then(|lookup| lookup.iter().next().map(|r| r.to_string().trim_end_matches('.').to_string()));

    let cname = cname?;

    // 2. match CNAME against fingerprint DB
    let fp = FINGERPRINTS.iter().find(|f| {
        f.cname_patterns
            .iter()
            .any(|p| cname.to_lowercase().contains(&p.to_lowercase()))
    })?;

    // 3. probe HTTP for confirmation
    let urls = [format!("https://{host}"), format!("http://{host}")];
    let mut http_status: Option<u16> = None;
    let mut body = String::new();

    for u in &urls {
        if let Ok(resp) = client.get(u).send().await {
            http_status = Some(resp.status().as_u16());
            body = resp.text().await.unwrap_or_default();
            if !body.is_empty() {
                break;
            }
        }
    }

    let mut matched = false;
    let mut evidence = String::new();
    for pat in fp.body_match {
        if body.to_lowercase().contains(&pat.to_lowercase()) {
            matched = true;
            evidence = format!("body contains: \"{pat}\"");
            break;
        }
    }

    if !matched {
        if let (Some(expected), Some(actual)) = (fp.http_status, http_status) {
            if expected == actual {
                evidence = format!("cname match + status {actual} (body signature missing — likely reclaimed)");
                matched = true;
            }
        }
    }

    // always report cname-fingerprinted hosts; vulnerability flag based on body confirm
    Some(TakeoverFinding {
        host: host.to_string(),
        cname: Some(cname),
        service: Some(fp.service.to_string()),
        vulnerable: matched && fp.vulnerable,
        confidence: if matched { fp.confidence.to_string() } else { "INFO".into() },
        evidence: if evidence.is_empty() {
            format!("cname points to {} (no takeover indicators)", fp.service)
        } else {
            evidence
        },
        http_status,
    })
}

pub async fn takeover_scan(
    app: AppHandle,
    req: TakeoverRequest,
) -> Result<Vec<TakeoverFinding>, String> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    let resolver = Arc::new(TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts));

    let client = Arc::new(
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(req.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Mozilla/5.0 (PocketPentester)")
            .build()
            .map_err(|e| e.to_string())?,
    );

    let total = req.hosts.len();
    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let findings: Vec<TakeoverFinding> = stream::iter(req.hosts.into_iter())
        .map(|host| {
            let resolver = resolver.clone();
            let client = client.clone();
            let sem = sem.clone();
            let done = done.clone();
            let app = app.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let res = check_host(&host, &resolver, &client).await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("takeover:progress", serde_json::json!({"done": n, "total": total}));
                if let Some(ref f) = res {
                    let _ = app.emit("takeover:hit", f.clone());
                }
                res
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let _ = app.emit("takeover:done", findings.len());
    Ok(findings)
}
