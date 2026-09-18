// ===================================================================
// Directory Fuzzer — feroxbuster-style content discovery.
// Streams hits via events. Supports extensions, recursion, filters.
// ===================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::{Mutex, Semaphore};

#[derive(Debug, Clone, Deserialize)]
pub struct DirFuzzRequest {
    pub base_url: String,
    pub wordlist: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub accept_status: Option<Vec<u16>>,
    #[serde(default)]
    pub size_min: Option<u64>,
    #[serde(default)]
    pub size_max: Option<u64>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default = "default_depth")]
    pub recursion_depth: u8,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

fn default_depth() -> u8 { 2 }

#[derive(Debug, Clone, Serialize)]
pub struct DirHit {
    pub url: String,
    pub status: u16,
    pub size: u64,
    pub words: usize,
    pub lines: usize,
    pub redirect: Option<String>,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub time_ms: u128,
}

fn default_statuses() -> Vec<u16> {
    vec![200, 201, 204, 301, 302, 307, 308, 401, 403, 405]
}

fn build_client(req: &DirFuzzRequest) -> reqwest::Client {
    let ua = req.user_agent.clone()
        .unwrap_or_else(|| "Mozilla/5.0 (PocketPentester-DirFuzz)".into());
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(ua)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn expand_paths(word: &str, extensions: &[String]) -> Vec<String> {
    let w = word.trim().trim_start_matches('/');
    if w.is_empty() { return vec![]; }
    let mut out = vec![w.to_string()];
    for ext in extensions {
        let e = ext.trim();
        if e.is_empty() { continue; }
        let normalized = if e.starts_with('.') { e.to_string() } else { format!(".{e}") };
        out.push(format!("{w}{normalized}"));
    }
    out
}

fn parse_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title")?;
    let rest = &body[start..];
    let body_start = rest.find('>')? + 1;
    let end = lower[start..].find("</title>")?;
    let title = &rest[body_start..end];
    let t = title.trim();
    if t.is_empty() { None } else { Some(t.chars().take(100).collect()) }
}

async fn probe(
    client: &reqwest::Client,
    url: &str,
    headers: &HashMap<String, String>,
) -> Option<DirHit> {
    let start = std::time::Instant::now();
    let mut builder = client.get(url);
    for (k, v) in headers {
        if k.trim().is_empty() { continue; }
        builder = builder.header(k.trim(), v);
    }
    let resp = builder.send().await.ok()?;
    let status = resp.status().as_u16();
    let content_type = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok()).map(String::from);
    let redirect = resp.headers().get("location")
        .and_then(|v| v.to_str().ok()).map(String::from);
    let body = resp.text().await.unwrap_or_default();
    let time_ms = start.elapsed().as_millis();

    Some(DirHit {
        url: url.to_string(),
        status,
        size: body.len() as u64,
        words: body.split_whitespace().count(),
        lines: body.lines().count(),
        redirect,
        title: parse_title(&body),
        content_type,
        time_ms,
    })
}

pub async fn dirfuzz_run(app: AppHandle, req: DirFuzzRequest) -> Result<Vec<DirHit>, String> {
    let base = req.base_url.trim_end_matches('/').to_string();
    let client = Arc::new(build_client(&req));
    let accept: Vec<u16> = req.accept_status.clone().unwrap_or_else(default_statuses);
    let accept_set: std::collections::HashSet<u16> = accept.iter().copied().collect();

    // ---- baseline calibration: fetch a random non-existent path to detect wildcard 200s ----
    let wildcard_marker = format!("__xploit_wildcard_{}_{}", rand::random::<u32>(), rand::random::<u32>());
    let wildcard_url = format!("{}/{}", base, wildcard_marker);
    let wildcard_size: Option<u64> = probe(&client, &wildcard_url, &req.headers).await
        .filter(|h| accept_set.contains(&h.status))
        .map(|h| h.size);
    if let Some(sz) = wildcard_size {
        let _ = app.emit("dirfuzz:status",
            format!("wildcard calibration: {} returned status (size={}) — same-size responses will be filtered", wildcard_url, sz));
    }

    // ---- build initial path list ----
    let mut initial_paths: Vec<String> = Vec::new();
    for w in &req.wordlist {
        for p in expand_paths(w, &req.extensions) {
            initial_paths.push(p);
        }
    }

    let queue: Arc<Mutex<Vec<(String, u8)>>> = Arc::new(Mutex::new(vec![(base.clone(), 0)]));
    let all_hits: Arc<Mutex<Vec<DirHit>>> = Arc::new(Mutex::new(Vec::new()));
    let total_done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        let (current_base, depth) = {
            let mut q = queue.lock().await;
            if q.is_empty() { break; }
            q.remove(0)
        };

        let urls: Vec<String> = initial_paths.iter()
            .map(|p| format!("{}/{}", current_base.trim_end_matches('/'), p))
            .collect();
        let total = urls.len();

        let _ = app.emit("dirfuzz:status",
            format!("fuzzing {} (depth {}): {} paths", current_base, depth, total));

        let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
        let local_hits: Arc<Mutex<Vec<DirHit>>> = Arc::new(Mutex::new(Vec::new()));

        stream::iter(urls.into_iter())
            .map(|url| {
                let client = client.clone();
                let sem = sem.clone();
                let headers = req.headers.clone();
                let accept_set = accept_set.clone();
                let size_min = req.size_min;
                let size_max = req.size_max;
                let wildcard_size = wildcard_size;
                let total_done = total_done.clone();
                let local_hits = local_hits.clone();
                let all_hits_c = all_hits.clone();
                let app = app.clone();
                async move {
                    let _permit = sem.acquire().await.unwrap();
                    if let Some(hit) = probe(&client, &url, &headers).await {
                        let n = total_done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let _ = app.emit("dirfuzz:progress",
                            serde_json::json!({"done": n, "total_seen": total_done.load(std::sync::atomic::Ordering::Relaxed)}));

                        if !accept_set.contains(&hit.status) { return; }
                        if let Some(min) = size_min { if hit.size < min { return; } }
                        if let Some(max) = size_max { if hit.size > max { return; } }
                        if let Some(wsz) = wildcard_size { if hit.size == wsz { return; } }

                        let _ = app.emit("dirfuzz:hit", hit.clone());
                        local_hits.lock().await.push(hit.clone());
                        all_hits_c.lock().await.push(hit);
                    } else {
                        total_done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
            .buffer_unordered(req.concurrency.max(1))
            .for_each(|_| async {})
            .await;

        // recursion: enqueue hits that look like directories
        if req.recursive && depth < req.recursion_depth {
            let hits = local_hits.lock().await;
            for h in hits.iter() {
                let looks_like_dir = h.status == 301 || h.status == 302
                    || h.url.ends_with('/')
                    || h.redirect.as_deref().map(|r| r.ends_with('/')).unwrap_or(false);
                if looks_like_dir {
                    let mut q = queue.lock().await;
                    q.push((h.url.trim_end_matches('/').to_string(), depth + 1));
                }
            }
        }
    }

    let hits = all_hits.lock().await.clone();
    let _ = app.emit("dirfuzz:done", hits.len());
    Ok(hits)
}

pub fn dirfuzz_common_wordlist() -> Vec<String> {
    // compact default wordlist — 150 of the highest-signal paths
    vec![
        "admin", "administrator", "login", "signin", "signup", "register",
        "dashboard", "api", "api/v1", "api/v2", "api/v3", "graphql",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        ".git/config", ".git/HEAD", ".git/logs/HEAD", ".svn/entries", ".hg/hgrc",
        ".env", ".env.local", ".env.production", ".env.backup",
        "config", "config.php", "config.json", "config.yml", "config.xml",
        "backup", "backup.zip", "backup.tar.gz", "backup.sql", "backup.bak",
        "db.sql", "dump.sql", "database.sql", "site.sql",
        "test", "test.php", "test.html", "phpinfo.php", "info.php",
        "server-status", "server-info", "status",
        "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-config.php",
        "administrator/index.php", "user/login", "users/sign_in",
        "phpmyadmin", "myadmin", "mysql", "dbadmin", "adminer", "adminer.php",
        ".htaccess", ".htpasswd", ".DS_Store", "thumbs.db",
        "uploads", "upload", "files", "file", "download", "downloads",
        "images", "img", "assets", "static", "public", "private",
        "docs", "doc", "documentation", "swagger", "swagger.json",
        "swagger-ui.html", "api-docs", "openapi.json", "openapi.yaml",
        "console", "actuator", "actuator/health", "actuator/env", "actuator/info",
        "metrics", "prometheus", "health", "healthcheck", "readiness", "liveness",
        "debug", "trace", "error", "errors", "log", "logs", "error_log",
        "jenkins", "phpunit", "webdav", "manager/html", "tomcat",
        "portal", "support", "help", "about", "contact", "feedback",
        "mail", "email", "webmail", "smtp", "imap",
        "vpn", "sso", "auth", "oauth", "oauth2", "openid",
        ".well-known/security.txt", ".well-known/openid-configuration",
        ".well-known/acme-challenge", ".well-known/nodeinfo",
        "index.php", "index.html", "index.asp", "index.aspx", "index.jsp",
        "home", "main", "default",
        "secret", "private.key", "id_rsa", "id_dsa",
        "setup", "install", "installer", "setup.php",
        "cgi-bin", "cgi-bin/test.sh", "cgi-bin/info.sh",
        "dev", "development", "staging", "stage", "beta", "qa", "uat",
        "old", "new", "tmp", "temp", "cache",
        "api/users", "api/user", "api/me", "api/login", "api/admin",
        "admin/login", "admin/config", "admin/users",
        "fckeditor", "ckeditor", "tinymce", "editor",
        "vendor", "node_modules", "composer.json", "composer.lock",
        "package.json", "yarn.lock", "webpack.config.js",
        "wp-json", "wp-json/wp/v2", "wp-json/wp/v2/users",
    ].into_iter().map(String::from).collect()
}
