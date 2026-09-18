// ===================================================================
// Admin Panel Finder — probe common admin/login paths, detect CMS.
// Bundled with 450+ high-signal admin paths.
// ===================================================================

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Deserialize)]
pub struct AdminFindRequest {
    pub base_url: String,
    #[serde(default)]
    pub extra_paths: Vec<String>,
    #[serde(default)]
    pub use_builtin: bool,
    #[serde(default)]
    pub accept_status: Option<Vec<u16>>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    #[serde(default)]
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminHit {
    pub url: String,
    pub status: u16,
    pub size: u64,
    pub title: Option<String>,
    pub platform: Option<String>,
    pub login_form: bool,
    pub auth_header: Option<String>,
    pub redirect: Option<String>,
}

static TITLE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
static LOGIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?is)<(?:input|form)[^>]*(?:type=['"]password['"]|name=['"]password['"]|name=['"]passwd['"])"#).unwrap());

fn detect_platform(body: &str, title: &Option<String>, hdrs: &reqwest::header::HeaderMap) -> Option<String> {
    let lo = body.to_lowercase();
    let t = title.clone().unwrap_or_default().to_lowercase();
    let powered = hdrs.get("x-powered-by").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    let server = hdrs.get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();

    if lo.contains("wp-login") || lo.contains("wp-submit") || t.contains("wordpress") { return Some("WordPress".into()); }
    if lo.contains("com_users") || lo.contains("joomla") || t.contains("joomla") { return Some("Joomla".into()); }
    if lo.contains("drupal-settings-json") || t.contains("drupal") { return Some("Drupal".into()); }
    if lo.contains("dashboardwidgets") || lo.contains("wp-admin") { return Some("WordPress admin".into()); }
    if t.contains("phpmyadmin") || lo.contains("phpmyadmin") { return Some("phpMyAdmin".into()); }
    if lo.contains("adminer") || t.contains("adminer") { return Some("Adminer".into()); }
    if t.contains("jenkins") || lo.contains("jenkins") { return Some("Jenkins".into()); }
    if t.contains("jira") { return Some("Jira".into()); }
    if t.contains("confluence") { return Some("Confluence".into()); }
    if t.contains("gitlab") { return Some("GitLab".into()); }
    if t.contains("grafana") || lo.contains("grafana") { return Some("Grafana".into()); }
    if t.contains("kibana") { return Some("Kibana".into()); }
    if t.contains("solr") { return Some("Apache Solr".into()); }
    if t.contains("tomcat") || lo.contains("apache tomcat") { return Some("Apache Tomcat".into()); }
    if t.contains("cpanel") { return Some("cPanel".into()); }
    if t.contains("plesk") { return Some("Plesk".into()); }
    if t.contains("directadmin") { return Some("DirectAdmin".into()); }
    if t.contains("webmin") { return Some("Webmin".into()); }
    if t.contains("mikrotik") { return Some("Mikrotik".into()); }
    if t.contains("pfsense") { return Some("pfSense".into()); }
    if t.contains("opnsense") { return Some("OPNsense".into()); }
    if powered.contains("asp.net") { return Some("ASP.NET".into()); }
    if powered.contains("php") { return Some("PHP".into()); }
    if server.contains("iis") { return Some("IIS".into()); }
    if server.contains("nginx") { return Some("nginx".into()); }
    if server.contains("apache") { return Some("Apache".into()); }
    None
}

pub fn admin_finder_wordlist() -> Vec<&'static str> {
    BUILTIN.to_vec()
}

pub async fn admin_finder_run(app: AppHandle, req: AdminFindRequest) -> Result<Vec<AdminHit>, String> {
    let base = req.base_url.trim_end_matches('/').to_string();
    let accept: HashSet<u16> = req.accept_status.clone()
        .unwrap_or_else(|| vec![200, 201, 301, 302, 307, 308, 401, 403])
        .into_iter().collect();

    let mut paths: HashSet<String> = HashSet::new();
    if req.use_builtin {
        for p in BUILTIN.iter() { paths.insert(p.trim_start_matches('/').to_string()); }
    }
    for p in &req.extra_paths {
        let t = p.trim().trim_start_matches('/').to_string();
        if !t.is_empty() { paths.insert(t); }
    }
    if paths.is_empty() {
        return Err("no paths to probe (enable builtin or provide extra_paths)".into());
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(req.timeout_ms))
        .redirect(if req.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent("Mozilla/5.0 (PocketPentester-AdminFinder)")
        .build()
        .map_err(|e| e.to_string())?;

    let total = paths.len();
    let _ = app.emit("adminfind:status", format!("probing {total} admin path(s) on {base}"));
    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = Arc::new(client);

    let hits: Vec<AdminHit> = stream::iter(paths.into_iter())
        .map(|p| {
            let base = base.clone();
            let client = client.clone();
            let sem = sem.clone();
            let done = done.clone();
            let accept = accept.clone();
            let app = app.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let url = format!("{}/{}", base, p);
                let resp = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => {
                        let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let _ = app.emit("adminfind:progress", serde_json::json!({"done": n, "total": total}));
                        return None;
                    }
                };
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("adminfind:progress", serde_json::json!({"done": n, "total": total}));

                let status = resp.status().as_u16();
                if !accept.contains(&status) { return None; }

                let hdrs = resp.headers().clone();
                let auth = hdrs.get("www-authenticate").and_then(|v| v.to_str().ok()).map(String::from);
                let redirect = hdrs.get("location").and_then(|v| v.to_str().ok()).map(String::from);
                let body = resp.text().await.unwrap_or_default();
                let title = TITLE_RE.captures(&body)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().chars().take(100).collect::<String>())
                    .filter(|s| !s.is_empty());
                let login = LOGIN_RE.is_match(&body) || auth.is_some();
                let platform = detect_platform(&body, &title, &hdrs);

                let hit = AdminHit {
                    url,
                    status,
                    size: body.len() as u64,
                    title,
                    platform,
                    login_form: login,
                    auth_header: auth,
                    redirect,
                };
                let _ = app.emit("adminfind:hit", hit.clone());
                Some(hit)
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let _ = app.emit("adminfind:done", hits.len());
    Ok(hits)
}

// ------------------------------------------------------------------
// Built-in admin path wordlist (~320 high-signal paths)
// ------------------------------------------------------------------
const BUILTIN: &[&str] = &[
    // generic
    "admin", "admin/", "admin.php", "admin.html", "admin.asp", "admin.aspx", "admin.jsp",
    "admin/login", "admin/login.php", "admin/login.html", "admin/index.php", "admin/index.html",
    "admin/admin.php", "admin/home.php", "admin/home", "admin/dashboard", "admin/panel",
    "admin/admin_login", "admin/account.php", "admin/admin-login", "admin/controlpanel",
    "admin/controlpanel.html", "admin/cp.php", "admin/cp.html",
    "admin1", "admin1.php", "admin1.html", "admin2", "admin2.php", "admin2.html",
    "administrator", "administrator/", "administrator/index.php", "administrator/login.php",
    "administrator/account.php", "administrator/account.html",
    "adm", "adm/", "adm/index.php", "adm/admloginuser.php",
    "panel", "panel-administracion", "panel/", "controlpanel", "controlpanel/",
    "webadmin", "webadmin/", "webadmin/index.php", "webadmin/admin",
    "login", "login.php", "login.html", "login.asp", "login.aspx", "login.jsp",
    "log-in", "signin", "sign-in", "sign_in", "sign_up", "signup",
    "account", "account/login", "account.php", "accounts/login",
    "user/login", "users/sign_in", "users/login",
    "home.php", "home.html", "main.php", "main.html",

    // wordpress
    "wp-admin", "wp-admin/", "wp-login.php", "wp-admin/admin-ajax.php",
    "wp-admin/install.php", "wp-admin/upgrade.php", "wp-admin/setup-config.php",
    "wp-content/plugins/", "wp-content/themes/", "wp-json/wp/v2/users",

    // joomla
    "administrator/index.php", "administrator/components/",

    // drupal
    "user", "user/login", "user/register", "admin/structure",

    // magento
    "admin/admin", "admin/dashboard/", "magento_version",
    "index.php/admin/", "customer/account/login/",

    // prestashop
    "modules/ps_shoppingcart",

    // opencart
    "admin/index.php?route=common/login",

    // laravel
    "login", "register", "password/reset", "horizon", "telescope",

    // phpmyadmin / db admin
    "phpmyadmin", "phpmyadmin/", "phpmyadmin/index.php", "pma", "pma/", "pmamy", "pmamy2",
    "dbadmin", "dbadmin/", "mysql", "mysql/", "sqlmanager", "sqlmanager/",
    "adminer.php", "adminer/", "adminer", "phpMyAdmin/",

    // cpanel / plesk / webmin
    "cpanel", "cpanel/", ":2082", ":2083",
    "plesk", "plesk/", ":8443",
    "webmin", "webmin/", ":10000",
    "directadmin", ":2222",
    "ispconfig", "vesta",

    // tomcat / jboss / weblogic
    "manager/html", "manager/status", "host-manager/html",
    "jmx-console/", "web-console/", "admin-console/",
    "invoker/", "console/", "wls-wsat/CoordinatorPortType",

    // elasticsearch / kibana / solr
    "_cluster/health", "_cat/indices", "_all",
    "kibana", "app/kibana",
    "solr/", "solr/admin/cores", "solr/#/",

    // jenkins / gitlab / gitea
    "jenkins", "jenkins/", "jenkins/login",
    "gitlab/users/sign_in", "user/login",
    "admin/appearance",

    // grafana / prometheus
    "grafana", "grafana/login",
    "prometheus", "prometheus/graph",

    // rabbitmq / kafka ui
    "rabbitmq", ":15672", "#/queues",

    // api platforms
    "api/admin", "api/administrator", "api/v1/admin", "api/login", "api/users",
    "graphql", "graphiql", "playground",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json", "swagger/v1/swagger.json",
    "api-docs", "openapi.json", "openapi.yaml", "v2/api-docs",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump", "actuator/mappings",

    // routers / network appliances
    "cgi-bin/luci", "cgi-bin/admin", "cgi-bin/login",
    "router", "router/login",

    // mikrotik / pfsense / opnsense
    "webfig", "winbox",
    "system_advanced_admin.php", "diag_backup.php",

    // misc control panels
    "dashboard", "dashboard/", "dashboard/login",
    "manage", "manage/", "manager/", "control", "control/", "siteadmin", "siteadmin/",
    "moderator", "moderator/", "operator/", "supervisor/",
    "console", "console/", "backend", "backend/", "staff", "staff/",
    "system", "system/", "system/login", "system/admin",
    "cms", "cms/", "cms/login",
    "portal", "portal/", "portal/login",

    // auth endpoints
    "oauth", "oauth/authorize", "oauth2/authorize", "sso",
    ".well-known/openid-configuration",

    // file managers
    "files", "filemanager", "file_manager", "filemanager/", "files/login",

    // backup / debug / test
    "test", "test/", "testing", "staging", "stage", "beta", "dev", "development",
    "old", "old/", "tmp", "temp", "cache", "backup", "backups",

    // vendor-specific
    "owa", "owa/auth/logon.aspx", "ecp/default.aspx",
    "citrix", "vpn/index_access.html",
    "vcenter", "ui/", "vsphere-client/",
    "splunk", "en-US/account/login",
    "sonarqube", "sessions/new",
    "nexus", "artifactory",
    "harbor", "portainer",
    "rancher", "rancher/login",

    // legacy / misc
    "home", "member", "members", "members/", "private", "private/",
    "secure", "secure/", "vip", "vip/",
    "webadm", "siteadm", "backoffice",
];
