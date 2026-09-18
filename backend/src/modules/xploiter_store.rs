// ===================================================================
// Xploiter template store — local CRUD + bundled starter templates.
//
// Templates live in: app_local_data_dir()/xploiter-templates/*.yaml
// Bundled templates are embedded at compile time and extracted on
// first run into the same directory (user can then edit them).
//
// TODO(backend): add a `templates_sync` command that pulls curated
//                community packs from a signed Pocket-hosted registry
//                (subscription tier). Templates must be signed so
//                malicious YAMLs can't be injected by a MITM.
// TODO(backend): add `templates_publish` to submit a local template
//                back to the registry for review.
// ===================================================================

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use walkdir::WalkDir;

// ------------------------------------------------------------------
// Bundled starter templates — covers RCE, SSTI, LFI, SSRF, info-leak
// ------------------------------------------------------------------
//
// These are embedded in the binary so the app is useful on first run
// without network access. Users can edit/delete/duplicate freely.

const STARTER_TEMPLATES: &[(&str, &str)] = &[
    ("xpl-env-leak.yaml",            include_str!("../../starter_templates/xpl-env-leak.yaml")),
    ("xpl-git-config.yaml",          include_str!("../../starter_templates/xpl-git-config.yaml")),
    ("xpl-phpinfo.yaml",             include_str!("../../starter_templates/xpl-phpinfo.yaml")),
    ("xpl-lfi-basic.yaml",           include_str!("../../starter_templates/xpl-lfi-basic.yaml")),
    ("xpl-rce-shellshock.yaml",      include_str!("../../starter_templates/xpl-rce-shellshock.yaml")),
    ("xpl-rce-log4shell.yaml",       include_str!("../../starter_templates/xpl-rce-log4shell.yaml")),
    ("xpl-ssti-jinja2.yaml",         include_str!("../../starter_templates/xpl-ssti-jinja2.yaml")),
    ("xpl-ssti-twig.yaml",           include_str!("../../starter_templates/xpl-ssti-twig.yaml")),
    ("xpl-open-redirect.yaml",       include_str!("../../starter_templates/xpl-open-redirect.yaml")),
    ("xpl-ssrf-basic.yaml",          include_str!("../../starter_templates/xpl-ssrf-basic.yaml")),
    ("xpl-wp-debug.yaml",            include_str!("../../starter_templates/xpl-wp-debug.yaml")),
    ("xpl-cors-misconfig.yaml",      include_str!("../../starter_templates/xpl-cors-misconfig.yaml")),
    ("xpl-backup-files.yaml",        include_str!("../../starter_templates/xpl-backup-files.yaml")),
];

fn store_root(_app: &AppHandle) -> Result<PathBuf, String> {
    let base = std::env::var("CYBERIND_DATA_DIR").map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("cyberind-toolkit"));
    let p = base.join("xploiter-templates");
    std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    Ok(p)
}

// ------------------------------------------------------------------
// Data shapes
// ------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct TemplateRef {
    pub filename: String,
    pub path: String,
    pub id: String,
    pub name: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub author: String,
    pub description: String,
    pub builtin: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct HeadYaml {
    id: Option<String>,
    info: Option<HeadInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct HeadInfo {
    name: Option<String>,
    severity: Option<String>,
    author: Option<String>,
    description: Option<String>,
    tags: Option<serde_yaml::Value>,
}

fn parse_tags(v: Option<serde_yaml::Value>) -> Vec<String> {
    match v {
        Some(serde_yaml::Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        Some(serde_yaml::Value::Sequence(seq)) => seq.into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    }
}

// ------------------------------------------------------------------
// Commands
// ------------------------------------------------------------------

pub async fn xploit_store_init(app: AppHandle) -> Result<serde_json::Value, String> {
    let root = store_root(&app)?;
    // Always overwrite bundled templates (user-authored custom templates with
    // different filenames are preserved). This picks up template improvements
    // shipped in app updates.
    let mut written = 0usize;
    let bundled: std::collections::HashSet<&str> =
        STARTER_TEMPLATES.iter().map(|(n, _)| *n).collect();
    for (name, body) in STARTER_TEMPLATES {
        let p = root.join(name);
        std::fs::write(&p, body).map_err(|e| e.to_string())?;
        written += 1;
    }
    let _ = app.emit("xpl:store:status",
        format!("store ready @ {} ({} bundled synced)", root.display(), written));
    let _ = bundled; // keep for clarity
    Ok(serde_json::json!({
        "path": root.to_string_lossy(),
        "written": written,
        "total_bundled": STARTER_TEMPLATES.len(),
    }))
}

pub async fn xploit_store_list(
    app: AppHandle,
    severity: Option<Vec<String>>,
    tag: Option<String>,
    query: Option<String>,
) -> Result<Vec<TemplateRef>, String> {
    let root = store_root(&app)?;
    let sev_filter: Option<Vec<String>> = severity.map(|v| v.into_iter().map(|s| s.to_lowercase()).collect());
    let q = query.map(|s| s.to_lowercase());

    let bundled_names: std::collections::HashSet<&str> = STARTER_TEMPLATES.iter().map(|(n, _)| *n).collect();

    let mut out: Vec<TemplateRef> = Vec::new();
    for entry in WalkDir::new(&root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") { continue; }
        let Ok(content) = std::fs::read_to_string(path) else { continue };
        let Ok(head) = serde_yaml::from_str::<HeadYaml>(&content) else { continue };

        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
        let id = head.id.unwrap_or_default();
        if id.is_empty() { continue; }
        let info = head.info.unwrap_or(HeadInfo { name: None, severity: None, author: None, description: None, tags: None });
        let severity = info.severity.unwrap_or_else(|| "info".into()).to_lowercase();
        let tags = parse_tags(info.tags);

        if let Some(ref sf) = sev_filter {
            if !sf.contains(&severity) { continue; }
        }
        if let Some(ref t) = tag {
            if !tags.iter().any(|x| x.eq_ignore_ascii_case(t)) { continue; }
        }
        if let Some(ref qq) = q {
            let hay = format!("{} {} {}", id, info.name.clone().unwrap_or_default(), tags.join(" "));
            if !hay.to_lowercase().contains(qq) { continue; }
        }

        out.push(TemplateRef {
            filename: filename.clone(),
            path: path.to_string_lossy().into_owned(),
            id,
            name: info.name.unwrap_or_default(),
            severity,
            tags,
            author: info.author.unwrap_or_default(),
            description: info.description.unwrap_or_default(),
            builtin: bundled_names.contains(filename.as_str()),
        });
    }
    out.sort_by(|a, b| a.filename.cmp(&b.filename));
    Ok(out)
}

pub async fn xploit_store_read(path: String) -> Result<String, String> {
    tokio::fs::read_to_string(&path).await.map_err(|e| e.to_string())
}

pub async fn xploit_store_save(app: AppHandle, filename: String, content: String) -> Result<String, String> {
    // validate YAML parses before writing
    serde_yaml::from_str::<serde_yaml::Value>(&content).map_err(|e| format!("invalid yaml: {e}"))?;

    let root = store_root(&app)?;
    let safe = filename.replace(['/', '\\', ':'], "_");
    let fname = if safe.ends_with(".yaml") { safe } else { format!("{safe}.yaml") };
    let path = root.join(&fname);
    tokio::fs::write(&path, content).await.map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

pub async fn xploit_store_delete(path: String) -> Result<(), String> {
    tokio::fs::remove_file(&path).await.map_err(|e| e.to_string())
}

pub async fn xploit_store_duplicate(app: AppHandle, path: String) -> Result<String, String> {
    let content = tokio::fs::read_to_string(&path).await.map_err(|e| e.to_string())?;
    let orig = std::path::Path::new(&path).file_stem()
        .and_then(|s| s.to_str()).unwrap_or("template");
    let new_name = format!("{orig}-copy-{}.yaml", rand::random::<u16>());
    let root = store_root(&app)?;
    let new_path = root.join(&new_name);
    tokio::fs::write(&new_path, content).await.map_err(|e| e.to_string())?;
    Ok(new_path.to_string_lossy().into_owned())
}

pub fn xploit_store_starter_template() -> String {
    // Returned when UI asks for a "new template" skeleton.
    r#"id: my-custom-check
info:
  name: My Custom Template
  author: you
  severity: info
  description: Describe what this template detects
  tags:
    - custom
  reference:
    - https://example.com/reference

variables:
  marker: "xpl_{{randstr}}"

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "Welcome"
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        regex:
          - "v([0-9]+\\.[0-9]+\\.[0-9]+)"
        group: 1
        name: version
"#.into()
}

// TODO(backend): subscription-gated commands (stubbed for now)
//
// #[tauri::command]
// pub async fn xploit_store_sync_community() -> Result<(), String> {
//     // POST to /v1/templates/sync with session token, download signed
//     // template pack, verify ed25519 sigs, extract to store_root().
//     Err("community sync requires a Pocket Pro subscription".into())
// }
//
// #[tauri::command]
// pub async fn xploit_store_publish(path: String) -> Result<(), String> {
//     // Upload local template for peer review. Requires auth session.
//     Err("publishing requires a Pocket Pro subscription".into())
// }

// unused import guard — HashMap isn't used yet but kept for future extractor aggregation
#[allow(dead_code)]
fn _keep(_: HashMap<(), ()>) {}
