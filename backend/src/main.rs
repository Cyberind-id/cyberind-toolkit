mod compat;
mod modules;

use axum::{extract::Path, http::{HeaderValue, Method, StatusCode}, response::IntoResponse, routing::{get, post}, Json, Router};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use compat::AppHandle;

async fn invoke(Path(cmd): Path<String>, Json(args): Json<Value>) -> impl IntoResponse {
    let app = AppHandle::default();
    let result: Result<Value, String> = match cmd.as_str() {
        "banner" => Ok(json!("Cyberind Toolkit v1.0 // independent security toolkit")),
        "default_ports" => Ok(json!(modules::port_scan::top_1000_ports())),
        "port_scan" => call!(modules::port_scan::port_scan, app, args, "req"),
        "subdomain_enum" => call!(modules::subdomain::subdomain_enum, app, args, "req"),
        "subdomain_sources" => Ok(modules::subdomain::subdomain_sources()),
        "http_probe" => call!(modules::httpx::http_probe, app, args, "req"),
        "takeover_scan" => call!(modules::takeover::takeover_scan, app, args, "req"),
        "sqli_scan" => call!(modules::sqli::sqli_scan, app, args, "req"),
        "sqli_probe_union" => call!(modules::sqli::sqli_probe_union, app, args, "req"),
        "sqli_dump" => call!(modules::sqli::sqli_dump, app, args, "req"),
        "xss_scan" => call!(modules::xss::xss_scan, app, args, "req"),
        "jwt_analyze" => call!(modules::jwt::jwt_analyze, app, args, "req"),
        "xploit_run" => call!(modules::xploiter::xploit_run, app, args, "req"),
        "autopwn_run" => call!(modules::autopwn::autopwn_run, app, args, "req"),
        "lan_scan" => call!(modules::lan_map::lan_scan, app, args, "req"),
        "lan_local_info" => modules::lan_map::lan_local_info().await.map(|v| v),
        "repeater_send" => call_plain!(modules::repeater::repeater_send, args, "req"),
        "repeater_to_curl" => {
            let req = serde_json::from_value(args.get("req").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string());
            req.map(|r| json!(modules::repeater::repeater_to_curl(r)))
        },
        "dirfuzz_run" => call!(modules::dirfuzz::dirfuzz_run, app, args, "req"),
        "dirfuzz_common_wordlist" => Ok(json!(modules::dirfuzz::dirfuzz_common_wordlist())),
        "admin_finder_run" => call!(modules::admin_finder::admin_finder_run, app, args, "req"),
        "admin_finder_wordlist" => Ok(json!(modules::admin_finder::admin_finder_wordlist())),
        "form_brute_run" => call!(modules::form_brute::form_brute_run, app, args, "req"),
        "form_brute_common_users" => Ok(json!(modules::form_brute::form_brute_common_users())),
        "form_brute_common_passwords" => Ok(json!(modules::form_brute::form_brute_common_passwords())),
        "dns_query" => call_plain!(modules::dns_tools::dns_query, args, "req"),
        "ssl_scan" => call_plain!(modules::ssl_scan::ssl_scan, args, "req"),
        "banner_grab" => call!(modules::banner::banner_grab, app, args, "req"),
        "iana_tld_list" => modules::domain_grabber::iana_tld_list().await.map(|v| json!(v)),
        "domain_grab" => call!(modules::domain_grabber::domain_grab, app, args, "req"),
        "wordlist_info" => Ok(modules::domain_grabber::wordlist_info()),
        "xploit_store_init" => modules::xploiter_store::xploit_store_init(app).await.map(|v| json!(v)),
        "xploit_store_list" => {
            let sev = serde_json::from_value(args.get("severity").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string());
            let tag = serde_json::from_value(args.get("tag").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string());
            let query = serde_json::from_value(args.get("query").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string());
            match (sev, tag, query) { (Ok(s), Ok(t), Ok(q)) => modules::xploiter_store::xploit_store_list(app, s, t, q).await.map(|v| json!(v)), (Err(e),_,_)|(_,Err(e),_)|(_,_,Err(e)) => Err(e) }
        },
        "xploit_store_read" => call_arg!(modules::xploiter_store::xploit_store_read, args, "path"),
        "xploit_store_save" => {
            let filename = serde_json::from_value(args.get("filename").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string());
            let content = serde_json::from_value(args.get("content").cloned().unwrap_or(Value::Null)).map_err(|e| e.to_string());
            match (filename, content) { (Ok(f), Ok(c)) => modules::xploiter_store::xploit_store_save(app, f, c).await.map(|v| json!(v)), (Err(e),_)|(_,Err(e)) => Err(e) }
        },
        "xploit_store_delete" => call_arg!(modules::xploiter_store::xploit_store_delete, args, "path"),
        "xploit_store_duplicate" => call_arg_app!(modules::xploiter_store::xploit_store_duplicate, app, args, "path"),
        "xploit_store_starter_template" => Ok(json!(modules::xploiter_store::xploit_store_starter_template())),
        _ => Err(format!("unknown command: {cmd}")),
    };
    match result { Ok(v) => (StatusCode::OK, Json(v)), Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))) }
}

macro_rules! call { ($f:path, $app:expr, $args:expr, $key:literal) => {{
    let v = $args.get($key).cloned().unwrap_or($args.clone());
    match serde_json::from_value(v) { Ok(req) => $f($app, req).await.map(|v| json!(v)), Err(e) => Err(e.to_string()) }
}} }
macro_rules! call_plain { ($f:path, $args:expr, $key:literal) => {{
    match $args.get($key).cloned().ok_or("missing argument".to_string()).and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())) {
        Ok(v) => $f(v).await.map(|v| json!(v)),
        Err(e) => Err(e),
    }
}} }

macro_rules! call_arg_app { ($f:path, $app:expr, $args:expr, $key:literal) => {{
    match $args.get($key).cloned().ok_or("missing argument".to_string()).and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())) { Ok(v) => $f($app, v).await.map(|v| json!(v)), Err(e) => Err(e) }
}} }
macro_rules! call_arg { ($f:path, $args:expr, $key:literal) => {{
    match $args.get($key).cloned().ok_or("missing argument".to_string()).and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())) { Ok(v) => $f(v).await.map(|v| json!(v)), Err(e) => Err(e) }
}} }

async fn health() -> impl IntoResponse { Json(json!({"ok":true,"name":"Cyberind Toolkit","backend":"rust"})) }

#[tokio::main]
async fn main() {
    let cors = match std::env::var("ALLOWED_ORIGIN") {
        Ok(origin) if !origin.trim().is_empty() => {
            let value = HeaderValue::from_str(origin.trim()).expect("ALLOWED_ORIGIN must be a valid origin");
            CorsLayer::new().allow_origin(value).allow_methods([Method::GET, Method::POST, Method::OPTIONS]).allow_headers(tower_http::cors::Any)
        }
        _ => CorsLayer::permissive(),
    };

    let app = Router::new().route("/health", get(health)).route("/api/invoke/:cmd", post(invoke))
        .layer(cors);
    let host = std::env::var("BIND_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var("PORT").ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(8080);
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("Cyberind Toolkit backend listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}
