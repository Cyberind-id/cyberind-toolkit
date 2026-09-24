// ===================================================================
// Banner Grabber — TCP connect + read service greeting, fingerprint
// common services (SSH / FTP / SMTP / HTTP / Redis / MySQL / IRC).
// ===================================================================

use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone, Deserialize)]
pub struct BannerRequest {
    pub host: String,
    pub ports: Vec<u16>,
    #[serde(default = "default_conc")]
    pub concurrency: usize,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_conc() -> usize { 50 }
fn default_timeout() -> u64 { 4000 }

#[derive(Debug, Clone, Serialize)]
pub struct BannerHit {
    pub port: u16,
    pub banner: String,
    pub service: String,
    pub version: Option<String>,
    pub bytes: usize,
}

fn fingerprint(port: u16, banner: &str) -> (String, Option<String>) {
    let lo = banner.to_lowercase();
    let first_line = banner.lines().next().unwrap_or("").to_string();

    // SSH
    if banner.starts_with("SSH-") {
        let ver = first_line.trim().to_string();
        return ("SSH".into(), Some(ver));
    }

    // HTTP (we sent a HEAD /)
    if banner.starts_with("HTTP/") {
        let server = banner.lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .map(|l| l.trim_start_matches("Server:").trim_start_matches("server:").trim().to_string());
        return ("HTTP".into(), server);
    }

    // FTP
    if banner.starts_with("220 ") && (lo.contains("ftp") || port == 21) {
        let ver = first_line.trim_start_matches("220 ").trim().to_string();
        return ("FTP".into(), Some(ver));
    }

    // SMTP
    if banner.starts_with("220 ") && (lo.contains("smtp") || lo.contains("mail") || port == 25 || port == 587) {
        return ("SMTP".into(), Some(first_line));
    }

    // POP3 / IMAP
    if banner.starts_with("+OK") { return ("POP3".into(), Some(first_line)); }
    if banner.starts_with("* OK") { return ("IMAP".into(), Some(first_line)); }

    // Telnet
    if banner.as_bytes().first() == Some(&0xFF) { return ("Telnet".into(), None); }

    // Redis
    if banner.starts_with("+PONG") || banner.starts_with("-NOAUTH") { return ("Redis".into(), None); }
    if banner.starts_with("-ERR") && port == 6379 { return ("Redis".into(), Some(first_line)); }

    // MySQL (handshake starts with packet length + protocol 0x0a)
    if banner.as_bytes().len() >= 5 && banner.as_bytes()[4] == 0x0a && port == 3306 {
        let ver_start = 5;
        let ver_end = banner.as_bytes().iter().skip(ver_start).position(|&b| b == 0)
            .map(|p| ver_start + p).unwrap_or(banner.len());
        if ver_end > ver_start {
            return ("MySQL".into(), Some(String::from_utf8_lossy(&banner.as_bytes()[ver_start..ver_end]).to_string()));
        }
        return ("MySQL".into(), None);
    }

    // PostgreSQL — responds with error on junk; check for "FATAL" or specific msg
    if port == 5432 && (lo.contains("fatal") || lo.contains("postgresql")) {
        return ("PostgreSQL".into(), None);
    }

    // RDP — first byte 0x03 (TPKT)
    if banner.as_bytes().first() == Some(&0x03) && port == 3389 {
        return ("RDP".into(), None);
    }

    // VNC
    if banner.starts_with("RFB ") { return ("VNC".into(), Some(first_line.trim().into())); }

    // IRC
    if banner.starts_with(":") && lo.contains("irc") { return ("IRC".into(), Some(first_line)); }

    // MongoDB — ismaster reply; harder
    if port == 27017 { return ("MongoDB".into(), None); }

    // Fallback by port
    let by_port = match port {
        53 => "DNS", 22 => "SSH?", 23 => "Telnet?", 25 => "SMTP?",
        80 | 8080 | 8000 | 8088 => "HTTP?", 110 => "POP3?", 143 => "IMAP?",
        443 | 8443 => "HTTPS?", 445 => "SMB", 465 => "SMTPS",
        587 => "SMTP-SUB", 993 => "IMAPS", 995 => "POP3S",
        1433 => "MSSQL", 1521 => "Oracle", 2049 => "NFS",
        3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL",
        5900 => "VNC", 6379 => "Redis", 6667 => "IRC",
        9200 => "Elasticsearch",
        11211 => "Memcached", 27017 => "MongoDB",
        _ => "unknown",
    };
    (by_port.to_string(), None)
}

async fn grab(host: &str, port: u16, timeout_ms: u64) -> Option<BannerHit> {
    let addr = format!("{host}:{port}");
    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await.ok()?.ok()?;
    let _ = stream.set_nodelay(true);
    let mut stream = stream;

    // For HTTP-ish ports, send a HEAD request to elicit a Server header
    let triggers: &[&[u8]] = match port {
        80 | 8080 | 8000 | 8008 | 8088 | 8888 | 9000 | 9090 | 10000 =>
            &[b"HEAD / HTTP/1.0\r\n\r\n"],
        21 | 22 | 25 | 110 | 143 | 220 | 5432 | 6379 => &[],
        _ => &[],
    };
    for t in triggers {
        let _ = timeout(Duration::from_millis(500), stream.write_all(t)).await;
    }

    let mut buf = [0u8; 2048];
    let read = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await.ok()?.ok()?;
    if read == 0 { return None; }

    let banner_raw = String::from_utf8_lossy(&buf[..read]).to_string();
    let banner = banner_raw.trim_end_matches(['\r', '\n', '\0']).to_string();
    let (service, version) = fingerprint(port, &banner);

    // If banner is empty but we got bytes (binary), keep as-is
    let display = if banner.is_empty() && read > 0 {
        format!("[binary {} bytes]", read)
    } else {
        // strip non-printable for display
        banner.chars().map(|c| if c.is_ascii_graphic() || c == ' ' || c == '\n' { c } else { '.' }).collect::<String>()
    };

    Some(BannerHit { port, banner: display, service, version, bytes: read })
}

pub async fn banner_grab(app: AppHandle, req: BannerRequest) -> Result<Vec<BannerHit>, String> {
    let total = req.ports.len();
    let _ = app.emit("banner:status", format!("grabbing banners on {} port(s)", total));

    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let host = Arc::new(req.host.clone());

    let hits: Vec<BannerHit> = stream::iter(req.ports.into_iter())
        .map(|port| {
            let sem = sem.clone();
            let done = done.clone();
            let app = app.clone();
            let host = host.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let res = grab(&host, port, req.timeout_ms).await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("banner:progress", serde_json::json!({"done": n, "total": total}));
                if let Some(ref h) = res {
                    let _ = app.emit("banner:hit", h.clone());
                }
                res
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let _ = app.emit("banner:done", hits.len());
    Ok(hits)
}
