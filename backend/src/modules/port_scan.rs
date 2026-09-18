use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanRequest {
    pub target: String,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub scanned: usize,
    pub total: usize,
}

pub fn top_1000_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
        3306, 3389, 5900, 8080, 8443, 8888, 5432, 6379, 27017, 9200, 5601, 11211,
        1433, 1521, 2049, 2181, 2375, 2376, 4369, 5000, 5001, 5044, 5432, 5601,
        5672, 5984, 6000, 6379, 7000, 7001, 7002, 8000, 8001, 8008, 8009, 8010,
        8081, 8082, 8083, 8086, 8088, 8090, 8091, 8161, 8200, 8291, 8333, 8400,
        8500, 8834, 8983, 9000, 9001, 9042, 9090, 9091, 9092, 9100, 9160, 9200,
        9300, 9418, 9443, 9999, 10000, 10001, 10250, 11211, 15672, 16379, 27017,
        27018, 27019, 28017, 50000, 50070, 54321, 61616,
        // common ports
        20, 26, 37, 79, 81, 82, 88, 106, 113, 119, 123, 137, 138, 161, 162, 389,
        427, 465, 500, 513, 514, 515, 548, 554, 587, 631, 636, 646, 873, 902,
        990, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1194, 1214, 1241, 1311,
        1352, 1434, 1433, 1494, 1503, 1720, 1755, 1761, 1812, 1900, 2000, 2001,
        2049, 2121, 2222, 2301, 2383, 2601, 2717, 2869, 3000, 3001, 3128, 3268,
        3306, 3389, 3690, 4000, 4001, 4045, 4100, 4333, 4444, 4662, 4899, 5009,
        5050, 5060, 5100, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900, 6001,
        6346, 6646, 6660, 6661, 6662, 6663, 6665, 6666, 6667, 6668, 6669, 6881,
        7070, 7937, 7938, 8021, 8031, 8042, 8080, 8088, 8181, 8443, 8686, 8888,
        9100, 9102, 9103, 9535, 9999, 10243, 10566, 12345, 13782, 13783, 16992,
        16993, 17877, 17988, 19101, 19801, 19842, 20000, 22939, 24800, 30718,
        32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
        32778, 32779, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
        49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 65000,
        65129, 65389,
    ]
}

pub fn service_name(port: u16) -> Option<String> {
    let s = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => return None,
    };
    Some(s.to_string())
}

async fn probe(addr: SocketAddr, timeout_ms: u64) -> bool {
    matches!(
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

pub async fn port_scan(app: AppHandle, req: PortScanRequest) -> Result<Vec<PortResult>, String> {
    let ip: std::net::IpAddr = tokio::net::lookup_host(format!("{}:80", req.target))
        .await
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .map(|s| s.ip())
        .ok_or("no addresses resolved")?;

    let total = req.ports.len();
    let sem = Arc::new(Semaphore::new(req.concurrency.max(1)));
    let scanned = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let results: Vec<PortResult> = stream::iter(req.ports.into_iter())
        .map(|port| {
            let sem = sem.clone();
            let scanned = scanned.clone();
            let app = app.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let addr = SocketAddr::new(ip, port);
                let open = probe(addr, req.timeout_ms).await;
                let n = scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("portscan:progress", ScanProgress { scanned: n, total });
                let result = PortResult { port, open, service: service_name(port) };
                if open {
                    let _ = app.emit("portscan:hit", result.clone());
                }
                result
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .collect()
        .await;

    let _ = app.emit("portscan:done", total);
    Ok(results.into_iter().filter(|r| r.open).collect())
}
