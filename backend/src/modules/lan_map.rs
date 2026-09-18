// ===================================================================
// LAN Map — discover devices on the connected local network.
//
// Pure Rust, works on Android without root. Combines:
//   1. TCP sweep on common ports across the /24 subnet
//   2. mDNS service discovery (UDP 5353 multicast)
//   3. SSDP/UPnP M-SEARCH (UDP 1900 multicast)
//
// NOTE on Android: multicast (mDNS/SSDP) requires WifiManager
// MulticastLock to be held by the host app. Without it, the OS
// drops multicast traffic in power-save. TCP sweep always works.
//
// TODO(plugin): Tauri Android plugin to acquire MulticastLock so
//               mDNS/SSDP returns reliable results on phone.
// TODO(oui): bundle a curated OUI prefix DB for vendor lookup.
// ===================================================================

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use crate::compat::{AppHandle, Emitter};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Debug, Clone, Deserialize)]
pub struct LanScanRequest {
    pub subnet_cidr: Option<String>,    // e.g. "192.168.1.0/24" — autodetect if None
    pub ports: Option<Vec<u16>>,        // ports to TCP-probe per host
    pub probe_mdns: bool,
    pub probe_ssdp: bool,
    pub concurrency: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LanDevice {
    pub ip: String,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,    // mDNS PTR services
    pub upnp: Vec<String>,        // SSDP server / device descriptions
    pub guess: Option<String>,    // best-effort device type guess
}

#[derive(Debug, Clone, Serialize)]
pub struct LanScanReport {
    pub local_ip: String,
    pub subnet: String,
    pub devices: Vec<LanDevice>,
}

const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 81, 88, 111, 135, 139, 143, 443, 445, 515, 548,
    554, 631, 873, 902, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2121,
    2222, 2375, 2376, 3000, 3306, 3389, 3478, 4444, 4567, 5000, 5040, 5432,
    5555, 5601, 5672, 5900, 5984, 6379, 6667, 7000, 7077, 7474, 7680, 8000,
    8008, 8009, 8080, 8081, 8086, 8088, 8089, 8123, 8181, 8200, 8291, 8333,
    8443, 8500, 8765, 8834, 8888, 9000, 9090, 9100, 9200, 9418, 9999, 10000,
    11211, 15672, 27017, 32400, 49152,
];

const MDNS_SERVICES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_printer._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_pdl-datastream._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_amzn-wplay._tcp.local",
];

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

fn detect_local_ipv4() -> Option<Ipv4Addr> {
    match local_ip_address::local_ip() {
        Ok(IpAddr::V4(v4)) => Some(v4),
        _ => None,
    }
}

fn parse_or_autodetect_subnet(spec: Option<&str>) -> Option<(Ipv4Addr, Vec<Ipv4Addr>, String)> {
    if let Some(cidr) = spec {
        if let Some((net, _)) = cidr.split_once('/') {
            if let Ok(base) = net.parse::<Ipv4Addr>() {
                // simple /24 only for now
                let octets = base.octets();
                let hosts: Vec<Ipv4Addr> = (1..255).map(|h| Ipv4Addr::new(octets[0], octets[1], octets[2], h)).collect();
                return Some((base, hosts, cidr.to_string()));
            }
        }
    }
    let me = detect_local_ipv4()?;
    let oct = me.octets();
    let base = Ipv4Addr::new(oct[0], oct[1], oct[2], 0);
    let hosts: Vec<Ipv4Addr> = (1..255)
        .map(|h| Ipv4Addr::new(oct[0], oct[1], oct[2], h))
        .filter(|ip| *ip != me)
        .collect();
    Some((base, hosts, format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2])))
}

fn guess_from_ports_and_services(ports: &[u16], services: &[String], upnp: &[String]) -> Option<String> {
    let s_lower: Vec<String> = services.iter().chain(upnp.iter()).map(|s| s.to_lowercase()).collect();
    let any = |needle: &str| s_lower.iter().any(|s| s.contains(needle));

    if any("googlecast") { return Some("Google Cast / Chromecast".into()); }
    if any("airplay") || any("raop") { return Some("Apple AirPlay device".into()); }
    if any("homekit") || any("hap") { return Some("HomeKit accessory".into()); }
    if any("spotify-connect") { return Some("Spotify Connect speaker".into()); }
    if any("printer") || any("ipp") || any("pdl") { return Some("Network printer".into()); }
    if any("workstation") { return Some("Workstation (NETBIOS/SMB)".into()); }

    if ports.contains(&445) || ports.contains(&139) { return Some("Windows / Samba host".into()); }
    if ports.contains(&3389) { return Some("Windows RDP host".into()); }
    if ports.contains(&22) { return Some("SSH server".into()); }
    if ports.contains(&80) && ports.contains(&443) && ports.contains(&8443) { return Some("Web server / appliance".into()); }
    if ports.contains(&554) || ports.contains(&8000) || ports.contains(&8554) { return Some("IP camera (RTSP)?".into()); }
    if ports.contains(&5900) { return Some("VNC server".into()); }
    if ports.contains(&3306) || ports.contains(&5432) || ports.contains(&27017) { return Some("Database server".into()); }
    if ports.contains(&53) && ports.contains(&80) { return Some("Router / gateway".into()); }
    if ports.contains(&80) || ports.contains(&8080) { return Some("HTTP service".into()); }
    None
}

// ------------------------------------------------------------------
// TCP sweep
// ------------------------------------------------------------------

async fn tcp_probe(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    matches!(
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

async fn sweep_host(ip: Ipv4Addr, ports: &[u16], concurrency: usize, timeout_ms: u64) -> Vec<u16> {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut futs = Vec::new();
    for p in ports {
        let sem = sem.clone();
        let p = *p;
        futs.push(async move {
            let _permit = sem.acquire().await.unwrap();
            if tcp_probe(ip, p, timeout_ms).await { Some(p) } else { None }
        });
    }
    let mut results: Vec<u16> = futures::future::join_all(futs).await
        .into_iter().flatten().collect();
    results.sort_unstable();
    results
}

// ------------------------------------------------------------------
// mDNS — fire one PTR query per service, listen for N seconds
// ------------------------------------------------------------------

fn build_mdns_query(name: &str) -> Vec<u8> {
    // minimal DNS query: tx=0, flags=0, 1 question, type PTR, class IN
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&[0, 0]);             // tx id
    buf.extend_from_slice(&[0, 0]);             // flags = standard query
    buf.extend_from_slice(&[0, 1]);             // questions = 1
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ans/auth/add = 0
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
    buf.extend_from_slice(&[0, 12]); // QTYPE = PTR
    buf.extend_from_slice(&[0, 1]);  // QCLASS = IN
    buf
}

fn parse_mdns_ptr(packet: &[u8]) -> Vec<String> {
    // best-effort: pull ANSWER PTR rdata as service-instance names
    // skips header + question; handles compression pointers loosely
    let mut out: Vec<String> = Vec::new();
    if packet.len() < 12 { return out; }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 { return out; }

    // skip header
    let mut pos = 12usize;
    // skip 1 question
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    for _ in 0..qdcount {
        // skip name labels
        while pos < packet.len() {
            let len = packet[pos] as usize;
            if len == 0 { pos += 1; break; }
            if len & 0xC0 == 0xC0 { pos += 2; break; }
            pos += 1 + len;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > packet.len() { return out; }
    }

    for _ in 0..ancount {
        if pos >= packet.len() { break; }
        // skip NAME (compressed or labels)
        if packet[pos] & 0xC0 == 0xC0 { pos += 2; }
        else {
            while pos < packet.len() {
                let len = packet[pos] as usize;
                if len == 0 { pos += 1; break; }
                if len & 0xC0 == 0xC0 { pos += 2; break; }
                pos += 1 + len;
            }
        }
        if pos + 10 > packet.len() { break; }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > packet.len() { break; }

        if rtype == 12 {
            // PTR rdata: domain-name
            if let Some(name) = read_name(packet, pos) {
                out.push(name);
            }
        }
        pos += rdlen;
    }
    out
}

fn read_name(packet: &[u8], start: usize) -> Option<String> {
    let mut pos = start;
    let mut out = String::new();
    let mut jumped = false;
    let mut hops = 0;
    loop {
        if hops > 20 || pos >= packet.len() { return None; }
        let len = packet[pos] as usize;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() { return None; }
            let off = ((len & 0x3F) << 8) | packet[pos + 1] as usize;
            pos = off;
            jumped = true;
            hops += 1;
            continue;
        }
        if !out.is_empty() { out.push('.'); }
        if pos + 1 + len > packet.len() { return None; }
        out.push_str(std::str::from_utf8(&packet[pos + 1..pos + 1 + len]).unwrap_or(""));
        pos += 1 + len;
        if !jumped && len == 0 { break; }
    }
    if out.is_empty() { None } else { Some(out) }
}

async fn run_mdns(timeout_secs: u64) -> HashMap<String, Vec<String>> {
    let mut results: HashMap<String, Vec<String>> = HashMap::new();

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = sock.set_broadcast(true);
    let mdns_addr: SocketAddr = "224.0.0.251:5353".parse().unwrap();

    for svc in MDNS_SERVICES {
        let q = build_mdns_query(svc);
        let _ = sock.send_to(&q, mdns_addr).await;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 4096];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline { break; }
        let remaining = deadline - now;
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let entries = parse_mdns_ptr(&buf[..n]);
                if let IpAddr::V4(v4) = src.ip() {
                    let key = v4.to_string();
                    let bucket = results.entry(key).or_default();
                    for e in entries {
                        if !bucket.contains(&e) { bucket.push(e); }
                    }
                }
            }
            _ => break,
        }
    }
    results
}

// ------------------------------------------------------------------
// SSDP
// ------------------------------------------------------------------

async fn run_ssdp(timeout_secs: u64) -> HashMap<String, Vec<String>> {
    let mut results: HashMap<String, Vec<String>> = HashMap::new();

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = sock.set_broadcast(true);
    let ssdp_addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();

    let msg = b"M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: ssdp:all\r\n\r\n";
    let _ = sock.send_to(msg, ssdp_addr).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 4096];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline { break; }
        let remaining = deadline - now;
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let IpAddr::V4(v4) = src.ip() {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    let mut info = String::new();
                    for line in text.lines() {
                        let l = line.to_lowercase();
                        if l.starts_with("server:") || l.starts_with("st:") || l.starts_with("location:") || l.starts_with("usn:") {
                            if !info.is_empty() { info.push_str(" | "); }
                            info.push_str(line.trim());
                        }
                    }
                    if !info.is_empty() {
                        let bucket = results.entry(v4.to_string()).or_default();
                        if !bucket.contains(&info) { bucket.push(info); }
                    }
                }
            }
            _ => break,
        }
    }
    results
}

// ------------------------------------------------------------------
// orchestrator
// ------------------------------------------------------------------

pub async fn lan_scan(app: AppHandle, req: LanScanRequest) -> Result<LanScanReport, String> {
    let ports = req.ports.clone().unwrap_or_else(|| DEFAULT_PORTS.to_vec());
    let local_ip = detect_local_ipv4()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());

    let (_base, hosts, subnet) = parse_or_autodetect_subnet(req.subnet_cidr.as_deref())
        .ok_or_else(|| "could not detect local network — pass subnet_cidr (e.g. 192.168.1.0/24)".to_string())?;

    let _ = app.emit("lanmap:status", format!("scanning {} ({} hosts × {} ports)", subnet, hosts.len(), ports.len()));

    let devices: Arc<Mutex<HashMap<String, LanDevice>>> = Arc::new(Mutex::new(HashMap::new()));

    // ---- multicast probes start in background ----
    let mdns_handle = if req.probe_mdns {
        Some(tokio::spawn(run_mdns(4)))
    } else { None };
    let ssdp_handle = if req.probe_ssdp {
        Some(tokio::spawn(run_ssdp(4)))
    } else { None };

    // ---- TCP sweep ----
    let total = hosts.len();
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let host_sem = Arc::new(tokio::sync::Semaphore::new(req.concurrency.max(1)));

    stream::iter(hosts.into_iter())
        .map(|ip| {
            let ports = ports.clone();
            let host_sem = host_sem.clone();
            let done = done.clone();
            let app = app.clone();
            let devices = devices.clone();
            async move {
                let _permit = host_sem.acquire().await.unwrap();
                // sequential per-host port sweep but capped concurrency
                let open = sweep_host(ip, &ports, 50, req.timeout_ms).await;
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let _ = app.emit("lanmap:progress", serde_json::json!({"done": n, "total": total}));
                if !open.is_empty() {
                    let mut guard = devices.lock().await;
                    let entry = guard.entry(ip.to_string()).or_insert_with(|| LanDevice {
                        ip: ip.to_string(), ..Default::default()
                    });
                    entry.open_ports = open.clone();
                    entry.guess = guess_from_ports_and_services(&open, &entry.services, &entry.upnp);
                    drop(guard);
                    let snapshot = LanDevice {
                        ip: ip.to_string(),
                        open_ports: open.clone(),
                        guess: guess_from_ports_and_services(&open, &[], &[]),
                        ..Default::default()
                    };
                    let _ = app.emit("lanmap:device", snapshot);
                }
            }
        })
        .buffer_unordered(req.concurrency.max(1))
        .for_each(|_| async {})
        .await;

    // ---- merge multicast results ----
    if let Some(h) = mdns_handle {
        if let Ok(map) = h.await {
            let mut guard = devices.lock().await;
            for (ip, services) in map {
                let entry = guard.entry(ip.clone()).or_insert_with(|| LanDevice { ip: ip.clone(), ..Default::default() });
                for s in services {
                    if !entry.services.contains(&s) { entry.services.push(s); }
                }
                entry.guess = guess_from_ports_and_services(&entry.open_ports, &entry.services, &entry.upnp);
            }
        }
    }
    if let Some(h) = ssdp_handle {
        if let Ok(map) = h.await {
            let mut guard = devices.lock().await;
            for (ip, lines) in map {
                let entry = guard.entry(ip.clone()).or_insert_with(|| LanDevice { ip: ip.clone(), ..Default::default() });
                for s in lines {
                    if !entry.upnp.contains(&s) { entry.upnp.push(s); }
                }
                entry.guess = guess_from_ports_and_services(&entry.open_ports, &entry.services, &entry.upnp);
            }
        }
    }

    let mut list: Vec<LanDevice> = devices.lock().await.values().cloned().collect();
    list.sort_by(|a, b| a.ip.cmp(&b.ip));

    let _ = app.emit("lanmap:done", list.len());

    Ok(LanScanReport {
        local_ip,
        subnet,
        devices: list,
    })
}

pub async fn lan_local_info() -> Result<serde_json::Value, String> {
    let v4 = detect_local_ipv4().map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".into());
    let oct = detect_local_ipv4().map(|ip| ip.octets()).unwrap_or([0; 4]);
    let subnet = if oct[0] == 0 { String::new() }
        else { format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]) };
    Ok(serde_json::json!({
        "local_ip": v4,
        "subnet": subnet,
        "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "android": cfg!(target_os = "android"),
    }))
}
