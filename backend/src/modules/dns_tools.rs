// ===================================================================
// DNS Tools — comprehensive record lookup + zone transfer + DNSSEC
// ===================================================================

use std::net::SocketAddr;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRequest {
    pub domain: String,
    #[serde(default)]
    pub resolver: Option<String>, // e.g. "1.1.1.1:53", "8.8.8.8:53", "internal-dns.corp:53"
    #[serde(default)]
    pub types: Option<Vec<String>>, // subset to query, None = all
    #[serde(default)]
    pub try_axfr: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsReport {
    pub domain: String,
    pub records: Vec<DnsRecordGroup>,
    pub axfr: Option<AxfrResult>,
    pub dnssec: DnssecCheck,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecordGroup {
    pub rtype: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AxfrResult {
    pub success: bool,
    pub nameserver: String,
    pub records_dumped: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnssecCheck {
    pub dnskey_count: usize,
    pub has_dnssec: bool,
}

fn build_resolver(custom: Option<&str>) -> Result<TokioAsyncResolver, String> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 2;

    if let Some(addr) = custom {
        let sa: SocketAddr = if addr.contains(':') {
            addr.parse().map_err(|e| format!("bad resolver addr: {e}"))?
        } else {
            format!("{addr}:53").parse().map_err(|e| format!("bad resolver addr: {e}"))?
        };
        let mut cfg = ResolverConfig::new();
        cfg.add_name_server(NameServerConfig {
            socket_addr: sa,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        Ok(TokioAsyncResolver::tokio(cfg, opts))
    } else {
        Ok(TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts))
    }
}

fn all_types() -> Vec<(&'static str, RecordType)> {
    vec![
        ("A", RecordType::A),
        ("AAAA", RecordType::AAAA),
        ("MX", RecordType::MX),
        ("NS", RecordType::NS),
        ("CNAME", RecordType::CNAME),
        ("TXT", RecordType::TXT),
        ("SOA", RecordType::SOA),
        ("CAA", RecordType::CAA),
        ("SRV", RecordType::SRV),
        ("PTR", RecordType::PTR),
    ]
}

async fn try_axfr(domain: &str, nameserver: &str) -> AxfrResult {
    // Best-effort AXFR via raw TCP to port 53.
    // Build a minimal DNS AXFR query (type 252) and read packets.
    // Most public servers will refuse (REFUSED rcode) — this is mostly a
    // "is this server misconfigured" check.
    let addr: SocketAddr = match format!("{nameserver}:53").parse() {
        Ok(a) => a,
        Err(e) => return AxfrResult { success: false, nameserver: nameserver.into(), records_dumped: vec![], error: Some(e.to_string()) },
    };

    let stream_res = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await;
    let mut stream = match stream_res {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return AxfrResult { success: false, nameserver: nameserver.into(), records_dumped: vec![], error: Some(e.to_string()) },
        Err(_) => return AxfrResult { success: false, nameserver: nameserver.into(), records_dumped: vec![], error: Some("connect timeout".into()) },
    };

    let mut query: Vec<u8> = Vec::new();
    // DNS header (12 bytes): tx=0, flags=0x0100 (RD), questions=1
    query.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // QNAME
    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        query.push(bytes.len() as u8);
        query.extend_from_slice(bytes);
    }
    query.push(0);
    // QTYPE=252 AXFR, QCLASS=IN
    query.extend_from_slice(&[0, 252, 0, 1]);

    // TCP DNS prepends 2-byte length
    let mut framed = Vec::with_capacity(query.len() + 2);
    let len = query.len() as u16;
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&query);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if let Err(e) = stream.write_all(&framed).await {
        return AxfrResult { success: false, nameserver: nameserver.into(), records_dumped: vec![], error: Some(e.to_string()) };
    }
    let _ = stream.flush().await;

    // Read up to 32KB of responses, parse roughly — just count record names.
    let mut out: Vec<String> = Vec::new();
    let mut total = 0usize;
    loop {
        let mut len_buf = [0u8; 2];
        let r = timeout(Duration::from_secs(4), stream.read_exact(&mut len_buf)).await;
        match r {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let rlen = u16::from_be_bytes(len_buf) as usize;
        if rlen == 0 || rlen > 65535 { break; }
        let mut buf = vec![0u8; rlen];
        if timeout(Duration::from_secs(4), stream.read_exact(&mut buf)).await.is_err() { break; }
        total += buf.len();
        // check RCODE in response flags
        if buf.len() >= 4 {
            let rcode = buf[3] & 0x0F;
            if rcode != 0 {
                return AxfrResult {
                    success: false,
                    nameserver: nameserver.into(),
                    records_dumped: vec![],
                    error: Some(format!("RCODE {rcode} (refused/notauth/other)")),
                };
            }
        }
        // naive: parse names from answer section (skip header + question)
        if let Some(names) = extract_names(&buf) {
            for n in names {
                if !out.contains(&n) { out.push(n); }
            }
        }
        if total > 65536 { break; }
    }

    AxfrResult {
        success: !out.is_empty(),
        nameserver: nameserver.into(),
        records_dumped: out,
        error: None,
    }
}

// Best-effort name extractor — walks bytes looking for printable labels.
fn extract_names(packet: &[u8]) -> Option<Vec<String>> {
    if packet.len() < 12 { return None; }
    let mut out: Vec<String> = Vec::new();
    let mut i = 12; // skip header
    let mut seen = std::collections::HashSet::new();
    while i < packet.len() {
        let len = packet[i] as usize;
        if len == 0 { i += 1; continue; }
        if len & 0xC0 == 0xC0 { i += 2; continue; }
        if i + 1 + len > packet.len() { break; }
        if len < 64 {
            let bytes = &packet[i + 1..i + 1 + len];
            if bytes.iter().all(|b| b.is_ascii_graphic()) {
                let s = String::from_utf8_lossy(bytes).to_string();
                if !seen.contains(&s) && s.len() > 1 {
                    seen.insert(s.clone());
                    out.push(s);
                }
            }
        }
        i += 1 + len;
    }
    Some(out)
}

pub async fn dns_query(req: DnsRequest) -> Result<DnsReport, String> {
    let resolver = build_resolver(req.resolver.as_deref())?;
    let wanted: Vec<(&'static str, RecordType)> = match &req.types {
        Some(v) if !v.is_empty() => all_types().into_iter().filter(|(n, _)| v.iter().any(|x| x.eq_ignore_ascii_case(n))).collect(),
        _ => all_types(),
    };

    let mut records: Vec<DnsRecordGroup> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut nameservers: Vec<String> = Vec::new();

    for (name, rt) in wanted {
        let result = resolver.lookup(req.domain.as_str(), rt).await;
        match result {
            Ok(lookup) => {
                let values: Vec<String> = lookup.iter().map(|r| r.to_string()).collect();
                if !values.is_empty() {
                    if name == "NS" {
                        for v in &values { nameservers.push(v.trim_end_matches('.').to_string()); }
                    }
                    records.push(DnsRecordGroup { rtype: name.to_string(), values });
                }
            }
            Err(e) => {
                let msg = format!("{name}: {e}");
                // "no records found" is noise — only log if not NoRecordsFound
                if !msg.to_lowercase().contains("no record") {
                    errors.push(msg);
                }
            }
        }
    }

    // DNSSEC check — presence of DNSKEY
    let dnssec = match resolver.lookup(req.domain.as_str(), RecordType::DNSKEY).await {
        Ok(lookup) => {
            let count = lookup.iter().count();
            DnssecCheck { dnskey_count: count, has_dnssec: count > 0 }
        }
        Err(_) => DnssecCheck { dnskey_count: 0, has_dnssec: false },
    };

    // AXFR attempt
    let axfr = if req.try_axfr {
        let ns = nameservers.first().cloned().unwrap_or_default();
        if ns.is_empty() {
            Some(AxfrResult { success: false, nameserver: String::new(), records_dumped: vec![], error: Some("no NS records to attempt AXFR".into()) })
        } else {
            Some(try_axfr(&req.domain, &ns).await)
        }
    } else {
        None
    };

    Ok(DnsReport { domain: req.domain, records, axfr, dnssec, errors })
}
