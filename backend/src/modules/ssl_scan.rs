// ===================================================================
// SSL/TLS Scanner — cert chain inspection + negotiation test.
//
// Uses rustls with a capturing verifier to extract peer cert chain
// even when the cert is invalid/expired/self-signed. Parses cert via
// x509-parser for SAN / issuer / validity extraction.
// ===================================================================

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Deserialize)]
pub struct SslScanRequest {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_port() -> u16 { 443 }
fn default_timeout() -> u64 { 8000 }

#[derive(Debug, Clone, Serialize)]
pub struct SslCertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub sans: Vec<String>,
    pub key_algo: String,
    pub signature_algo: String,
    pub sha256_fingerprint: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SslScanReport {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: Option<String>,
    pub sni_presented: String,
    pub cert_chain: Vec<SslCertInfo>,
    pub chain_valid: bool,
    pub issues: Vec<String>,
    pub alpn: Option<String>,
}

// ---- capturing verifier: accept everything, remember the cert chain ----

#[derive(Debug)]
struct CaptureVerifier {
    captured: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl rustls::client::danger::ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut guard = self.captured.lock().unwrap();
        guard.push(end_entity.as_ref().to_vec());
        for it in intermediates { guard.push(it.as_ref().to_vec()); }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn parse_cert(der: &[u8]) -> Result<SslCertInfo, String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial = format!("{:x}", cert.serial);
    let not_before = cert.validity.not_before.to_rfc2822().unwrap_or_default();
    let not_after = cert.validity.not_after.to_rfc2822().unwrap_or_default();

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let nb = cert.validity.not_after.timestamp();
    let days_remaining = (nb - now) / 86400;
    let expired = nb < now;

    let mut sans: Vec<String> = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for n in &san.general_names {
                sans.push(format!("{n}"));
            }
        }
    }

    let key_algo = cert.public_key().algorithm.algorithm.to_id_string();
    let signature_algo = cert.signature_algorithm.algorithm.to_id_string();

    let self_signed = subject == issuer;

    let is_ca = cert.extensions().iter().any(|e| {
        matches!(e.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca)
    });

    let mut h = Sha256::new();
    h.update(der);
    let fp = h.finalize();
    let sha256_fingerprint = fp.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":");

    Ok(SslCertInfo {
        subject, issuer, serial, not_before, not_after, days_remaining,
        sans, key_algo: map_key_algo(&key_algo), signature_algo: map_sig_algo(&signature_algo),
        sha256_fingerprint, is_ca, self_signed, expired,
    })
}

fn map_key_algo(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA".into(),
        "1.2.840.10045.2.1" => "ECDSA".into(),
        "1.3.101.112" => "Ed25519".into(),
        other => other.into(),
    }
}
fn map_sig_algo(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA256-RSA".into(),
        "1.2.840.113549.1.1.12" => "SHA384-RSA".into(),
        "1.2.840.113549.1.1.13" => "SHA512-RSA".into(),
        "1.2.840.113549.1.1.5"  => "SHA1-RSA (WEAK)".into(),
        "1.2.840.113549.1.1.4"  => "MD5-RSA (BROKEN)".into(),
        "1.2.840.10045.4.3.2"   => "ECDSA-SHA256".into(),
        "1.2.840.10045.4.3.3"   => "ECDSA-SHA384".into(),
        "1.2.840.10045.4.3.4"   => "ECDSA-SHA512".into(),
        "1.3.101.112"           => "Ed25519".into(),
        other => other.into(),
    }
}

pub async fn ssl_scan(req: SslScanRequest) -> Result<SslScanReport, String> {
    let addr_str = format!("{}:{}", req.host, req.port);
    let addr: SocketAddr = tokio::net::lookup_host(&addr_str).await
        .map_err(|e| format!("dns: {e}"))?
        .next()
        .ok_or_else(|| "no address resolved".to_string())?;

    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let verifier = Arc::new(CaptureVerifier { captured: captured.clone() });

    // install default crypto provider (ring) for this thread — idempotent
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(Duration::from_millis(req.timeout_ms), TcpStream::connect(addr)).await
        .map_err(|_| "tcp connect timeout".to_string())?
        .map_err(|e| format!("tcp: {e}"))?;

    let server_name: ServerName<'static> = ServerName::try_from(req.host.clone())
        .map_err(|e| format!("invalid server name: {e}"))?;

    let tls = timeout(Duration::from_millis(req.timeout_ms), connector.connect(server_name, tcp)).await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls handshake: {e}"))?;

    let (_, conn) = tls.get_ref();
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".into(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".into(),
        Some(v) => format!("{v:?} (WEAK/LEGACY)"),
        None => "unknown".into(),
    };
    let cipher_suite = conn.negotiated_cipher_suite().map(|cs| format!("{:?}", cs.suite()));
    let alpn = conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).to_string());

    drop(tls);

    let certs = captured.lock().unwrap().clone();
    if certs.is_empty() {
        return Err("no certs captured".into());
    }

    let mut chain: Vec<SslCertInfo> = Vec::new();
    let mut issues: Vec<String> = Vec::new();
    for (i, der) in certs.iter().enumerate() {
        match parse_cert(der) {
            Ok(info) => {
                if info.expired && i == 0 { issues.push("leaf certificate is EXPIRED".into()); }
                if info.days_remaining < 14 && !info.expired && i == 0 {
                    issues.push(format!("leaf cert expires in {} days", info.days_remaining));
                }
                if info.self_signed && i == 0 && chain.is_empty() {
                    issues.push("leaf is self-signed".into());
                }
                if info.signature_algo.contains("WEAK") || info.signature_algo.contains("BROKEN") {
                    issues.push(format!("weak signature algorithm: {}", info.signature_algo));
                }
                chain.push(info);
            }
            Err(e) => issues.push(format!("cert[{i}] parse error: {e}")),
        }
    }

    if version.contains("LEGACY") || version.contains("1.0") || version.contains("1.1") {
        issues.push(format!("weak TLS version negotiated: {version}"));
    }

    // SAN must include hostname
    if let Some(leaf) = chain.first() {
        let host_lc = req.host.to_lowercase();
        let match_ok = leaf.sans.iter().any(|s| {
            let s_lc = s.to_lowercase();
            s_lc.contains(&host_lc) || s_lc.starts_with("dns:*.") && host_lc.ends_with(&s_lc.trim_start_matches("dns:*").to_string())
        });
        if !match_ok && !leaf.sans.is_empty() {
            issues.push(format!("hostname {} not in SANs", req.host));
        }
    }

    Ok(SslScanReport {
        host: req.host.clone(),
        port: req.port,
        tls_version: version,
        cipher_suite,
        sni_presented: req.host,
        cert_chain: chain,
        chain_valid: issues.is_empty(),
        issues,
        alpn,
    })
}
