use bytes::Bytes;
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::warn;

/// Verifier سهل‌گیر برای مسیر QUIC/H3: زنجیره‌ی گواهی سرور را بررسی نمی‌کند
/// چون سرور REALITY (برای کلاینت‌های مجاز) یک گواهی موقت خودامضا ارائه
/// می‌دهد. اعتماد واقعی روی AEAD مشترک (secret) است، نه روی PKI عمومی.
#[derive(Debug)]
pub struct NoCertVerification;

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ==========================================
// 2. TCP KEEPALIVE (بخشی از "2. TCP KEEPALIVE & CRYPTO")
// ==========================================

pub fn enable_tcp_keepalive(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(15)).with_interval(Duration::from_secs(5));
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        warn!("Failed to set TCP Keepalive: {}", e);
    }
}

pub fn frame_grpc(data: &[u8]) -> Bytes {
    let mut buf = crate::buf_pool::PooledVec::new();
    buf.push(0);
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
    Bytes::copy_from_slice(&buf)
}

/// یک گواهی خود-امضا (Self-Signed) و کلید خصوصی موقت و صرفاً در حافظه
/// می‌سازد. سرور دیگر نیازی به گواهی واقعیِ سایت هدف (یا هیچ گواهی روی
/// دیسک) ندارد؛ این گواهی فقط برای کلاینت‌هایی که از قبل از طریق کانال
/// SNI/HMAC احراز هویت شده‌اند به‌کار می‌رود و چون آن کلاینت‌ها اعتبارسنجی
/// زنجیره‌ی گواهی را عمداً غیرفعال کرده‌اند (امنیت واقعی از AEAD مشترک
/// تامین می‌شود، نه از PKI)، خود-امضا بودن آن مشکلی ایجاد نمی‌کند.
pub fn generate_ephemeral_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate ephemeral REALITY certificate");

    let cert_der = CertificateDer::from(cert_key.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    (vec![cert_der], key_der)
}

pub fn get_random_headers() -> Vec<(&'static str, &'static str)> {
    let user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ];
    let ua = user_agents[rand::thread_rng().gen_range(0..user_agents.len())];
    vec![
        ("user-agent", ua),
        ("accept", "application/grpc-web, application/grpc, */*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("te", "trailers"),
        ("content-type", "application/grpc"),
    ]
}
