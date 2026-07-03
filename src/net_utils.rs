use bytes::{Bytes, BytesMut};
use rand::Rng;
use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::warn;

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
    let mut buf = BytesMut::with_capacity(5 + data.len());
    buf.extend_from_slice(&[0]);
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
    buf.freeze()
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
