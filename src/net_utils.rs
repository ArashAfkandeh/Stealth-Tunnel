

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

pub fn tune_socket_buffers(stream: &TcpStream) {
    // Only keeping socket reference for future tuning if needed.
    // Explicit SO_RCVBUF and SO_SNDBUF removed to allow Linux TCP Auto-Tuning.
    let _sock = SockRef::from(stream);
}

#[cfg(target_os = "linux")]
pub fn enable_tcp_bbr(stream: &TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let bbr = b"bbr\0";
    unsafe {
        let res = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            bbr.as_ptr() as *const _,
            (bbr.len() - 1) as libc::socklen_t, // pass length without null terminator or with? Wait, usually we pass the string length, e.g. 3 for "bbr"
        );
        if res != 0 {
            warn!("Failed to set TCP BBR. Is it enabled in the kernel?");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn enable_tcp_bbr(_stream: &TcpStream) {
    // BBR setting is Linux-specific
}



pub fn get_random_headers() -> Vec<(&'static str, &'static str)> {
    let user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ];
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let ua = user_agents[(now % user_agents.len() as u128) as usize];
    vec![
        ("user-agent", ua),
        ("accept", "application/grpc-web, application/grpc, */*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("te", "trailers"),
        ("content-type", "application/grpc"),
    ]
}

pub fn create_reuseport_listener(addr_str: &str) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Socket, Domain, Type, Protocol};
    use std::net::SocketAddr;
    
    let addr: SocketAddr = addr_str.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    socket.set_reuse_address(true)?;
    
    #[cfg(target_family = "unix")]
    if let Err(e) = socket.set_reuse_port(true) {
        tracing::warn!("Failed to set SO_REUSEPORT (Hot-reload might drop connections during restart): {}", e);
    }
    
    socket.bind(&addr.into())?;
    socket.listen(1024)?; // backlog of 1024
    
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(std_listener)
}

pub fn create_reuseport_udp_socket(addr_str: &str) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Socket, Domain, Type, Protocol};
    use std::net::SocketAddr;
    
    let addr: SocketAddr = addr_str.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    
    socket.set_reuse_address(true)?;
    
    #[cfg(target_family = "unix")]
    if let Err(e) = socket.set_reuse_port(true) {
        tracing::warn!("Failed to set SO_REUSEPORT on UDP (Hot-reload might fail): {}", e);
    }
    
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    
    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}
