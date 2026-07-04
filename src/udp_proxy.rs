use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info};
use std::net::IpAddr;

// TTL برای نشست‌های UDP (چقدر یک پورت بدون تبادل داده باز بماند)
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
// TTL برای IP‌های احراز هویت شده توسط TCP
const AUTH_IP_TTL: Duration = Duration::from_secs(2 * 3600); // 2 hours

pub async fn run_udp_proxy(
    bind_addr: String,
    local_quic_addr: SocketAddr,
    reality_target_addr: String,
    authorized_ips: Arc<RwLock<HashMap<IpAddr, Instant>>>,
    cancel_token: tokio_util::sync::CancellationToken,
) {
    let public_socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to bind public UDP socket on {}: {}", bind_addr, e);
            return;
        }
    };

    // نگاشت آدرس کلاینت به سوکت محلی (که با هدف ارتباط دارد)
    let sessions: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::new(RwLock::new(HashMap::new()));
    let mut buf = crate::buf_pool::PooledVec::new_with_size(65535); // حداکثر سایز پکت UDP

    info!("🚀 UDP/QUIC User-Space NAT Proxy started on {}", bind_addr);

    // تسک پاکسازی نشست‌های منقضی شده
    let auth_ips_clone = authorized_ips.clone();
    let cancel_clone = cancel_token.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    // TODO: Implement idle timeout cleanup if needed.
                    // For auth IPs:
                    let mut auth = auth_ips_clone.write().await;
                    auth.retain(|_, time| time.elapsed() < AUTH_IP_TTL);
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("🛑 Stopping UDP NAT Proxy due to Hot-Reload");
                break;
            }
            res = public_socket.recv_from(&mut buf) => {
                let (len, client_addr) = match res {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let data = &buf[..len];

                let session_socket = {
                    let map = sessions.read().await;
                    map.get(&client_addr).cloned()
                };

                if let Some(local_sock) = session_socket {
                    let _ = local_sock.send(data).await;
                } else {
                    // نشست جدید! بررسی احراز هویت
                    let is_auth = {
                        let auth = authorized_ips.read().await;
                        if let Some(time) = auth.get(&client_addr.ip()) {
                            time.elapsed() < AUTH_IP_TTL
                        } else {
                            false
                        }
                    };

                    let target: String = if is_auth {
                        debug!("[UDP] ✅ Authorized IP {}, routing to local QUIC", client_addr.ip());
                        local_quic_addr.to_string()
                    } else {
                        debug!("[UDP] ⚠️ Unauthorized IP {}, routing to REALITY target {}", client_addr.ip(), reality_target_addr);
                        reality_target_addr.clone()
                    };

                    // ایجاد سوکت محلی جدید برای این کلاینت
                    if let Ok(local_sock) = UdpSocket::bind("0.0.0.0:0").await {
                        if local_sock.connect(&target).await.is_ok() {
                            let local_sock = Arc::new(local_sock);
                            sessions.write().await.insert(client_addr, local_sock.clone());
                            let _ = local_sock.send(data).await;

                            // اسپاون تسک برای دریافت پاسخ‌ها از هدف و ارسال به کلاینت
                            let sessions_ref = sessions.clone();
                            let public_sock_ref = public_socket.clone();
                            tokio::spawn(async move {
                                let mut lbuf = crate::buf_pool::PooledVec::new_with_size(65535);
                                loop {
                                    match tokio::time::timeout(UDP_SESSION_TIMEOUT, local_sock.recv(&mut lbuf)).await {
                                        Ok(Ok(n)) => {
                                            if n == 0 { break; }
                                            let _ = public_sock_ref.send_to(&lbuf[..n], client_addr).await;
                                        }
                                        _ => {
                                            // Timeout or Error
                                            break;
                                        }
                                    }
                                }
                                debug!("[UDP] Session closed for {}", client_addr);
                                sessions_ref.write().await.remove(&client_addr);
                            });
                        }
                    }
                }
            }
        }
    }
}
