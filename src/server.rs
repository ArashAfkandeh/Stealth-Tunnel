use crate::config::ServerConfig;
use crate::crypto::{decrypt_payload, derive_cipher, encrypt_payload, is_authorized_sni};
use crate::net_utils::{enable_tcp_keepalive, frame_grpc, generate_ephemeral_cert, get_random_headers};
use crate::routing::extract_sni;

use rand::Rng;
use http::StatusCode;
use quinn::{ServerConfig as QuinnServerConfig, Endpoint};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use std::net::IpAddr;
use std::collections::HashMap;
use tokio::sync::RwLock;

// حداکثر بایتی که برای استخراج ClientHello/SNI با peek() بررسی می‌شود
const PEEK_BUF_SIZE: usize = 8192;
// حداکثر زمان انتظار برای رسیدن کامل ClientHello (میلی‌ثانیه)
const PEEK_TIMEOUT_MS: u64 = 400;

/// بدون این‌که حتی یک بایت از سوکت مصرف (Consume) شود، منتظر می‌ماند تا
/// ClientHello کامل برسد و SNI آن را استخراج می‌کند. چون از peek() استفاده
/// می‌شود، بایت‌ها همچنان در بافر کرنل باقی می‌مانند و چه مسیر Splice خام
/// و چه مسیر TLS Terminate محلی انتخاب شود، همان جریان اصلی TCP بدون هیچ
/// کپی/بازپخش دستی مصرف خواهد شد.
async fn peek_sni(tcp: &TcpStream) -> Option<String> {
    let mut buf = crate::buf_pool::PooledVec::new_with_size(PEEK_BUF_SIZE);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(PEEK_TIMEOUT_MS);
    loop {
        if let Ok(n) = tcp.peek(&mut buf).await {
            if n > 0 {
                if let Some(sni) = extract_sni(&buf[..n]) {
                    return Some(sni);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline { return None; }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

/// مسیر عدم-احراز-هویت: اتصال TCP به صورت کاملاً خام (Layer-4) به سرور هدف
/// واقعی وصل و بدون هیچ دخالتی Splice می‌شود. از آن‌جا که هیچ داده‌ای رمزگشایی،
/// بازتولید یا Fetch نمی‌شود، سرعت و هدرها دقیقاً همان سرور هدف واقعی است؛
/// نه تاخیر Fetch-and-Serve وجود دارد و نه امکان نشت هدر.
async fn splice_to_real_target(mut client_tcp: TcpStream, target_addr: &str) {
    match TcpStream::connect(target_addr).await {
        Ok(mut target_tcp) => {
            let _ = target_tcp.set_nodelay(true);
            enable_tcp_keepalive(&target_tcp);
            if let Err(e) = tokio::io::copy_bidirectional(&mut client_tcp, &mut target_tcp).await {
                debug!("Splice session ended: {}", e);
            }
        }
        Err(e) => {
            warn!("⚠️ Could not reach reality_target_addr ({}): {} — dropping connection", target_addr, e);
        }
    }
}

pub async fn run_server(cfg: ServerConfig, cancel_token: CancellationToken) {
    let cipher = Arc::new(derive_cipher(&cfg.secret));
    let authorized_ips: Arc<RwLock<HashMap<IpAddr, tokio::time::Instant>>> = Arc::new(RwLock::new(HashMap::new()));

    // ============================
    // گواهی موقت (Ephemeral Self-Signed Certificate)
    // ----------------------------
    // دیگر نیازی به tls_cert/tls_key واقعی روی دیسک نیست. این سرتیفیکیت فقط
    // برای کلاینت‌های خودمان (که از قبل با HMAC بر پایه‌ی SNI احراز هویت
    // شده‌اند و اعتبارسنجی زنجیره‌ی گواهی را در سمت کلاینت خاموش کرده‌اند)
    // استفاده می‌شود؛ نه برای کاربران/اسکنرهایی که هرگز به این مرحله نمی‌رسند.
    // ============================
    let (certs, key_tcp, key_quic) = if let (Some(cert_path), Some(key_path)) = (&cfg.tls_cert, &cfg.tls_key) {
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert_path).unwrap())).map(|r| r.unwrap()).collect();
        let key_bytes = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(std::fs::File::open(key_path).unwrap())).next().unwrap().unwrap();
        (certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key_bytes.clone_key()), rustls::pki_types::PrivateKeyDer::Pkcs8(key_bytes))
    } else {
        let (c, k1) = generate_ephemeral_cert();
        let (_, k2) = generate_ephemeral_cert();
        (c, k1, k2)
    };
    

    // ============================
    // 1. TCP Server (H2 Tunneling)
    // ============================
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key_tcp)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&cfg.bind_addr).await.unwrap();
    
    // ============================
    // 2. UDP Server (QUIC Tunneling with User-Space NAT Proxy)
    // ============================
    let mut quic_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_quic)
        .unwrap();
    quic_crypto.alpn_protocols = vec![b"h3".to_vec()]; // تظاهر به HTTP/3 برای فرار از سیستم فیلترینگ
    
    let quic_config = QuinnServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(quic_crypto).unwrap()));
    // بایند کردن quinn به یک پورت لوکال تصادفی
    let local_quic_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let quic_endpoint = Endpoint::server(quic_config, local_quic_addr).unwrap();
    let actual_local_quic_addr = quic_endpoint.local_addr().unwrap();

    let fallback_camo = cfg.reality_fallback_url.as_deref()
        .and_then(|u| u.trim_start_matches("https://").trim_start_matches("http://").split('/').next())
        .unwrap_or("www.ubuntu.com");
    let print_target = cfg.reality_target_addr.as_deref().unwrap_or(fallback_camo);
    let reality_target_addr = cfg.reality_target_addr.clone().unwrap_or_else(|| format!("{}:443", print_target));
    
    info!("🛡️ TCP & QUIC (UDP) Server listening concurrently on {} (REALITY-style L4 splice active, target={})", cfg.bind_addr, print_target);
    info!("ℹ️ UDP/QUIC traffic is now protected by TCP-first IP Authorization & User-Space NAT Proxy.");

    // اسپاون کردن پراکسی UDP
    let udp_bind_addr = cfg.bind_addr.clone();
    let udp_auth_ips = authorized_ips.clone();
    let udp_cancel_token = cancel_token.clone();
    let udp_reality_target = reality_target_addr.clone();
    
    tokio::spawn(async move {
        crate::udp_proxy::run_udp_proxy(
            udp_bind_addr,
            actual_local_quic_addr,
            udp_reality_target,
            udp_auth_ips,
            udp_cancel_token,
        ).await;
    });

    // اسپاون کردن روتین QUIC (کاملاً مستقل از TCP)
    let cancel_quic = cancel_token.clone();
    let cipher_quic = cipher.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_quic.cancelled() => break,
                Some(conn) = quic_endpoint.accept() => {
                    let cipher_in = cipher_quic.clone();
                    let cipher_out = cipher_quic.clone();
                    tokio::spawn(async move {
                        if let Ok(connection) = conn.await {
                            while let Ok((mut send_stream, mut recv_stream)) = connection.accept_bi().await {
                                let cipher_in = cipher_in.clone();
                                let cipher_out = cipher_out.clone();
                                tokio::spawn(async move {
                                    // پردازش هدر امن برای QUIC (استخراج آدرس مقصد)
                                    let mut head = [0u8; 5];
                                    if recv_stream.read_exact(&mut head).await.is_err() { return; }
                                    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
                                    if len > 8192 { return; }
                                    let mut payload = crate::buf_pool::PooledVec::new_with_size(len);
                                    if recv_stream.read_exact(&mut payload).await.is_err() { return; }
                                    
                                    let dec = match decrypt_payload(&cipher_in, &payload) {
                                        Ok(d) => d,
                                        Err(_) => return,
                                    };
                                    if dec.is_empty() { return; }
                                    let target_len = dec[0] as usize;
                                    if dec.len() < 1 + target_len { return; }
                                    let target = String::from_utf8_lossy(&dec[1..1+target_len]).to_string();
                                    
                                    if let Ok(target_tcp) = tokio::net::TcpStream::connect(&target).await {
                                        let _ = target_tcp.set_nodelay(true);
                                        enable_tcp_keepalive(&target_tcp);
                                        let (mut target_read, mut target_write) = target_tcp.into_split();
                                        
                                        tokio::spawn(async move {
                                            let mut buf = crate::buf_pool::PooledVec::new_with_size(8192);
                                            loop {
                                                let timeout_dur = std::time::Duration::from_millis(rand::thread_rng().gen_range(20..50));
                                                match tokio::time::timeout(timeout_dur, target_read.read(&mut buf)).await {
                                                    Ok(Ok(0)) => break,
                                                    Ok(Ok(n)) => {
                                                        let framed = frame_grpc(&encrypt_payload(&cipher_out, &buf[..n]));
                                                        if send_stream.write_all(&framed).await.is_err() { break; }
                                                    }
                                                    Ok(Err(_)) => break,
                                                    Err(_) => {
                                                        // Timeout -> Send Dummy Packet
                                                        let framed = frame_grpc(&encrypt_payload(&cipher_out, &[]));
                                                        if send_stream.write_all(&framed).await.is_err() { break; }
                                                    }
                                                }
                                            }
                                        });
                                        
                                        let mut grpc_buf = crate::buf_pool::PooledVec::new();
                                        while let Ok(Some(chunk)) = recv_stream.read_chunk(usize::MAX, true).await {
                                            grpc_buf.extend_from_slice(&chunk.bytes);
                                            while grpc_buf.len() >= 5 {
                                                let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                if grpc_buf.len() < 5 + len { break; }
                                                if let Ok(dec) = decrypt_payload(&cipher_in, &grpc_buf[5..5+len]) {
                                                    if target_write.write_all(&dec).await.is_err() { break; }
                                                }
                                                grpc_buf.drain(0..5+len);
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    });
                }
            }
        }
    });

    // حلقه اصلی پردازش TCP (H2)
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("🛑 Stopping server listener on {} due to Hot-Reload", cfg.bind_addr);
                break;
            }
            accept_res = listener.accept() => {
                if let Ok((tcp, peer)) = accept_res {
                    let _ = tcp.set_nodelay(true);
                    enable_tcp_keepalive(&tcp);

                    let acceptor = acceptor.clone();
                    let cfg_path = cfg.hidden_path.clone();
                    let cfg_secret = cfg.secret.clone();
                    let cfg_camo_domain = cfg.camouflage_domain.clone().unwrap_or_else(|| {
                        cfg.reality_fallback_url.as_deref()
                            .and_then(|u| u.trim_start_matches("https://").trim_start_matches("http://").split('/').next())
                            .unwrap_or("www.ubuntu.com")
                            .to_string()
                    });
                    let cfg_target_addr = cfg.reality_target_addr.clone().unwrap_or_else(|| {
                        format!("{}:443", cfg_camo_domain)
                    });
                    let cipher_in = cipher.clone();
                    let cipher_out = cipher.clone();
                    let authorized_ips = authorized_ips.clone();

                    tokio::spawn(async move {
                        // ==========================================
                        // REALITY-STYLE GATE (لایه ۴/۵.۵)
                        // ------------------------------------------
                        // پیش از هرگونه Handshake واقعی TLS، فقط با peek()
                        // (بدون مصرف بایت) هویت کلاینت از روی SNI بررسی می‌شود.
                        // - کلاینت اصیل ⇒ Handshake محلی با گواهی موقت.
                        // - هرچیز دیگر (اسکنر Active Prober، مرورگر واقعی،
                        //   بایت‌های ناقص/غیر-TLS) ⇒ Splice خام لایه ۴ به
                        //   سرور هدف واقعی؛ صفر پردازش، صفر تاخیر اضافه،
                        //   صفر امکان نشت هدر.
                        // ==========================================
                        let sni = peek_sni(&tcp).await;
                        let authorized = sni.as_deref()
                            .map(|s| is_authorized_sni(s, &cfg_secret, &cfg_camo_domain))
                            .unwrap_or(false);

                        if !authorized {
                            debug!("[{}] Unauthorized/foreign ClientHello (sni={:?}) → raw L4 splice to {}", peer, sni, cfg_target_addr);
                            splice_to_real_target(tcp, &cfg_target_addr).await;
                            return;
                        }

                        debug!("[{}] ✅ REALITY auth OK via camouflage SNI → local tunnel termination", peer);
                        // ذخیره IP برای اجازه عبور ترافیک UDP (QUIC)
                        authorized_ips.write().await.insert(peer.ip(), tokio::time::Instant::now());

                        let tls_stream = match acceptor.accept(tcp).await { Ok(s) => s, Err(_) => return };
                        let mut h2 = match h2::server::handshake(tls_stream).await { Ok(h) => h, Err(_) => return };

                        while let Some(Ok((req, mut respond))) = h2.accept().await {
                            if req.uri().path() != cfg_path {
                                // این کلاینت از قبل در لایه SNI احراز هویت شده؛ اگر با
                                // این‌حال مسیر درخواستش اشتباه بود، به‌جای Fetch از سایت
                                // هدف (که یک نشتی Timing/Header دیگر می‌ساخت) فقط اتصال
                                // بسته می‌شود.
                                let response = http::Response::builder().status(StatusCode::NOT_FOUND).body(()).unwrap();
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            let target = req.headers().get("x-tunnel-target").unwrap().to_str().unwrap().to_string();
                            let mut res_builder = http::Response::builder().status(StatusCode::OK);
                            for (k, v) in get_random_headers() { res_builder = res_builder.header(k, v); }
                            let mut send_stream = respond.send_response(res_builder.body(()).unwrap(), false).unwrap();

                            let cipher_in = cipher_in.clone();
                            let cipher_out = cipher_out.clone();

                            tokio::spawn(async move {
                                if let Ok(target_tcp) = TcpStream::connect(&target).await {
                                    let _ = target_tcp.set_nodelay(true);
                                    enable_tcp_keepalive(&target_tcp);
                                    let (mut target_read, mut target_write) = target_tcp.into_split();

                                    tokio::spawn(async move {
                                        let mut buf = crate::buf_pool::PooledVec::new_with_size(8192);
                                        loop {
                                            let timeout_dur = std::time::Duration::from_millis(rand::thread_rng().gen_range(20..50));
                                            match tokio::time::timeout(timeout_dur, target_read.read(&mut buf)).await {
                                                Ok(Ok(0)) => break,
                                                Ok(Ok(n)) => {
                                                    let framed = frame_grpc(&encrypt_payload(&cipher_out, &buf[..n]));
                                                    send_stream.reserve_capacity(framed.len());
                                                    while send_stream.capacity() < framed.len() {
                                                        if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                    }
                                                    if send_stream.send_data(bytes::Bytes::copy_from_slice(&framed), false).is_err() { break; }
                                                }
                                                Ok(Err(_)) => break,
                                                Err(_) => {
                                                    let framed = frame_grpc(&encrypt_payload(&cipher_out, &[]));
                                                    send_stream.reserve_capacity(framed.len());
                                                    while send_stream.capacity() < framed.len() {
                                                        if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                    }
                                                    if send_stream.send_data(bytes::Bytes::copy_from_slice(&framed), false).is_err() { break; }
                                                }
                                            }
                                        }
                                        let _ = send_stream.send_data(bytes::Bytes::new(), true);
                                    });

                                    let mut grpc_buf = crate::buf_pool::PooledVec::new();
                                    let mut body = req.into_body();
                                    while let Some(Ok(data)) = body.data().await {
                                        let _ = body.flow_control().release_capacity(data.len());
                                        grpc_buf.extend_from_slice(&data);
                                        while grpc_buf.len() >= 5 {
                                            let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                            if grpc_buf.len() < 5 + len { break; }
                                            if let Ok(dec) = decrypt_payload(&cipher_in, &grpc_buf[5..5+len]) {
                                                if target_write.write_all(&dec).await.is_err() { break; }
                                            }
                                            grpc_buf.drain(0..5+len);
                                        }
                                    }
                                }
                            });
                        }
                    });
                }
            }
        }
    }
}
