use crate::config::ServerConfig;

use crate::net_utils::{enable_tcp_keepalive, get_random_headers};

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use std::{fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

// ==========================================
// 6. SERVER MODE
// ==========================================
pub async fn run_server(cfg: ServerConfig, cancel_token: CancellationToken) {
    let cert_file = match fs::File::open(&cfg.tls_cert) {
        Ok(f) => f,
        Err(_) => {
            tracing::error!("❌ گواهینامه TLS پیدا نشد!");
            tracing::error!("مسیر جستجو: {}", cfg.tls_cert);
            tracing::error!("اگر از توکن Cloudflare استفاده نمی‌کنید، باید گواهینامه‌های خود را به صورت دستی در این مسیر قرار دهید.");
            tracing::error!("برنامه متوقف شد.");
            std::process::exit(1);
        }
    };
    
    let key_file = match fs::File::open(&cfg.tls_key) {
        Ok(f) => f,
        Err(_) => {
            tracing::error!("❌ فایل کلید خصوصی (Private Key) پیدا نشد!");
            tracing::error!("مسیر جستجو: {}", cfg.tls_key);
            tracing::error!("برنامه متوقف شد.");
            std::process::exit(1);
        }
    };

    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file)).map(|r| r.unwrap()).collect();
    let key = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(key_file)).next().unwrap().unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = crate::net_utils::create_reuseport_listener(&cfg.bind_addr).unwrap();
    info!("🛡️ Server listening on {}", cfg.bind_addr);
    
    let mut route_table = std::collections::HashMap::new();
    crate::routing::parse_port_mappings(cfg.port_mappings.as_ref().unwrap_or(&vec![]), None, &mut route_table);
    let local_route = Arc::new(route_table.get(&cfg.bind_addr).cloned().unwrap_or_default());

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("🛑 Stopping server listener on {} due to Hot-Reload", cfg.bind_addr);
                break;
            }
            accept_res = listener.accept() => {
                if let Ok((mut tcp, peer)) = accept_res {
                    tracing::debug!("🔗 Accepted TCP connection from {}", peer);
                    let _ = tcp.set_nodelay(true);
                    crate::net_utils::enable_tcp_bbr(&tcp);
                    crate::net_utils::tune_socket_buffers(&tcp);
                    enable_tcp_keepalive(&tcp);

                    let acceptor = acceptor.clone();
                    let cfg_path = cfg.hidden_path.clone();
                    let cfg_camo = cfg.camouflage_target.clone();
                    let cfg_secret = cfg.secret.clone();
                    let route = local_route.clone();

                    tokio::spawn(async move {
                        let mut initial_buf = [0u8; 2048];
                        let mut initial_len = 0;
                        let mut extracted_sni = None;
                        
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                            loop {
                                if initial_len >= 2048 { break; }
                                let n = match tcp.read(&mut initial_buf[initial_len..]).await {
                                    Ok(n) if n > 0 => n,
                                    _ => break,
                                };
                                initial_len += n;

                                if initial_buf[0] != 0x16 { break; }
                                if let Some(sni) = crate::routing::extract_sni(&initial_buf[..initial_len]) {
                                    extracted_sni = Some(sni);
                                    break;
                                }

                                if initial_len >= 5 {
                                    let record_len = ((initial_buf[3] as usize) << 8) | (initial_buf[4] as usize);
                                    if initial_len >= 5 + record_len {
                                        break; 
                                    }
                                }
                            }
                        }).await;
                        
                        let target_up = if let Some(sni) = &extracted_sni {
                            route.sni_rules.get(sni).cloned().or_else(|| route.default_upstream.clone())
                        } else {
                            route.default_upstream.clone()
                        };

                        if let Some(target) = target_up {
                            tracing::debug!("🔄 SNI Routing triggered for {:?} -> {}", extracted_sni, target);
                            match TcpStream::connect(&target).await {
                                Ok(mut upstream_tcp) => {
                                    let _ = upstream_tcp.set_nodelay(true);
                                    crate::net_utils::tune_socket_buffers(&upstream_tcp);
                                    crate::net_utils::enable_tcp_keepalive(&upstream_tcp);
                                    
                                    if initial_len > 0 {
                                        if upstream_tcp.write_all(&initial_buf[..initial_len]).await.is_err() { return; }
                                    }
                                    
                                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream_tcp).await;
                                }
                                Err(e) => tracing::error!("Failed to connect to SNI target {}: {}", target, e),
                            }
                            return;
                        }

                        let prefixed_tcp = crate::prefixed_stream::PrefixedStream {
                            prefix: initial_buf[..initial_len].to_vec(),
                            inner: tcp,
                        };

                        let tls_stream = match acceptor.accept(prefixed_tcp).await { 
                            Ok(s) => { tracing::debug!("🔒 TLS Handshake succeeded"); s }, 
                            Err(e) => { tracing::debug!("TLS Accept failed: {:?}", e); return } 
                        };
                        let mut h2 = match h2::server::Builder::new()
                            .initial_window_size(33_554_432) // 32 MB Stream Window
                            .initial_connection_window_size(134_217_728) // 128 MB Connection Window
                            .max_frame_size(1_048_576) // 1 MB max frame
                            .handshake(tls_stream).await { Ok(h) => h, Err(e) => { tracing::debug!("H2 Handshake failed: {:?}", e); return } };

                        while let Some(Ok((req, mut respond))) = h2.accept().await {
                            let tunnel_target = if req.uri().path() != cfg_path {
                                None
                            } else {
                                let t_hdr = req.headers().get("x-tunnel-target").and_then(|h| h.to_str().ok());
                                let s_hdr = req.headers().get("x-tunnel-secret").and_then(|h| h.to_str().ok());
                                match (t_hdr, s_hdr) {
                                    (Some(t_val), Some(s_val)) if s_val == cfg_secret.clone().unwrap_or_default() => Some(t_val.to_string()),
                                    _ => {
                                        tracing::warn!("Unauthorized or malformed request to hidden path from {}", peer);
                                        None
                                    }
                                }
                            };

                            if tunnel_target.is_none() {
                                if let Some(camo) = &cfg_camo {
                                    if camo.starts_with("http://") || camo.starts_with("https://") {
                                        let url = format!("{}{}", camo, req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
                                        tokio::spawn(async move {
                                            let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
                                            match client.get(&url).send().await {
                                                Ok(mut resp) => {
                                                    let mut res_builder = http::Response::builder().status(resp.status());
                                                    for (k, v) in resp.headers() {
                                                        let k_str = k.as_str().to_lowercase();
                                                        if k_str != "transfer-encoding" && k_str != "connection" && k_str != "content-length" {
                                                            res_builder = res_builder.header(k.clone(), v.clone());
                                                        }
                                                    }
                                                    if let Ok(mut send_stream) = respond.send_response(res_builder.body(()).unwrap(), false) {
                                                        while let Ok(Some(chunk)) = resp.chunk().await {
                                                            send_stream.reserve_capacity(chunk.len());
                                                            while send_stream.capacity() < chunk.len() {
                                                                if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                            }
                                                            if send_stream.send_data(chunk, false).is_err() { break; }
                                                        }
                                                        let _ = send_stream.send_data(Bytes::new(), true);
                                                    }
                                                }
                                                Err(_) => {
                                                    let _ = respond.send_response(http::Response::builder().status(404).body(()).unwrap(), true);
                                                }
                                            }
                                        });
                                    } else {
                                        let camo_clone = camo.clone();
                                        tokio::spawn(async move {
                                            let mut file_path = std::path::PathBuf::from(&camo_clone);
                                            if file_path.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true) {
                                                let exe_dir = std::env::current_exe()
                                                    .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
                                                    .parent()
                                                    .unwrap_or(std::path::Path::new(""))
                                                    .to_path_buf();
                                                file_path = exe_dir.join(&camo_clone);
                                            }

                                            if let Ok(content) = tokio::fs::read(&file_path).await {
                                                let res = http::Response::builder()
                                                    .status(200)
                                                    .header("content-type", "text/html; charset=utf-8")
                                                    .body(())
                                                    .unwrap();
                                                if let Ok(mut send_stream) = respond.send_response(res, false) {
                                                    let framed = Bytes::from(content);
                                                    send_stream.reserve_capacity(framed.len());
                                                    while send_stream.capacity() < framed.len() {
                                                        if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                    }
                                                    let _ = send_stream.send_data(framed, true);
                                                }
                                            } else {
                                                let _ = respond.send_response(http::Response::builder().status(404).body(()).unwrap(), true);
                                            }
                                        });
                                    }
                                } else {
                                    let _ = respond.send_response(http::Response::builder().status(404).body(()).unwrap(), true);
                                }
                                continue;
                            }

                            let target_val = tunnel_target.unwrap();
                            tracing::debug!("🎯 Valid tunnel request received for target: {}", target_val);
                            
                            let mut target = target_val;
                            if !target.contains(':') {
                                target = format!("127.0.0.1:{}", target);
                            }
                            
                            let mut res_builder = http::Response::builder().status(StatusCode::OK);
                            for (k, v) in get_random_headers() { res_builder = res_builder.header(k, v); }
                            let mut send_stream = respond.send_response(res_builder.body(()).unwrap(), false).unwrap();


                            let is_udp = req.headers().get("x-tunnel-protocol").map(|v| v.as_bytes() == b"udp").unwrap_or(false);

                            tokio::spawn(async move {
                                if is_udp {
                                    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                        Ok(s) => Arc::new(s),
                                        Err(e) => { tracing::error!("Failed to bind UDP socket: {}", e); return; }
                                    };
                                    let target_addr: std::net::SocketAddr = match tokio::net::lookup_host(&target).await.and_then(|mut iter| iter.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No IP found"))) {
                                        Ok(a) => a,
                                        Err(e) => { tracing::error!("Invalid UDP target addr {}: {}", target, e); return; }
                                    };
                                    tracing::debug!("✅ Successfully bound local UDP socket for target: {}", target);

                                    let socket_recv = socket.clone();
                                    tokio::spawn(async move {
                                        let mut buf = [0u8; 65536];
                                        loop {
                                            match socket_recv.recv_from(&mut buf).await {
                                                Ok((n, from)) if from == target_addr => {
                                                    let mut init_buf = BytesMut::with_capacity(5 + n);
                                                    init_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                                    init_buf[1..5].copy_from_slice(&(n as u32).to_be_bytes());
                                                    init_buf.extend_from_slice(&buf[..n]);
                                                    let framed = init_buf.freeze();
                                                    
                                                    send_stream.reserve_capacity(framed.len());
                                                    while send_stream.capacity() < framed.len() {
                                                        if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                    }
                                                    if send_stream.send_data(framed, false).is_err() { break; }
                                                }
                                                Ok(_) => continue,
                                                Err(_) => break,
                                            }
                                        }
                                        let _ = send_stream.send_data(Bytes::new(), true);
                                    });

                                    let mut grpc_buf = BytesMut::new();
                                    let mut body = req.into_body();
                                    while let Some(Ok(mut data)) = body.data().await {
                                        let _ = body.flow_control().release_capacity(data.len());
                                        if grpc_buf.is_empty() {
                                            while data.len() >= 5 {
                                                let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                                                if data.len() < 5 + len { break; }
                                                if socket.send_to(&data[5..5+len], target_addr).await.is_err() { return; }
                                                data = data.slice(5+len..);
                                            }
                                            if !data.is_empty() { grpc_buf.extend_from_slice(&data); }
                                        } else {
                                            grpc_buf.extend_from_slice(&data);
                                            while grpc_buf.len() >= 5 {
                                                let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                if grpc_buf.len() < 5 + len { break; }
                                                if socket.send_to(&grpc_buf[5..5+len], target_addr).await.is_err() { return; }
                                                let _ = grpc_buf.split_to(5 + len);
                                            }
                                        }
                                    }
                                    return;
                                }
                                match TcpStream::connect(&target).await {
                                    Ok(target_tcp) => {
                                        tracing::debug!("✅ Successfully connected to local target: {}", target);
                                        let _ = target_tcp.set_nodelay(true);
                                        crate::net_utils::tune_socket_buffers(&target_tcp);
                                        enable_tcp_keepalive(&target_tcp);
                                        let (mut target_read, mut target_write) = target_tcp.into_split();

                                    tokio::spawn(async move {
                                        let mut read_buf = BytesMut::with_capacity(65536 + 5);
                                        loop {
                                            read_buf.clear();
                                            read_buf.reserve(65536 + 5);
                                            read_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                            let n = match target_read.read_buf(&mut read_buf).await {
                                                Ok(0) | Err(_) => break,
                                                Ok(n) => n,
                                            };
                                            read_buf[1..5].copy_from_slice(&(n as u32).to_be_bytes());
                                            let framed = read_buf.split().freeze();
                                            
                                            send_stream.reserve_capacity(framed.len());
                                            while send_stream.capacity() < framed.len() {
                                                if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                            }
                                            if send_stream.send_data(framed, false).is_err() { break; }
                                        }
                                        let _ = send_stream.send_data(Bytes::new(), true);
                                    });

                                    let mut grpc_buf = BytesMut::new();
                                    let mut body = req.into_body();
                                    while let Some(Ok(mut data)) = body.data().await {
                                        let _ = body.flow_control().release_capacity(data.len());
                                        
                                        if grpc_buf.is_empty() {
                                            while data.len() >= 5 {
                                                let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                                                if data.len() < 5 + len { break; }
                                                if target_write.write_all(&data[5..5+len]).await.is_err() { return; }
                                                data = data.slice(5+len..);
                                            }
                                            if !data.is_empty() {
                                                grpc_buf.extend_from_slice(&data);
                                            }
                                        } else {
                                            grpc_buf.extend_from_slice(&data);
                                            while grpc_buf.len() >= 5 {
                                                let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                if grpc_buf.len() < 5 + len { break; }
                                                if target_write.write_all(&grpc_buf[5..5+len]).await.is_err() { return; }
                                                let _ = grpc_buf.split_to(5 + len);
                                            }
                                        }
                                    }
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to connect to local target {}: {}", target, e);
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
