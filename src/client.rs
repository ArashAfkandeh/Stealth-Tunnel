use crate::config::{ClientConfig, RemoteNode};
use crate::crypto::{decrypt_payload, derive_cipher, encrypt_payload};
use crate::fragment::FragmentedStream;
use crate::net_utils::{enable_tcp_keepalive, frame_grpc, get_random_headers};
use crate::routing::{extract_sni, parse_port_mappings};

use boring::ssl::{SslConnector, SslMethod, SslOptions};
use bytes::{Bytes, BytesMut};
use http::{Method, Request};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use std::{
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    net::TcpStream,
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

#[derive(Clone)]
enum ClientPoolItem {
    H2(h2::client::SendRequest<Bytes>),
    Quic(quinn::Connection),
}

async fn connect_h2_node(remote: &RemoteNode, tls_connector: &SslConnector) -> Result<h2::client::SendRequest<Bytes>, String> {
    let tcp = TcpStream::connect(&remote.addr).await.map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    enable_tcp_keepalive(&tcp);
    let frag_tcp = FragmentedStream { inner: tcp, first_write: false };
    
    let mut config = tls_connector.configure().map_err(|e| e.to_string())?;
    config.set_verify_hostname(false); // Can be enabled with proper roots for stealth
    
    let tls_stream = tokio_boring::connect(config, &remote.sni, frag_tcp).await.map_err(|e| e.to_string())?;
    let (client, conn) = h2::client::handshake(tls_stream).await.map_err(|e| e.to_string())?;

    tokio::spawn(async move {
        if let Err(e) = conn.await { debug!("H2 background connection closed: {:?}", e); }
    });
    Ok(client)
}

pub async fn run_client(cfg: ClientConfig, cancel_token: CancellationToken) {
    if cfg.remotes.is_empty() {
        error!("No remote servers defined in [client.remotes]!");
        return;
    }

    let cipher = Arc::new(derive_cipher(&cfg.secret));

    // 1. استتار ClientHello با BoringSSL برای ارتباطات TCP (H2)
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_options(SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    builder.set_alpn_protos(b"\x02h2").unwrap();
    builder.set_grease_enabled(true);
    builder.set_cipher_list("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384").unwrap();
    let tls_connector = Arc::new(builder.build());

    // 2. پیکربندی QUIC برای ارتباطات UDP (Multiplexing قدرتمند بدون Head-of-line blocking)
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut quic_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    quic_crypto.alpn_protocols = vec![b"h3".to_vec()]; // تظاهر به ترافیک استاندارد HTTP/3
    let quic_client_cfg = QuinnClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(quic_crypto).unwrap()));
    let mut quic_endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    quic_endpoint.set_default_client_config(quic_client_cfg);
    let quic_endpoint = Arc::new(quic_endpoint);

    let pool_per_node = cfg.pool_size_per_node;
    let total_pool_size = cfg.remotes.len() * pool_per_node;

    info!("Initializing Distributed Tunnel Pool ({} nodes x {} conns = {} total streams)...", cfg.remotes.len(), pool_per_node, total_pool_size);

    let mut pool: Vec<(Arc<Mutex<Option<ClientPoolItem>>>, RemoteNode)> = Vec::new();
    for remote in &cfg.remotes {
        for _ in 0..pool_per_node {
            pool.push((Arc::new(Mutex::new(None)), remote.clone()));
        }
    }
    let pool = Arc::new(pool);
    let conn_counter = Arc::new(AtomicUsize::new(0));

    let mapped_routes = parse_port_mappings(&cfg.port_mappings);

    for (local_bind, route_table) in mapped_routes {
        let listener = match TcpListener::bind(&local_bind).await {
            Ok(l) => l, Err(e) => { error!("Failed to bind {}: {}", local_bind, e); continue; }
        };
        info!("🚀 Listener active on {} with {} SNI rules", local_bind, route_table.sni_rules.len());

        let cfg_clone = cfg.clone();
        let tls_clone = tls_connector.clone();
        let quic_clone = quic_endpoint.clone();
        let pool_clone = pool.clone();
        let cipher_clone = cipher.clone();
        let counter_clone = conn_counter.clone();
        let token = cancel_token.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        info!("🛑 Stopping listener on {} due to Hot-Reload", local_bind);
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((local_tcp, peer)) = accept_res {
                            let _ = local_tcp.set_nodelay(true);
                            enable_tcp_keepalive(&local_tcp);
                            let c_id = counter_clone.fetch_add(1, Ordering::SeqCst);

                            let route_table = route_table.clone();
                            let pool_clone = pool_clone.clone();
                            let tls_inner = tls_clone.clone();
                            let quic_inner = quic_clone.clone();
                            let cfg_inner = cfg_clone.clone();
                            let cipher_in = cipher_clone.clone();
                            let cipher_out = cipher_clone.clone();

                            tokio::spawn(async move {
                                // استخراج SNI
                                let mut extracted_sni = None;
                                let mut peek_buf = [0u8; 2048];
                                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                                    loop {
                                        let n = local_tcp.peek(&mut peek_buf).await.unwrap_or(0);
                                        if n > 0 {
                                            if peek_buf[0] != 0x16 { break; } 
                                            if let Some(sni) = extract_sni(&peek_buf[..n]) {
                                                extracted_sni = Some(sni);
                                                break;
                                            }
                                        }
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                    }
                                }).await;

                                let target_up = if let Some(sni) = &extracted_sni {
                                    trace!("[Conn #{}] Detected SNI: {}", c_id, sni);
                                    route_table.sni_rules.get(sni).cloned().or_else(|| route_table.default_upstream.clone())
                                } else {
                                    route_table.default_upstream.clone()
                                };

                                let target_up = match target_up {
                                    Some(t) => t,
                                    None => {
                                        warn!("[Conn #{}] Connection from {} dropped: No matching SNI or default route.", c_id, peer);
                                        return;
                                    }
                                };

                                debug!("[Conn #{}] Accepted {} -> Routed to {}", c_id, peer, target_up);

                                let (mut local_read, mut local_write) = local_tcp.into_split();
                                let (pool_slot, target_remote) = pool_clone[c_id % total_pool_size].clone();

                                let mut resolved_client = None;
                                let mut retry = true;
                                while retry {
                                    let client_opt = { pool_slot.lock().await.as_ref().cloned() };
                                    if let Some(c_clone) = client_opt {
                                        match c_clone {
                                            ClientPoolItem::H2(h2_c) => {
                                                if let Ok(ready_c) = h2_c.ready().await {
                                                    resolved_client = Some(ClientPoolItem::H2(ready_c));
                                                    retry = false;
                                                } else { *pool_slot.lock().await = None; }
                                            }
                                            ClientPoolItem::Quic(quic_c) => {
                                                if quic_c.close_reason().is_some() {
                                                    *pool_slot.lock().await = None;
                                                } else {
                                                    resolved_client = Some(ClientPoolItem::Quic(quic_c));
                                                    retry = false;
                                                }
                                            }
                                        }
                                    } else {
                                        if target_remote.protocol.as_deref() == Some("quic") {
                                            if let Ok(conn) = quic_inner.connect(target_remote.addr.parse().unwrap(), &target_remote.sni).unwrap().await {
                                                *pool_slot.lock().await = Some(ClientPoolItem::Quic(conn));
                                            } else {
                                                tokio::time::sleep(Duration::from_millis(1500)).await;
                                            }
                                        } else {
                                            if let Ok(new_c) = connect_h2_node(&target_remote, &tls_inner).await {
                                                *pool_slot.lock().await = Some(ClientPoolItem::H2(new_c));
                                            } else {
                                                tokio::time::sleep(Duration::from_millis(1500)).await;
                                            }
                                        }
                                    }
                                }

                                match resolved_client.unwrap() {
                                    ClientPoolItem::Quic(conn) => {
                                        if let Ok((mut send_stream, mut recv_stream)) = conn.open_bi().await {
                                            // ارسال آدرس مقصد در بستر امن QUIC
                                            let target_bytes = target_up.as_bytes();
                                            let mut initial_payload = vec![target_bytes.len() as u8];
                                            initial_payload.extend_from_slice(target_bytes);
                                            let enc_initial = encrypt_payload(&cipher_out, &initial_payload);
                                            let framed = frame_grpc(&enc_initial);
                                            if send_stream.write_all(&framed).await.is_err() { return; }
                                            
                                            tokio::spawn(async move {
                                                let mut buf = [0u8; 8192];
                                                while let Ok(n) = local_read.read(&mut buf).await {
                                                    if n == 0 { break; }
                                                    let framed = frame_grpc(&encrypt_payload(&cipher_out, &buf[..n]));
                                                    if send_stream.write_all(&framed).await.is_err() { break; }
                                                }
                                            });
                                            
                                            let mut grpc_buf = BytesMut::new();
                                            let mut buf = [0u8; 8192];
                                            while let Ok(Some(n)) = recv_stream.read(&mut buf).await {
                                                if n == 0 { break; }
                                                grpc_buf.extend_from_slice(&buf[..n]);
                                                while grpc_buf.len() >= 5 {
                                                    let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                    if grpc_buf.len() < 5 + len { break; }
                                                    if let Ok(dec) = decrypt_payload(&cipher_in, &grpc_buf[5..5+len]) {
                                                        if local_write.write_all(&dec).await.is_err() { break; }
                                                    }
                                                    let _ = grpc_buf.split_to(5 + len);
                                                }
                                            }
                                        }
                                    }
                                    ClientPoolItem::H2(mut ready_client) => {
                                        let mut req_builder = Request::builder()
                                            .method(Method::POST)
                                            .uri(format!("https://{}{}", target_remote.host, cfg_inner.hidden_path))
                                            .header("Host", target_remote.host.clone())
                                            .header("x-tunnel-target", target_up);

                                        for (k, v) in get_random_headers() { req_builder = req_builder.header(k, v); }

                                        let (response, mut send_stream) = match ready_client.send_request(req_builder.body(()).unwrap(), false) {
                                            Ok(res) => res, Err(_) => return,
                                        };

                                        tokio::spawn(async move {
                                            let mut buf = [0u8; 8192];
                                            while let Ok(n) = local_read.read(&mut buf).await {
                                                if n == 0 { break; }
                                                let framed = frame_grpc(&encrypt_payload(&cipher_out, &buf[..n]));
                                                send_stream.reserve_capacity(framed.len());
                                                while send_stream.capacity() < framed.len() {
                                                    if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                }
                                                if send_stream.send_data(framed, false).is_err() { break; }
                                            }
                                            let _ = send_stream.send_data(Bytes::new(), true);
                                        });

                                        let mut grpc_buf = BytesMut::new();
                                        if let Ok(res) = response.await {
                                            let mut body = res.into_body();
                                            while let Some(Ok(data)) = body.data().await {
                                                let _ = body.flow_control().release_capacity(data.len());
                                                grpc_buf.extend_from_slice(&data);
                                                while grpc_buf.len() >= 5 {
                                                    let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                    if grpc_buf.len() < 5 + len { break; }
                                                    if let Ok(dec) = decrypt_payload(&cipher_in, &grpc_buf[5..5+len]) {
                                                        if local_write.write_all(&dec).await.is_err() { break; }
                                                    }
                                                    let _ = grpc_buf.split_to(5 + len);
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });
    }
    cancel_token.cancelled().await;
}
