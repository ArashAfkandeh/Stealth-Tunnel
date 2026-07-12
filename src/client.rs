use crate::config::ClientConfig;


use crate::net_utils::{enable_tcp_keepalive, get_random_headers};
use crate::routing::extract_sni;

use bytes::{Bytes, BytesMut};
use http::{Method, Request};
use std::{
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};


pub struct ConnectionState {
    pub client: Option<h2::client::SendRequest<Bytes>>,
    pub consecutive_errors: u32,
    pub ewma_latency: f64,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self { client: None, consecutive_errors: 0, ewma_latency: 500.0 }
    }
}


#[derive(Debug, Clone)]
pub struct ActiveNode {
    pub location: String,
    pub sni: String,
}

async fn connect_h2_node(node: &ActiveNode, clean_ips: &[String], tls_connector: &TlsConnector) -> Result<h2::client::SendRequest<Bytes>, String> {
    let (sni_host, sni_port) = if let Some(idx) = node.sni.rfind(':') {
        (&node.sni[..idx], &node.sni[idx+1..])
    } else {
        (node.sni.as_str(), "443")
    };

    use futures::stream::{FuturesUnordered, StreamExt};
    let mut connect_tasks = FuturesUnordered::new();
    
    for ip in clean_ips {
        let addr_str = if ip.contains(':') && !ip.starts_with('[') {
             if ip.split(':').count() > 2 {
                 format!("[{}]:{}", ip, sni_port) // IPv6
             } else {
                 ip.to_string() // User provided IPv4:Port in clean_ip? Unlikely but supported
             }
        } else {
             format!("{}:{}", ip, sni_port)
        };
        
        connect_tasks.push(async move {
            let addrs = tokio::net::lookup_host(&addr_str).await.map_err(|e| e.to_string())?.collect::<Vec<_>>();
            for addr in addrs {
                 if let Ok(Ok(stream)) = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr)).await {
                     return Ok::<_, String>(stream);
                 }
            }
            Err::<_, String>("Failed".into())
        });
    }

    let mut tcp_opt = None;
    while let Some(res) = connect_tasks.next().await {
        if let Ok(stream) = res {
            tcp_opt = Some(stream);
            break;
        }
    }

    let tcp = tcp_opt.ok_or_else(|| "All TCP connection attempts (Racing) failed".to_string())?;
    let _ = tcp.set_nodelay(true);
    crate::net_utils::enable_tcp_bbr(&tcp);
    crate::net_utils::tune_socket_buffers(&tcp);
    enable_tcp_keepalive(&tcp);

    let domain = rustls::pki_types::ServerName::try_from(sni_host).map_err(|e| e.to_string())?.to_owned();
    let tls_stream = tls_connector.connect(domain, tcp).await.map_err(|e| e.to_string())?;
    
    // Use aggressive HTTP/2 flow control windows (Default 65KB is too slow for WAN)
    let (client, conn) = h2::client::Builder::new()
        .initial_window_size(33_554_432) // 32 MB Stream Window
        .initial_connection_window_size(134_217_728) // 128 MB Connection Window
        .max_frame_size(1_048_576) // 1 MB max frame
        .handshake(tls_stream).await.map_err(|e| e.to_string())?;

    tokio::spawn(async move {
        if let Err(e) = conn.await { debug!("H2 background connection closed: {:?}", e); }
    });
    Ok(client)
}

pub async fn run_client(cfg: ClientConfig, cancel_token: CancellationToken) {
    let mut flat_remotes = Vec::new();
    for loc in cfg.remotes.iter() {
        for sni in loc.sni.iter() {
            flat_remotes.push(ActiveNode {
                location: loc.location.clone(),
                sni: sni.clone(),
            });
        }
    }
    if flat_remotes.is_empty() {
        error!("No remote servers defined!");
        return;
    }

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    let mut tls_config_h2 = rustls::ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();
    tls_config_h2.alpn_protocols = vec![b"h2".to_vec()];
    let tls_connector = Arc::new(TlsConnector::from(Arc::new(tls_config_h2)));

    let pool_per_node = cfg.pool_size_per_node.unwrap_or(16);
    let total_pool_size = flat_remotes.len() * pool_per_node;

    info!("Initializing Distributed Pool ({} nodes x {} conns = {} total streams)...", flat_remotes.len(), pool_per_node, total_pool_size);

    let mut pool: Vec<(Arc<Mutex<ConnectionState>>, ActiveNode)> = Vec::new();
    for _ in 0..pool_per_node {
        for remote in &flat_remotes {
            pool.push((Arc::new(Mutex::new(ConnectionState::default())), remote.clone()));
        }
    }
    let pool = Arc::new(pool);

    // Eager Pool Maintainer (Background Connect)
    let clean_ips_global = Arc::new(cfg.clean_ip.clone());
    for (slot_arc, remote) in pool.iter() {
        let slot = slot_arc.clone();
        let remote = remote.clone();
        let tls = tls_connector.clone();
        let token = cancel_token.clone();
        let clean_ips = clean_ips_global.clone();
        
        tokio::spawn(async move {
            loop {
                if token.is_cancelled() { break; }
                
                let is_none = slot.lock().await.client.is_none();
                if is_none {
                    let start_time = tokio::time::Instant::now();
                    if let Ok(new_client) = connect_h2_node(&remote, &clean_ips, &tls).await {
                        let mut guard = slot.lock().await;
                        guard.client = Some(new_client);
                        guard.consecutive_errors = 0;
                        guard.ewma_latency = start_time.elapsed().as_millis() as f64;
                        tracing::debug!("🔥 Pool Maintainer: Warmed up connection to {} ({}ms)", remote.sni, guard.ewma_latency);
                    }
                }
                
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                    _ = token.cancelled() => break,
                }
            }
        });
    }

    let conn_counter = Arc::new(AtomicUsize::new(0));
    let accept_udp = cfg.accept_udp.as_deref() == Some("yes");
    let mut mapped_routes = std::collections::HashMap::new();
    for loc in cfg.remotes.iter() {
        crate::routing::parse_port_mappings(&loc.port_mappings, Some(&loc.location), &mut mapped_routes);
    }

    if accept_udp {
        for (local_bind, route_table) in mapped_routes.clone() {
            let remote_target = if let Some(up) = &route_table.default_upstream {
                up.clone()
            } else if let Some(up) = route_table.sni_rules.values().next() {
                up.clone()
            } else {
                continue;
            };

            let local_bind = local_bind.clone();
            let route_table = route_table.clone();
            
            let pool_clone = pool.clone();
            let cfg_inner = cfg.clone();
            let token = cancel_token.clone();
            
            tokio::spawn(async move {
                let socket = match crate::net_utils::create_reuseport_udp_socket(&local_bind) {
                    Ok(s) => Arc::new(s),
                    Err(e) => { tracing::error!("Failed to bind UDP {}: {}", local_bind, e); return; }
                };
                tracing::info!("🚀 UDP Listener active on {} -> {}", local_bind, remote_target);

                let mut active_streams = std::collections::HashMap::new();
                let (cleanup_tx, mut cleanup_rx) = tokio::sync::mpsc::channel(100);
                let mut buf = [0u8; 65536];

                loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            tracing::info!("🛑 Stopping UDP listener on {} due to Hot-Reload", local_bind);
                            break;
                        }
                        Some(peer) = cleanup_rx.recv() => {
                            active_streams.remove(&peer);
                        }
                        res = socket.recv_from(&mut buf) => {
                            let (len, peer) = match res { Ok(x) => x, Err(_) => continue };
                            let data = Bytes::copy_from_slice(&buf[..len]);

                            let tx = active_streams.entry(peer).or_insert_with(|| {
                                let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(100);
                                let pool_clone = pool_clone.clone();
                                let cfg_inner = cfg_inner.clone();
                                let target_up = remote_target.clone();
                                let udp_socket = socket.clone();
                                let cleanup_tx = cleanup_tx.clone();
                                let route_table = route_table.clone();

                                tokio::spawn(async move {
                                let mut final_send_stream = None;
                                let mut final_response = None;
                                let mut global_retries = 0;
                                let mut failed_snis = std::collections::HashSet::new();
                                
                                while global_retries < 5 {
                                    let mut ready_client = None;
                                    let mut retries = 0;
                                    while retries < 5 {
                                        let mut best_client = None;
                                        let mut best_slot = None;
                                        let mut best_remote = None;
                                        let mut lowest_latency = f64::MAX;
                                        let total_pool_size = pool_clone.len();
                                        
                                        for i in 0..total_pool_size {
                                            let (pool_slot, target_remote) = &pool_clone[i];
                                            
                                            if failed_snis.contains(&target_remote.sni) {
                                                continue;
                                            }
                                            
                                            let mut slot_guard = pool_slot.lock().await;
                                            if let Some(c) = &slot_guard.client {
                                                let mut c_clone = c.clone();
                                                if let Ok(_) = std::future::poll_fn(|cx| c_clone.poll_ready(cx)).await {
                                                    let mut penalty = 0.0;
                                                    if let Some(pref) = route_table.target_locations.get(&target_up) {
                                                        if target_remote.location != *pref {
                                                            penalty = 10000.0;
                                                        }
                                                    }
                                                    let score = slot_guard.ewma_latency + penalty;
                                                    if score < lowest_latency {
                                                        lowest_latency = score;
                                                        best_client = Some(c_clone);
                                                        best_slot = Some(pool_slot.clone());
                                                        best_remote = Some(target_remote.clone());
                                                    }
                                                } else {
                                                    slot_guard.client = None;
                                                }
                                            }
                                        }

                                        if let Some(c) = best_client {
                                            ready_client = Some((c, best_slot.unwrap(), best_remote.unwrap()));
                                            break;
                                        } else {
                                            retries += 1;
                                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                        }
                                    }
                                    
                                    if ready_client.is_none() {
                                        tracing::error!("All pool slots are disconnected! Connection dropped.");
                                        return;
                                    }

                                    let (mut c, pool_slot, target_remote) = ready_client.unwrap();

                                    let mut req_builder = Request::builder()
                                        .method(Method::POST)
                                        .uri(format!("https://{}{}", target_remote.sni, cfg_inner.hidden_path))
                                        .header("Host", target_remote.sni.clone())
                                        .header("x-tunnel-protocol", "udp")
                                        .header("x-tunnel-target", target_up.clone())
                                        .header("x-tunnel-secret", cfg_inner.secret.clone().unwrap_or_default());

                                    for (k, v) in get_random_headers() { req_builder = req_builder.header(k, v); }

                                    let start_time = tokio::time::Instant::now();
                                    match c.send_request(req_builder.body(()).unwrap(), false) {
                                        Ok((response_future, send_stream)) => {
                                            if let Ok(Ok(res)) = tokio::time::timeout(std::time::Duration::from_millis(5000), response_future).await {
                                                if res.status() == http::StatusCode::OK {
                                                    let latency = start_time.elapsed().as_millis() as f64;
                                                    let mut slot = pool_slot.lock().await;
                                                    slot.ewma_latency = (0.2 * latency) + (0.8 * slot.ewma_latency);
                                                    slot.consecutive_errors = 0;
                                                    
                                                    if !failed_snis.is_empty() {
                                                        tracing::info!("UDP Tunnel successfully fell back to alternate SNI: {}", target_remote.sni);
                                                    }
                                                    
                                                    final_send_stream = Some(send_stream);
                                                    final_response = Some(res);
                                                    break;
                                                }
                                                tracing::error!("UDP Tunnel failed! Remote server {} returned HTTP {}", target_remote.sni, res.status());
                                                let mut slot = pool_slot.lock().await;
                                                slot.client = None; 
                                                slot.consecutive_errors = 0;
                                                failed_snis.insert(target_remote.sni.clone());
                                            } else {
                                                let mut slot = pool_slot.lock().await;
                                                slot.client = None;
                                                failed_snis.insert(target_remote.sni.clone());
                                            }
                                        }
                                        Err(_) => {
                                            let mut slot = pool_slot.lock().await;
                                            slot.consecutive_errors += 1;
                                            if slot.consecutive_errors >= 3 {
                                                slot.client = None; slot.consecutive_errors = 0;
                                            }
                                            failed_snis.insert(target_remote.sni.clone());
                                        }
                                    }

                                    global_retries += 1;
                                }
                                
                                if final_send_stream.is_none() {
                                    tracing::error!("All UDP tunnel attempts failed.");
                                    return;
                                }
                                
                                let mut send_stream = final_send_stream.unwrap();
                                let response = final_response.unwrap();

                                    tokio::spawn(async move {
                                        let mut grpc_buf = BytesMut::new();
                                        let mut body = response.into_body();
                                        while let Some(Ok(mut data)) = body.data().await {
                                            let _ = body.flow_control().release_capacity(data.len());
                                            if grpc_buf.is_empty() {
                                                while data.len() >= 5 {
                                                    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                                                    if data.len() < 5 + len { break; }
                                                    let _ = udp_socket.send_to(&data[5..5+len], peer).await;
                                                    data = data.slice(5+len..);
                                                }
                                                if !data.is_empty() { grpc_buf.extend_from_slice(&data); }
                                            } else {
                                                grpc_buf.extend_from_slice(&data);
                                                while grpc_buf.len() >= 5 {
                                                    let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                    if grpc_buf.len() < 5 + len { break; }
                                                    let _ = udp_socket.send_to(&grpc_buf[5..5+len], peer).await;
                                                    let _ = grpc_buf.split_to(5 + len);
                                                }
                                            }
                                        }
                                        let _ = cleanup_tx.send(peer).await;
                                    });

                                    while let Some(data) = rx.recv().await {
                                        let mut init_buf = BytesMut::with_capacity(5 + data.len());
                                        init_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                        init_buf[1..5].copy_from_slice(&(data.len() as u32).to_be_bytes());
                                        init_buf.extend_from_slice(&data);
                                        let framed = init_buf.freeze();
                                        
                                        send_stream.reserve_capacity(framed.len());
                                        while send_stream.capacity() < framed.len() {
                                            if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                        }
                                        if send_stream.send_data(framed, false).is_err() { break; }
                                    }
                                    let _ = send_stream.send_data(Bytes::new(), true);
                                });
                                tx
                            });
                            let _ = tx.try_send(data);
                        }
                    }
                }
            });
        }
    }

    for (local_bind, route_table) in mapped_routes {
        let listener = match crate::net_utils::create_reuseport_listener(&local_bind) {
            Ok(l) => l, Err(e) => { error!("Failed to bind {}: {}", local_bind, e); continue; }
        };
        info!("🚀 Listener active on {} with {} SNI rules", local_bind, route_table.sni_rules.len());

        let cfg_clone = cfg.clone();

        let pool_clone = pool.clone();

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
                        if let Ok((mut local_tcp, peer)) = accept_res {
                            let _ = local_tcp.set_nodelay(true);
                            crate::net_utils::tune_socket_buffers(&local_tcp);
                            enable_tcp_keepalive(&local_tcp);
                            let c_id = counter_clone.fetch_add(1, Ordering::SeqCst);

                            let route_table = route_table.clone();
                            let pool_clone = pool_clone.clone();
                            let cfg_inner = cfg_clone.clone();


                            tokio::spawn(async move {
                                let mut extracted_sni = None;
                                let mut initial_buf = [0u8; 2048];
                                let mut initial_len = 0;
                                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                                    loop {
                                        if initial_len >= 2048 { break; }
                                        let n = match local_tcp.read(&mut initial_buf[initial_len..]).await {
                                            Ok(n) if n > 0 => n,
                                            _ => break,
                                        };
                                        initial_len += n;

                                        if initial_buf[0] != 0x16 { break; }
                                        if let Some(sni) = extract_sni(&initial_buf[..initial_len]) {
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
                                let initial_data = initial_buf[..initial_len].to_vec();

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

                                let mut final_send_stream = None;
                                let mut final_response = None;
                                let mut global_retries = 0;
                                let mut failed_snis = std::collections::HashSet::new();
                                
                                while global_retries < 5 {
                                    let mut ready_client = None;
                                    let mut retries = 0;
                                    while retries < 5 {
                                        let mut best_client = None;
                                        let mut best_slot = None;
                                        let mut best_remote = None;
                                        let mut lowest_latency = f64::MAX;
                                        let total_pool_size = pool_clone.len();
                                        
                                        for i in 0..total_pool_size {
                                            let (pool_slot, target_remote) = &pool_clone[i];
                                            
                                            if failed_snis.contains(&target_remote.sni) {
                                                continue;
                                            }
                                            
                                            let mut slot_guard = pool_slot.lock().await;
                                            
                                            if let Some(c) = &slot_guard.client {
                                                let mut c_clone = c.clone();
                                                if let Ok(_) = std::future::poll_fn(|cx| c_clone.poll_ready(cx)).await {
                                                    let mut penalty = 0.0;
                                                    if let Some(pref) = route_table.target_locations.get(&target_up) {
                                                        if target_remote.location != *pref {
                                                            penalty = 10000.0;
                                                        }
                                                    }
                                                    let score = slot_guard.ewma_latency + penalty;
                                                    if score < lowest_latency {
                                                        lowest_latency = score;
                                                        best_client = Some(c_clone);
                                                        best_slot = Some(pool_slot.clone());
                                                        best_remote = Some(target_remote.clone());
                                                    }
                                                } else {
                                                    slot_guard.client = None;
                                                }
                                            }
                                        }

                                        if let Some(c) = best_client {
                                            ready_client = Some((c, best_slot.unwrap(), best_remote.unwrap()));
                                            break;
                                        } else {
                                            retries += 1;
                                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                        }
                                    }
                                    
                                    if ready_client.is_none() {
                                        tracing::error!("[Conn #{}] All pool slots are disconnected! Connection dropped.", c_id);
                                        return;
                                    }
                                    
                                    let (mut c, pool_slot, target_remote) = ready_client.unwrap();

                                    let mut req_builder = Request::builder()
                                        .method(Method::POST)
                                        .uri(format!("https://{}{}", target_remote.sni, cfg_inner.hidden_path))
                                        .header("Host", target_remote.sni.clone())
                                        .header("x-tunnel-target", target_up.clone())
                                        .header("x-tunnel-secret", cfg_inner.secret.clone().unwrap_or_default());

                                    for (k, v) in get_random_headers() { req_builder = req_builder.header(k, v); }

                                    let start_time = tokio::time::Instant::now();
                                    match c.send_request(req_builder.body(()).unwrap(), false) {
                                        Ok((response_future, send_stream)) => {
                                            if let Ok(Ok(res)) = tokio::time::timeout(tokio::time::Duration::from_millis(5000), response_future).await {
                                                if res.status() == http::StatusCode::OK {
                                                    let latency = start_time.elapsed().as_millis() as f64;
                                                    let mut slot = pool_slot.lock().await;
                                                    slot.ewma_latency = (0.2 * latency) + (0.8 * slot.ewma_latency);
                                                    slot.consecutive_errors = 0;
                                                    
                                                    if !failed_snis.is_empty() {
                                                        tracing::info!("[Conn #{}] TCP Tunnel successfully fell back to alternate SNI: {}", c_id, target_remote.sni);
                                                    }
                                                    
                                                    final_send_stream = Some(send_stream);
                                                    final_response = Some(res);
                                                    break;
                                                }
                                                tracing::error!("[Conn #{}] Tunnel failed! Remote server {} returned HTTP {}", c_id, target_remote.sni, res.status());
                                                let mut slot = pool_slot.lock().await;
                                                slot.client = None; 
                                                slot.consecutive_errors = 0;
                                                failed_snis.insert(target_remote.sni.clone());
                                            } else {
                                                let mut slot = pool_slot.lock().await;
                                                slot.client = None;
                                                failed_snis.insert(target_remote.sni.clone());
                                            }
                                        }
                                        Err(_) => {
                                            let mut slot = pool_slot.lock().await;
                                            slot.consecutive_errors += 1;
                                            if slot.consecutive_errors >= 3 {
                                                slot.client = None; slot.consecutive_errors = 0;
                                                tracing::warn!("[Conn #{}] Drained node due to send errors.", c_id);
                                            }
                                            failed_snis.insert(target_remote.sni.clone());
                                        }
                                    }

                                    global_retries += 1;
                                }
                                
                                if final_send_stream.is_none() {
                                    tracing::error!("[Conn #{}] All tunnel attempts failed.", c_id);
                                    return;
                                }
                                
                                let mut send_stream = final_send_stream.unwrap();
                                let response = final_response.unwrap();

                                tokio::spawn(async move {
                                            if !initial_data.is_empty() {
                                                let mut init_buf = BytesMut::with_capacity(5 + initial_data.len());
                                                init_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                                init_buf[1..5].copy_from_slice(&(initial_data.len() as u32).to_be_bytes());
                                                init_buf.extend_from_slice(&initial_data);
                                                let framed = init_buf.freeze();
                                                
                                                send_stream.reserve_capacity(framed.len());
                                                while send_stream.capacity() < framed.len() {
                                                    if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await { break; }
                                                }
                                                if send_stream.send_data(framed, false).is_err() { return; }
                                            }

                                            let mut read_buf = BytesMut::with_capacity(65536 + 5);
                                            loop {
                                                read_buf.clear();
                                                read_buf.reserve(65536 + 5);
                                                read_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                                let n = match local_read.read_buf(&mut read_buf).await {
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
                                        let mut body = response.into_body();
                                        while let Some(Ok(mut data)) = body.data().await {
                                            let _ = body.flow_control().release_capacity(data.len());
                                            
                                            if grpc_buf.is_empty() {
                                                while data.len() >= 5 {
                                                    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                                                    if data.len() < 5 + len { break; }
                                                    if local_write.write_all(&data[5..5+len]).await.is_err() { return; }
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
                                                    if local_write.write_all(&grpc_buf[5..5+len]).await.is_err() { return; }
                                                    let _ = grpc_buf.split_to(5 + len);
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
