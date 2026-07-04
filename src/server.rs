use crate::config::ServerConfig;
use crate::crypto::{decrypt_payload, derive_cipher, encrypt_payload};
use crate::net_utils::{enable_tcp_keepalive, frame_grpc, get_random_headers};

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use quinn::{ServerConfig as QuinnServerConfig, Endpoint};
use std::{fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::info;

pub async fn run_server(cfg: ServerConfig, cancel_token: CancellationToken) {
    let cipher = Arc::new(derive_cipher(&cfg.secret));
    
    // لود کردن Certificate ها
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(&cfg.tls_cert).unwrap())).map(|r| r.unwrap()).collect();
    let key_tcp = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(fs::File::open(&cfg.tls_key).unwrap())).next().unwrap().unwrap();
    let key_quic = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(fs::File::open(&cfg.tls_key).unwrap())).next().unwrap().unwrap();

    // ============================
    // 1. TCP Server (H2 Tunneling)
    // ============================
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), rustls::pki_types::PrivateKeyDer::Pkcs8(key_tcp))
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&cfg.bind_addr).await.unwrap();
    
    // ============================
    // 2. UDP Server (QUIC Tunneling)
    // ============================
    let mut quic_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key_quic))
        .unwrap();
    quic_crypto.alpn_protocols = vec![b"h3".to_vec()]; // تظاهر به HTTP/3 برای فرار از سیستم فیلترینگ
    
    let quic_config = QuinnServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(quic_crypto).unwrap()));
    let quic_endpoint = Endpoint::server(quic_config, cfg.bind_addr.parse().unwrap()).unwrap();

    info!("🛡️ TCP & QUIC (UDP) Server listening concurrently on {}", cfg.bind_addr);

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
                                    let mut payload = vec![0u8; len];
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
                                            let mut buf = [0u8; 8192];
                                            while let Ok(n) = target_read.read(&mut buf).await {
                                                if n == 0 { break; }
                                                let framed = frame_grpc(&encrypt_payload(&cipher_out, &buf[..n]));
                                                if send_stream.write_all(&framed).await.is_err() { break; }
                                            }
                                        });
                                        
                                        let mut buf = [0u8; 8192];
                                        let mut grpc_buf = BytesMut::new();
                                        while let Ok(Some(n)) = recv_stream.read(&mut buf).await {
                                            if n == 0 { break; }
                                            grpc_buf.extend_from_slice(&buf[..n]);
                                            while grpc_buf.len() >= 5 {
                                                let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                if grpc_buf.len() < 5 + len { break; }
                                                if let Ok(dec) = decrypt_payload(&cipher_in, &grpc_buf[5..5+len]) {
                                                    if target_write.write_all(&dec).await.is_err() { break; }
                                                }
                                                let _ = grpc_buf.split_to(5 + len);
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
                if let Ok((tcp, _peer)) = accept_res {
                    let _ = tcp.set_nodelay(true);
                    enable_tcp_keepalive(&tcp);

                    let acceptor = acceptor.clone();
                    let cfg_path = cfg.hidden_path.clone();
                    let cfg_fallback = cfg.reality_fallback_url.clone();
                    let cipher_in = cipher.clone();
                    let cipher_out = cipher.clone();

                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(tcp).await { Ok(s) => s, Err(_) => return };
                        let mut h2 = match h2::server::handshake(tls_stream).await { Ok(h) => h, Err(_) => return };

                        while let Some(Ok((req, mut respond))) = h2.accept().await {
                            if req.uri().path() != cfg_path {
                                let fallback_res = reqwest::get(&cfg_fallback).await;
                                let status = fallback_res.as_ref().map(|r| r.status().as_u16()).unwrap_or(404);
                                let response = http::Response::builder().status(status).body(()).unwrap();
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
                                        let mut buf = [0u8; 8192];
                                        while let Ok(n) = target_read.read(&mut buf).await {
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
                                            let _ = grpc_buf.split_to(5 + len);
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
