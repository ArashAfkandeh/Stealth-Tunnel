use crate::config::ServerConfig;
use crate::crypto::{decrypt_payload, derive_cipher, encrypt_payload};
use crate::net_utils::{enable_tcp_keepalive, frame_grpc, get_random_headers};

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use std::{fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::info;

// ==========================================
// 6. SERVER MODE
// ==========================================
pub async fn run_server(cfg: ServerConfig, cancel_token: CancellationToken) {
    let cipher = Arc::new(derive_cipher(&cfg.secret));
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(&cfg.tls_cert).unwrap())).map(|r| r.unwrap()).collect();
    let key = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(fs::File::open(&cfg.tls_key).unwrap())).next().unwrap().unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&cfg.bind_addr).await.unwrap();
    info!("🛡️ Server listening on {}", cfg.bind_addr);

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
                                let fallback_res = reqwest::get(&cfg_fallback).await.unwrap();
                                let response = http::Response::builder().status(fallback_res.status().as_u16()).body(()).unwrap();
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
