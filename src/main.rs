mod acme;
mod client;
mod config;

mod net_utils;
mod prefixed_stream;
mod routing;
mod server;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use client::run_client;
use config::AppConfig;
use server::run_server;

use std::{fs, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

// ==========================================
// 7. HOT-RELOAD & ENTRY POINT
// ==========================================
use std::path::Path;

fn resolve_cert_path(path_str: &str, default_filename: &str) -> String {
    let p = path_str.trim();
    let p = if p.is_empty() { default_filename } else { p };
    let path = Path::new(p);
    
    if path.parent().map(|parent| parent.as_os_str().is_empty()).unwrap_or(true) {
        let exe_dir = std::env::current_exe()
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();
        
        let certs_dir = exe_dir.join("certs");
        if !certs_dir.exists() {
            let _ = std::fs::create_dir_all(&certs_dir);
        }
        return certs_dir.join(p).to_string_lossy().to_string();
    }
    
    p.to_string()
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());

    let initial_content = fs::read_to_string(&config_path).expect("Failed to read config");
    let mut initial_config: AppConfig = toml::from_str(&initial_content).unwrap();
    if let Some(ref mut server_cfg) = initial_config.server {
        server_cfg.tls_cert = resolve_cert_path(&server_cfg.tls_cert, "fullchain.pem");
        server_cfg.tls_key = resolve_cert_path(&server_cfg.tls_key, "privkey.pem");
    }
    let log_level = initial_config.log_level.clone().unwrap_or_else(|| "info".to_string());

    let filter_str = format!("h2=warn,rustls=warn,tokio_rustls=warn,GhostRPC={}", log_level);
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_str));
    fmt().with_env_filter(env_filter).with_thread_ids(true).with_target(false).init();

    info!("🚀 Starting GhostRPC with SNI Routing & Hot-Reload");

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    initial_content.hash(&mut hasher);
    let mut last_hash = hasher.finish();
    let mut current_cancel_token = CancellationToken::new();

    let token = current_cancel_token.clone();
    let cfg_initial = initial_config.clone();
    let config_path_main = config_path.clone();
    let _ = tokio::spawn(async move {
        if let Some(server_cfg) = cfg_initial.server {
            if server_cfg.cloudflare_api_token.is_some() {
                if crate::acme::needs_renewal(&server_cfg.tls_cert) {
                    if let Err(e) = crate::acme::provision_acme_cert(&server_cfg).await {
                        tracing::error!("❌ ACME Provisioning failed: {}", e);
                    }
                }
                
                let s_cfg = server_cfg.clone();
                let config_path_clone = config_path_main.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(86400)).await; // 24 hours
                        if crate::acme::needs_renewal(&s_cfg.tls_cert) {
                            tracing::info!("🔄 Certificate needs renewal. Starting ACME...");
                            if let Ok(_) = crate::acme::provision_acme_cert(&s_cfg).await {
                                // Trigger Hot-Reload by appending a comment to config
                                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&config_path_clone) {
                                    use std::io::Write;
                                    let _ = f.write_all(b"\n# ACME Auto-Renewed\n");
                                }
                            }
                        }
                    }
                });
            }
            run_server(server_cfg, token).await;
        } else if let Some(client_cfg) = cfg_initial.client {
            run_client(client_cfg, token).await;
        } else {
            error!("❌ Neither [server] nor [client] configuration found!");
        }
    });

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        if let Ok(new_content) = fs::read_to_string(&config_path) {
            let mut hasher = DefaultHasher::new();
            new_content.hash(&mut hasher);
            let new_hash = hasher.finish();
            if new_hash != last_hash {
                last_hash = new_hash;
                info!("🔄 Config file changed! Initiating Zero-Downtime Hot-Reload...");

                if let Ok(mut new_config) = toml::from_str::<AppConfig>(&new_content) {
                    if let Some(ref mut server_cfg) = new_config.server {
                        server_cfg.tls_cert = resolve_cert_path(&server_cfg.tls_cert, "fullchain.pem");
                        server_cfg.tls_key = resolve_cert_path(&server_cfg.tls_key, "privkey.pem");
                    }
                    let token_new = CancellationToken::new();
                    let token_new_clone = token_new.clone();

                    let _ = tokio::spawn(async move {
                        if let Some(server_cfg) = new_config.server {
                            if server_cfg.cloudflare_api_token.is_some() {
                                if crate::acme::needs_renewal(&server_cfg.tls_cert) {
                                    if let Err(e) = crate::acme::provision_acme_cert(&server_cfg).await {
                                        tracing::error!("❌ ACME Provisioning failed: {}", e);
                                    }
                                }
                            }
                            run_server(server_cfg, token_new_clone).await;
                        } else if let Some(client_cfg) = new_config.client {
                            run_client(client_cfg, token_new_clone).await;
                        } else {
                            error!("❌ Neither [server] nor [client] configuration found!");
                        }
                    });

                    // Wait 100ms for the new listener to bind and be ready via SO_REUSEPORT
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    // Stop the old listener (active connections remain alive)
                    current_cancel_token.cancel();
                    
                    current_cancel_token = token_new;
                    info!("✅ Reload successful. Traffic is now routing through the new settings.");
                } else {
                    error!("❌ TOML Parse Error. Ignoring changes...");
                }
            }
        }
    }
}
