mod client;
mod config;
mod crypto;
mod fragment;
mod net_utils;
mod routing;
mod server;

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
#[tokio::main]
async fn main() {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());

    let initial_content = fs::read_to_string(&config_path).expect("Failed to read config");
    let initial_config: AppConfig = toml::from_str(&initial_content).unwrap();
    let log_level = initial_config.log_level.clone().unwrap_or_else(|| "info".to_string());

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
    fmt().with_env_filter(env_filter).with_thread_ids(true).with_target(false).init();

    info!("🚀 Starting Stealth Tunnel with SNI Routing & Hot-Reload");

    let mut last_modified = fs::metadata(&config_path).and_then(|m| m.modified()).unwrap();
    let mut current_cancel_token = CancellationToken::new();

    let token = current_cancel_token.clone();
    let cfg_initial = initial_config.clone();
    tokio::spawn(async move {
        if let Some(server_cfg) = cfg_initial.server {
            run_server(server_cfg, token).await;
        } else if let Some(client_cfg) = cfg_initial.client {
            run_client(client_cfg, token).await;
        } else {
            error!("❌ Invalid config: Neither [server] nor [client] block found.");
        }
    });

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Ok(meta) = fs::metadata(&config_path) {
            if let Ok(modified) = meta.modified() {
                if modified > last_modified {
                    last_modified = modified;
                    info!("🔄 Config file changed! Initiating Graceful Hot-Reload...");

                    if let Ok(new_content) = fs::read_to_string(&config_path) {
                        if let Ok(new_config) = toml::from_str::<AppConfig>(&new_content) {
                            current_cancel_token.cancel();
                            current_cancel_token = CancellationToken::new();
                            let token_new = current_cancel_token.clone();

                            tokio::spawn(async move {
                                if let Some(server_cfg) = new_config.server {
                                    run_server(server_cfg, token_new).await;
                                } else if let Some(client_cfg) = new_config.client {
                                    run_client(client_cfg, token_new).await;
                                }
                            });
                            info!("✅ Reload successful. New settings applied.");
                        } else {
                            error!("❌ TOML Parse Error. Ignoring changes...");
                        }
                    }
                }
            }
        }
    }
}
