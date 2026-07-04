use serde::Deserialize;
use std::collections::HashMap;

// ==========================================
// 1. CONFIGURATION (TOML)
// ==========================================

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub log_level: Option<String>,
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub secret: String,
    pub hidden_path: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub reality_fallback_url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteNode {
    pub addr: String,
    pub sni: String,
    pub host: String,
    pub protocol: Option<String>, // "h2" or "quic"
}

fn default_pool_size() -> usize { 5 }

#[derive(Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub port_mappings: Vec<String>,
    pub remotes: Vec<RemoteNode>,
    pub hidden_path: String,
    pub secret: String,
    #[serde(default = "default_pool_size")]
    pub pool_size_per_node: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub default_upstream: Option<String>,
    pub sni_rules: HashMap<String, String>,
}
