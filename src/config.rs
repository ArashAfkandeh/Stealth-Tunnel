use serde::Deserialize;
use std::collections::HashMap;

// ==========================================
// 1. CONFIGURATION (TOML)
// ==========================================

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub mode: String,
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
    pub domain: String, // ادغام sni و host به یک کلید برای سادگی پشت کلودفلر
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub port_mappings: Vec<String>,
    pub remotes: Vec<RemoteNode>,
    pub hidden_path: String,
    pub secret: String,
    pub pool_size_per_node: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub default_upstream: Option<String>,
    pub sni_rules: HashMap<String, String>,
}
