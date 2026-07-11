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
    pub hidden_path: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub port_mappings: Option<Vec<String>>,
    pub camouflage_target: Option<String>,
    pub cloudflare_api_token: Option<String>,
    pub acme_domains: Option<Vec<String>>,
    pub secret: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteLocation {
    pub location: String,
    pub sni: Vec<String>,
    pub port_mappings: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub clean_ip: Vec<String>,
    pub remotes: Vec<RemoteLocation>,
    pub hidden_path: String,
    pub pool_size_per_node: Option<usize>,
    pub accept_udp: Option<String>,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub target_locations: HashMap<String, String>,
    pub default_upstream: Option<String>,
    pub sni_rules: HashMap<String, String>,
}
