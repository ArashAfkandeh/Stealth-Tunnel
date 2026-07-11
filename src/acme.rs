use crate::config::ServerConfig;
use rcgen::{CertificateParams, KeyPair};
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

async fn set_cloudflare_dns_record(zone_id: &str, api_token: &str, name: &str, content: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id);
    
    let payload = serde_json::json!({
        "type": "TXT",
        "name": name,
        "content": content,
        "ttl": 60
    });

    let res = client.post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if body["success"].as_bool() == Some(true) {
        let record_id = body["result"]["id"].as_str().unwrap_or("").to_string();
        Ok(record_id)
    } else {
        Err(format!("Cloudflare API error: {:?}", body["errors"]))
    }
}

async fn delete_cloudflare_dns_record(zone_id: &str, api_token: &str, record_id: &str) {
    let client = reqwest::Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id);
    
    let _ = client.delete(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await;
}

async fn get_cloudflare_zone_id(api_token: &str, domain: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let mut base_domain = domain.to_string();
    if base_domain.starts_with("*.") {
        base_domain = base_domain[2..].to_string();
    }
    
    let url = "https://api.cloudflare.com/client/v4/zones";
    let res = client.get(url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if body["success"].as_bool() != Some(true) {
        return Err(format!("Cloudflare API error: {:?}", body["errors"]));
    }
    
    let zones = body["result"].as_array().ok_or("No zones found")?;
    for zone in zones {
        let name = zone["name"].as_str().unwrap_or("");
        if base_domain.ends_with(name) {
            return Ok(zone["id"].as_str().unwrap().to_string());
        }
    }
    Err(format!("Zone not found for domain: {}", base_domain))
}

pub async fn provision_acme_cert(cfg: &ServerConfig) -> Result<(), String> {
    let domains = cfg.acme_domains.as_ref().ok_or("acme_domains missing")?;
    let cf_token = cfg.cloudflare_api_token.as_ref().ok_or("cloudflare_api_token missing")?;
    let email = format!("admin@{}", domains[0].replace("*.", ""));

    info!("Starting ACME DNS-01 provisioning for domains: {:?}", domains);
    let cf_zone = get_cloudflare_zone_id(cf_token, &domains[0]).await?;

    let new_account = instant_acme::NewAccount {
        contact: &[&format!("mailto:{}", email)],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, _creds) = instant_acme::Account::create(&new_account, instant_acme::LetsEncrypt::Production.url(), None).await.map_err(|e| e.to_string())?;
    
    let identifiers: Vec<instant_acme::Identifier> = domains.iter().map(|d| instant_acme::Identifier::Dns(d.clone())).collect();
    let new_order = instant_acme::NewOrder { identifiers: &identifiers };
    let mut order = account.new_order(&new_order).await.map_err(|e| e.to_string())?;
    
    let authorizations = order.authorizations().await.map_err(|e| e.to_string())?;
    
    let mut dns_records = Vec::new();

    for auth in &authorizations {
        let challenge = auth.challenges.iter().find(|c| c.r#type == instant_acme::ChallengeType::Dns01).ok_or("No DNS-01 challenge found")?;
        let key_auth = order.key_authorization(challenge);
        
        let key_auth_str = key_auth.as_str();
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(key_auth_str.as_bytes());
        use base64::Engine;
        let txt_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

        let domain = match &auth.identifier {
            instant_acme::Identifier::Dns(d) => d,
        };
        let record_name = format!("_acme-challenge.{}", domain.replace("*.", ""));
        
        info!("Setting DNS record for {}...", domain);
        let record_id = set_cloudflare_dns_record(&cf_zone, cf_token, &record_name, &txt_value).await?;
        dns_records.push(record_id);
    }

    info!("Waiting 30 seconds for DNS propagation...");
    sleep(Duration::from_secs(30)).await;

    for auth in &authorizations {
        let challenge = auth.challenges.iter().find(|c| c.r#type == instant_acme::ChallengeType::Dns01).unwrap();
        order.set_challenge_ready(&challenge.url).await.map_err(|e| e.to_string())?;
    }

    loop {
        let state = order.state();
        if let instant_acme::OrderStatus::Ready | instant_acme::OrderStatus::Invalid | instant_acme::OrderStatus::Valid = state.status {
            break;
        }
        sleep(Duration::from_secs(3)).await;
        order.refresh().await.map_err(|e| e.to_string())?;
    }

    // Cleanup DNS records
    for rec_id in dns_records {
        delete_cloudflare_dns_record(&cf_zone, cf_token, &rec_id).await;
    }

    if order.state().status == instant_acme::OrderStatus::Invalid {
        return Err("ACME Order failed".to_string());
    }

    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(domains.clone()).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key_pair).map_err(|e| e.to_string())?;

    order.finalize(csr.der()).await.map_err(|e| e.to_string())?;

    loop {
        if order.state().status == instant_acme::OrderStatus::Valid { break; }
        sleep(Duration::from_secs(3)).await;
        order.refresh().await.map_err(|e| e.to_string())?;
    }

    let cert_chain = order.certificate().await.map_err(|e| e.to_string())?.unwrap_or_default();
    
    std::fs::write(&cfg.tls_cert, cert_chain).map_err(|e| e.to_string())?;
    std::fs::write(&cfg.tls_key, key_pair.serialize_pem()).map_err(|e| e.to_string())?;
    
    info!("✅ ACME Certificate successfully provisioned and saved to {} and {}", cfg.tls_cert, cfg.tls_key);
    Ok(())
}

pub fn needs_renewal(cert_path: &str) -> bool {
    let _cert_data = match std::fs::read(cert_path) {
        Ok(d) => d,
        Err(_) => return true,
    };
    // A simple check: if file is older than 60 days, renew.
    if let Ok(metadata) = std::fs::metadata(cert_path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() > 60 * 24 * 3600 {
                    return true;
                }
            }
        }
    }
    false
}
