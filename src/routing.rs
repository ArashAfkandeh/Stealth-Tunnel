use crate::config::Route;
use std::{collections::HashMap, net::IpAddr};

// ==========================================
// 3. SMART PORT MAPPING & SNI ROUTING
// ==========================================
pub fn parse_port_mappings(mappings: &[String], location: Option<&str>, routes: &mut HashMap<String, Route>) {
    for m in mappings {
        let (left, right) = if let Some(idx) = m.find('=') {
            (&m[..idx], &m[idx+1..])
        } else if let Some(idx) = m.rfind(':') {
            (&m[..idx], &m[idx+1..])
        } else {
            continue;
        };
        let right = right.trim().to_string();
        let left_parts: Vec<&str> = left.trim().rsplitn(2, ':').collect();
        let port_str = left_parts[0];

        let mut bind_ip = "0.0.0.0".to_string();
        let mut sni_rule = None;

        if left_parts.len() == 2 {
            let host_or_ip = left_parts[1];
            if host_or_ip.parse::<IpAddr>().is_ok() || host_or_ip == "localhost" {
                bind_ip = host_or_ip.to_string();
            } else {
                sni_rule = Some(host_or_ip.to_string());
            }
        }

        let bind_addr = format!("{}:{}", bind_ip, port_str);
        let route = routes.entry(bind_addr).or_default();

        if let Some(sni) = sni_rule {
            route.sni_rules.insert(sni, right.clone());
        } else {
            route.default_upstream = Some(right.clone());
        }
        if let Some(loc) = location {
            route.target_locations.insert(right, loc.to_string());
        }
    }
}

// استخراج SNI از داخل پکت‌های خام TLS (بدون دستکاری پکت)
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let mut pos = 0;
    if buf.len() < 5 || buf[0] != 0x16 { return None; } // Not a Handshake
    pos += 5;
    if buf.len() < pos + 4 || buf[pos] != 0x01 { return None; } // Not ClientHello
    pos += 38; // Skip to Session ID
    if buf.len() <= pos { return None; }

    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if buf.len() <= pos + 1 { return None; }

    let cipher_suites_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
    pos += 2 + cipher_suites_len;
    if buf.len() <= pos { return None; }

    let comp_methods_len = buf[pos] as usize;
    pos += 1 + comp_methods_len;
    if buf.len() <= pos + 1 { return None; }

    let ext_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
    pos += 2;
    let ext_end = pos + ext_len;
    if buf.len() < ext_end { return None; }

    while pos + 4 <= ext_end {
        let ext_type = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
        let ext_size = ((buf[pos + 2] as usize) << 8) | (buf[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 { // SNI Extension
            if pos + 2 > ext_end { return None; }
            let sni_list_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
            let mut sni_pos = pos + 2;
            let list_end = sni_pos + sni_list_len;

            while sni_pos + 3 <= list_end {
                let name_type = buf[sni_pos];
                let name_len = ((buf[sni_pos + 1] as usize) << 8) | (buf[sni_pos + 2] as usize);
                sni_pos += 3;
                if name_type == 0x00 { // Hostname
                    if sni_pos + name_len <= list_end {
                        if let Ok(sni) = std::str::from_utf8(&buf[sni_pos..sni_pos + name_len]) {
                            return Some(sni.to_string());
                        }
                    }
                    break;
                }
                sni_pos += name_len;
            }
            break;
        }
        pos += ext_size;
    }
    None
}
