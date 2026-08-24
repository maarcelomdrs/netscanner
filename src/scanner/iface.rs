use crate::types::InterfaceInfo;
use pnet::datalink::{self, MacAddr};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub fn get_interface(specified_name: Option<String>) -> Result<InterfaceInfo, String> {
    let pnet_interfaces = datalink::interfaces();

    for iface in pnet_interfaces {
        if let Some(ref target_name) = specified_name {
            if iface.name != *target_name {
                continue;
            }
        } else if iface.is_loopback() || !iface.is_up() || iface.mac.is_none() {
            continue;
        }

        let mac = match iface.mac {
            Some(m) if m != MacAddr::zero() => m,
            _ => continue,
        };

        for ip_network in iface.ips {
            if let (IpAddr::V4(ipv4), IpAddr::V4(mask)) = (ip_network.ip(), ip_network.mask()) {
                if ipv4.is_loopback() || ipv4.is_link_local() {
                    continue;
                }

                return Ok(InterfaceInfo {
                    name: iface.name,
                    ip: ipv4,
                    netmask: mask,
                    mac,
                });
            }
        }
    }

    match specified_name {
        Some(name) => Err(format!(
            "Interface '{}' não encontrada ou sem IPv4 válido.",
            name
        )),
        None => Err("Nenhuma interface física ativa com IPv4 encontrada.".to_string()),
    }
}

pub fn parse_target_range(
    target_str: &str,
    default_iface: &InterfaceInfo,
) -> Result<Vec<Ipv4Addr>, String> {
    if target_str.eq_ignore_ascii_case("local") || target_str.eq_ignore_ascii_case("auto") {
        return Ok(default_iface.usable_hosts());
    }

    // Suporte a CIDR: 192.168.2.0/24
    if target_str.contains('/') {
        let parts: Vec<&str> = target_str.split('/').collect();
        if parts.len() == 2 {
            let base_ip =
                Ipv4Addr::from_str(parts[0]).map_err(|e| format!("IP base inválido: {}", e))?;
            let prefix: u32 = parts[1].parse().map_err(|_| "Prefixo CIDR inválido")?;

            if prefix > 32 || prefix < 16 {
                return Err("Prefixo CIDR deve estar entre /16 e /32".to_string());
            }

            let mask_u32 = if prefix == 0 {
                0
            } else {
                !0u32 << (32 - prefix)
            };
            let net_u32 = u32::from(base_ip) & mask_u32;
            let broadcast_u32 = net_u32 | !mask_u32;

            let mut hosts = Vec::new();
            for ip_int in (net_u32 + 1)..broadcast_u32 {
                hosts.push(Ipv4Addr::from(ip_int));
            }
            return Ok(hosts);
        }
    }

    // Suporte a IP único: 192.168.2.105
    if let Ok(single_ip) = Ipv4Addr::from_str(target_str) {
        return Ok(vec![single_ip]);
    }

    Err(format!(
        "Formato de alvo inválido: '{}'. Use CIDR (192.168.2.0/24) ou 'local'",
        target_str
    ))
}
