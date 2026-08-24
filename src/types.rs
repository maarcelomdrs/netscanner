use pnet::datalink::MacAddr;
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostAudit {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub os_guess: String,
    pub hostname: Option<String>,
    pub open_ports: Vec<PortResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target_scope: String,
    pub local_ip: String,
    pub gateway_dns: String,
    pub scan_mode: String,
    pub scanned_ports_count: usize,
    pub execution_time_ms: u128,
    pub hosts: Vec<HostAudit>,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mac: MacAddr,
}

impl InterfaceInfo {
    pub fn network_address(&self) -> Ipv4Addr {
        let ip = self.ip.octets();
        let mask = self.netmask.octets();
        Ipv4Addr::new(
            ip[0] & mask[0],
            ip[1] & mask[1],
            ip[2] & mask[2],
            ip[3] & mask[3],
        )
    }

    pub fn gateway_guess(&self) -> Ipv4Addr {
        let net = self.network_address().octets();
        Ipv4Addr::new(net[0], net[1], net[2], 1)
    }

    pub fn usable_hosts(&self) -> Vec<Ipv4Addr> {
        let net_u32 = u32::from(self.network_address());
        let mask_u32 = u32::from(self.netmask);
        let broadcast_u32 = net_u32 | !mask_u32;

        let mut hosts = Vec::new();
        for ip_int in (net_u32 + 1)..broadcast_u32 {
            hosts.push(Ipv4Addr::from(ip_int));
        }
        hosts
    }
}
