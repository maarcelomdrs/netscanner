pub mod arp;
pub mod iface;
pub mod tcp;

use crate::oui::resolve_mac_vendor;
use crate::probes::{dns, mdns_unicast, netbios, os};
use crate::types::{HostAudit, PortResult};
use pnet::datalink::MacAddr;
use rayon::prelude::*;
use std::net::Ipv4Addr;
use std::time::Duration;

pub fn audit_host(
    ip: Ipv4Addr,
    mac: MacAddr,
    ttl: u8,
    gateway: Ipv4Addr,
    multicast_name: Option<String>,
    ports: &[u16],
    timeout: Duration,
) -> HostAudit {
    let vendor = resolve_mac_vendor(mac).to_string();
    let os_guess = os::guess_os_by_ttl(ttl).to_string();

    let resolved_hostname = multicast_name
        .or_else(|| dns::reverse_dns_lookup(ip, gateway, Duration::from_millis(250)))
        .or_else(|| mdns_unicast::probe_mdns_unicast(ip, Duration::from_millis(250)))
        .or_else(|| netbios::probe_netbios_name(ip, Duration::from_millis(250)));

    let open_ports: Vec<PortResult> = ports
        .par_iter()
        .filter_map(|&port| tcp::scan_tcp_port(ip, port, timeout))
        .collect();

    HostAudit {
        ip: ip.to_string(),
        mac: mac.to_string(),
        vendor,
        os_guess,
        hostname: resolved_hostname,
        open_ports,
    }
}
