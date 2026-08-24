use crate::probes::grab_banner;
use crate::types::PortResult;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

pub fn resolve_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        139 => "NetBIOS",
        443 => "HTTPS",
        445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        _ => "Unknown",
    }
}

pub fn scan_tcp_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<PortResult> {
    let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    if TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
        let banner = grab_banner(ip, port, timeout);
        Some(PortResult {
            port,
            service: resolve_service_name(port).to_string(),
            banner,
        })
    } else {
        None
    }
}
