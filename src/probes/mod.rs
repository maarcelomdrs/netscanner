pub mod dns;
pub mod http;
pub mod mdns_unicast;
pub mod netbios;
pub mod os;
pub mod tls;
pub mod udp;

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

pub fn grab_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).ok()?;

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if port == 443 || port == 8443 {
        if let Some(cert_info) = tls::probe_tls_certificate(stream, &ip.to_string()) {
            return Some(cert_info);
        }
        return None;
    }

    if port == 80 || port == 8080 || port == 8000 {
        return http::grab_http_banner(ip, port, timeout);
    }

    // Leitura passiva de banner de serviços interativos (SSH, FTP, SMTP, Telnet)
    let mut buffer = [0u8; 1024];
    match stream.read(&mut buffer) {
        Ok(bytes_read) if bytes_read > 0 => {
            let raw = String::from_utf8_lossy(&buffer[..bytes_read]);
            let first_line = raw.lines().next().unwrap_or("").trim();
            if !first_line.is_empty() {
                let sanitized: String = first_line.chars().take(60).collect();
                return Some(sanitized);
            }
            None
        }
        _ => None,
    }
}
