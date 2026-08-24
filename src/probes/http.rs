use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

pub fn grab_http_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&socket_addr, timeout).ok()?;

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let probe = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NetScanner/1.0\r\nConnection: close\r\n\r\n",
        ip
    );
    let _ = stream.write_all(probe.as_bytes());

    let mut buffer = [0u8; 1024];
    match stream.read(&mut buffer) {
        Ok(bytes_read) if bytes_read > 0 => {
            let raw_banner = String::from_utf8_lossy(&buffer[..bytes_read]);

            for line in raw_banner.lines() {
                if line.to_lowercase().starts_with("server:") {
                    return Some(line.trim().to_string());
                }
            }

            let first_line = raw_banner.lines().next().unwrap_or("").trim();
            if !first_line.is_empty() {
                let sanitized: String = first_line.chars().take(60).collect();
                return Some(sanitized);
            }
            None
        }
        _ => None,
    }
}
