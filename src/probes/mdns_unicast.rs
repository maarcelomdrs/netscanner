use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub fn probe_mdns_unicast(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.set_read_timeout(Some(timeout));

    let query: [u8; 41] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, b'_', b'w',
        b'o', b'r', b'k', b's', b't', b'a', b't', b'i', b'o', b'n', 0x04, b'_', b't', b'c', b'p',
        0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0c, 0x00, 0x01,
    ];

    let dest = SocketAddrV4::new(ip, 5353);
    let _ = socket.send_to(&query, dest);

    let mut buf = [0u8; 1024];
    if let Ok((len, _)) = socket.recv_from(&mut buf) {
        if len > 12 {
            let data_str = String::from_utf8_lossy(&buf[12..len]);
            for part in data_str.split('\0') {
                let clean: String = part
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '-')
                    .collect();
                if clean.contains(".local") || clean.contains("._tcp") {
                    let name = clean.split('.').next().unwrap_or("").trim();
                    if name.len() >= 3 && !name.starts_with('_') {
                        return Some(format!("mDNS: {}", name));
                    }
                }
            }
        }
    }
    None
}
