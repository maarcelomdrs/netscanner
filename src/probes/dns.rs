use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub fn reverse_dns_lookup(ip: Ipv4Addr, gateway: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.set_read_timeout(Some(timeout));

    let octets = ip.octets();
    let ptr_labels = [
        octets[3].to_string(),
        octets[2].to_string(),
        octets[1].to_string(),
        octets[0].to_string(),
        "in-addr".to_string(),
        "arpa".to_string(),
    ];

    let mut packet = Vec::with_capacity(128);
    packet.extend_from_slice(&[
        0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    for label in &ptr_labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);

    let dest = SocketAddrV4::new(gateway, 53);
    let _ = socket.send_to(&packet, dest);

    let mut buf = [0u8; 1024];
    if let Ok((len, _)) = socket.recv_from(&mut buf) {
        if len > 12 {
            let ancount = u16::from_be_bytes([buf[6], buf[7]]);
            if ancount > 0 {
                let mut offset = 12;
                while offset < len && buf[offset] != 0 {
                    offset += 1 + buf[offset] as usize;
                }
                offset += 5;

                if offset + 12 <= len {
                    offset += 10;
                    let rdlength = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                    offset += 2;

                    if offset + rdlength <= len {
                        let mut name_parts = Vec::new();
                        let mut curr = offset;
                        let end = offset + rdlength;

                        while curr < end && buf[curr] != 0 {
                            let label_len = buf[curr] as usize;
                            curr += 1;
                            if curr + label_len <= end {
                                let label = String::from_utf8_lossy(&buf[curr..curr + label_len]);
                                name_parts.push(label.to_string());
                                curr += label_len;
                            } else {
                                break;
                            }
                        }

                        if !name_parts.is_empty() {
                            let fqdn = name_parts.join(".");
                            let sanitized = fqdn.trim_end_matches('.').to_string();
                            return Some(format!("DNS-PTR: {}", sanitized));
                        }
                    }
                }
            }
        }
    }
    None
}
