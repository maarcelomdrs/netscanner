use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub fn probe_netbios_name(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.set_read_timeout(Some(timeout));

    let nbns_query: [u8; 48] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'C', b'K',
        b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
        b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', 0x00, 0x00,
        0x21, 0x00, 0x01,
    ];

    let dest = SocketAddrV4::new(ip, 137);
    let _ = socket.send_to(&nbns_query, dest);

    let mut buf = [0u8; 1024];
    if let Ok((len, _)) = socket.recv_from(&mut buf) {
        if len > 56 {
            let num_names = buf[56] as usize;
            let mut offset = 57;

            for _ in 0..num_names {
                if offset + 18 <= len {
                    let name_bytes = &buf[offset..offset + 15];
                    let name_type = buf[offset + 15];
                    let flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
                    let is_group = (flags & 0x8000) != 0;

                    if name_type == 0x00 && !is_group {
                        let name = String::from_utf8_lossy(name_bytes).trim().to_string();
                        if !name.is_empty() {
                            return Some(format!("NetBIOS: {}", name));
                        }
                    }
                    offset += 18;
                }
            }
        }
    }
    None
}
