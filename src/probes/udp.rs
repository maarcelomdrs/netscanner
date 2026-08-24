use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

pub fn run_udp_discovery(
    local_ip: Ipv4Addr,
    hostnames: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
    running: Arc<AtomicBool>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(150)));
    let _ = socket.set_broadcast(true);

    let ssdp_msg = "M-SEARCH * HTTP/1.1\r\n\
                    HOST: 239.255.255.250:1900\r\n\
                    MAN: \"ssdp:discover\"\r\n\
                    MX: 1\r\n\
                    ST: ssdp:all\r\n\r\n";
    let _ = socket.send_to(ssdp_msg.as_bytes(), "239.255.255.250:1900");

    let mdns_query: [u8; 46] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'_', b's',
        b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
        0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0c, 0x00,
        0x01,
    ];
    let _ = socket.send_to(&mdns_query, "224.0.0.251:5353");

    let mut buf = [0u8; 2048];
    while running.load(Ordering::Relaxed) {
        if let Ok((len, src)) = socket.recv_from(&mut buf) {
            if let IpAddr::V4(src_ipv4) = src.ip() {
                if src_ipv4 == local_ip {
                    continue;
                }

                let data_str = String::from_utf8_lossy(&buf[..len]);

                for line in data_str.lines() {
                    let lower = line.to_lowercase();
                    if lower.starts_with("server:") || lower.starts_with("location:") {
                        let val = line
                            .split_once(':')
                            .map(|x| x.1.trim())
                            .unwrap_or("")
                            .to_string();
                        if !val.is_empty() {
                            let mut map = hostnames.lock().unwrap();
                            map.insert(src_ipv4, val);
                        }
                    }
                }
            }
        }
    }
}
