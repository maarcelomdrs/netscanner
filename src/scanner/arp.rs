use pcap::Capture;
use pnet::datalink::{self, Channel, MacAddr};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DiscoveredHostInfo {
    pub mac: MacAddr,
    pub ttl: u8,
}

pub fn build_arp_request_packet(
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut buffer = [0u8; 42];

    let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..14]).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(source_mac);
    eth_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(&mut buffer[14..42]).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    buffer
}

pub fn run_arp_discovery(
    iface_name: &str,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    discovered: Arc<Mutex<HashMap<Ipv4Addr, DiscoveredHostInfo>>>,
) {
    let running = Arc::new(AtomicBool::new(true));
    let sniffer_iface = iface_name.to_string();
    let sniffer_discovered = Arc::clone(&discovered);
    let sniffer_running = Arc::clone(&running);

    let sniffer_handle = thread::spawn(move || {
        let mut cap = match Capture::from_device(sniffer_iface.as_str())
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        let _ = cap.filter("arp or ip", true);

        while sniffer_running.load(Ordering::Relaxed) {
            if let Ok(packet) = cap.next_packet() {
                let data = packet.data;
                if data.len() >= 42 {
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);

                    if ethertype == 0x0806 {
                        let opcode = u16::from_be_bytes([data[20], data[21]]);
                        if opcode == 2 {
                            let sender_mac = MacAddr::new(
                                data[22], data[23], data[24], data[25], data[26], data[27],
                            );
                            let sender_ip = Ipv4Addr::new(data[28], data[29], data[30], data[31]);

                            let mut disc = sniffer_discovered.lock().unwrap();
                            disc.entry(sender_ip).or_insert(DiscoveredHostInfo {
                                mac: sender_mac,
                                ttl: 64,
                            });
                        }
                    } else if ethertype == 0x0800 && data.len() >= 34 {
                        let src_ip = Ipv4Addr::new(data[26], data[27], data[28], data[29]);
                        let ttl = data[22];

                        let mut disc = sniffer_discovered.lock().unwrap();
                        if let Some(info) = disc.get_mut(&src_ip) {
                            info.ttl = ttl;
                        }
                    }
                }
            }
        }
    });

    let pnet_iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface_name)
        .expect("Falha ao recuperar interface de rede");

    let (mut tx, _) = match datalink::channel(&pnet_iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return,
    };

    for &target_ip in targets {
        let packet = build_arp_request_packet(source_mac, source_ip, target_ip);
        let _ = tx.send_to(&packet, None);
        thread::sleep(Duration::from_millis(2));
    }

    thread::sleep(Duration::from_millis(1500));
    running.store(false, Ordering::Relaxed);
    let _ = sniffer_handle.join();
}
