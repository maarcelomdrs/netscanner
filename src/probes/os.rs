pub fn guess_os_by_ttl(ttl: u8) -> &'static str {
    match ttl {
        1..=64 => "Linux / Android / iOS",
        65..=128 => "Windows",
        129..=255 => "Cisco / Network Appliance / Solaris",
        _ => "Desconhecido",
    }
}
