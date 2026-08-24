mod oui;
mod probes;
mod scanner;
mod types;

use clap::Parser;
use colored::*;
use comfy_table::{Cell, CellAlignment, Color, ContentArrangement, Table};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use types::{HostAudit, ScanReport};

const DEFAULT_COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443,
];

#[derive(Parser, Debug)]
#[command(
    name = "netscanner",
    author,
    version,
    about = "Auditoria de Rede e Scanner TCP Concorrente"
)]
struct Cli {
    #[arg(
        short = 'i',
        long,
        help = "Nome da interface de rede (ex: enp6s0, wlan0)"
    )]
    interface: Option<String>,

    #[arg(
        short = 't',
        long,
        help = "Alvo da varredura: 'local', IP único (ex: 192.168.2.1) ou CIDR (ex: 192.168.2.0/24)",
        default_value = "local"
    )]
    target: String,

    #[arg(
        short = 'p',
        long,
        help = "Portas a escanear (ex: '80,443', '1-1024' ou 'top')",
        default_value = "top"
    )]
    ports: String,

    #[arg(
        short = 'T',
        long,
        help = "Timeout de conexão em milissegundos",
        default_value_t = 600
    )]
    timeout: u64,

    #[arg(short = 'o', long, help = "Salvar relatório em arquivo JSON")]
    output: Option<String>,
}

fn parse_port_range(input: &str) -> Result<Vec<u16>, String> {
    if input.to_lowercase() == "top" {
        return Ok(DEFAULT_COMMON_PORTS.to_vec());
    }

    let mut ports = HashSet::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                return Err(format!("Intervalo de portas inválido: {}", part));
            }
            let start: u16 = bounds[0]
                .trim()
                .parse()
                .map_err(|_| format!("Porta inicial inválida: {}", bounds[0]))?;
            let end: u16 = bounds[1]
                .trim()
                .parse()
                .map_err(|_| format!("Porta final inválida: {}", bounds[1]))?;

            if start > end {
                return Err(format!("Intervalo inválido: {} > {}", start, end));
            }

            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("Porta inválida: {}", part))?;
            ports.insert(p);
        }
    }

    let mut sorted: Vec<u16> = ports.into_iter().collect();
    sorted.sort_unstable();
    Ok(sorted)
}

fn render_results_table(hosts: &[HostAudit], duration: Duration) {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("IP / Hostname").set_alignment(CellAlignment::Left),
            Cell::new("MAC Address").set_alignment(CellAlignment::Left),
            Cell::new("Fabricante (OUI)").set_alignment(CellAlignment::Left),
            Cell::new("SO Estimado").set_alignment(CellAlignment::Left),
            Cell::new("Portas / Banners Identificados").set_alignment(CellAlignment::Left),
        ]);

    for host in hosts {
        let host_name_display = match &host.hostname {
            Some(name) => format!("{}\n({})", host.ip, name),
            None => host.ip.clone(),
        };

        let ports_display = if host.open_ports.is_empty() {
            "Sem portas abertas".to_string()
        } else {
            host.open_ports
                .iter()
                .map(|p| {
                    let banner = match &p.banner {
                        Some(b) => format!(" [{}]", b),
                        None => "".to_string(),
                    };
                    format!("{}/TCP - {}{}", p.port, p.service, banner)
                })
                .collect::<Vec<String>>()
                .join("\n")
        };

        table.add_row(vec![
            Cell::new(host_name_display).fg(Color::Green),
            Cell::new(&host.mac).fg(Color::Yellow),
            Cell::new(&host.vendor).fg(Color::Magenta),
            Cell::new(&host.os_guess).fg(Color::Cyan),
            Cell::new(ports_display).fg(Color::White),
        ]);
    }

    println!("\n{}", table);
    println!(
        "[*] Auditoria finalizada em {:.2}s. Total de {} hosts mapeados.",
        duration.as_secs_f64(),
        hosts.len().to_string().bold().green()
    );
}

fn main() {
    let cli = Cli::parse();

    let target_ports = match parse_port_range(&cli.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {}", "[!] Erro nas portas".bold().red(), e);
            return;
        }
    };

    let scan_timeout = Duration::from_millis(cli.timeout);

    println!(
        "{}",
        "==================================================".cyan()
    );
    println!(
        "{}",
        "  NetScanner - Advanced Recon & Network Auditor   "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "==================================================\n".cyan()
    );

    let iface = match scanner::iface::get_interface(cli.interface) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{}: {}", "[!] Erro de Interface".bold().red(), e);
            return;
        }
    };

    let targets = match scanner::iface::parse_target_range(&cli.target, &iface) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}: {}", "[!] Erro no Alvo".bold().red(), e);
            return;
        }
    };

    let local_vendor = oui::resolve_mac_vendor(iface.mac);
    let gateway = iface.gateway_guess();

    println!("{}", "[+] Parâmetros de Auditoria:".bold().green());
    println!("    Interface:    {}", iface.name.bold().yellow());
    println!(
        "    MAC Local:    {} ({})",
        iface.mac.to_string().bold().yellow(),
        local_vendor.magenta()
    );
    println!("    IP Local:     {}", iface.ip.to_string().cyan());
    println!("    Gateway DNS:  {}", gateway.to_string().cyan());
    println!(
        "    Alvo Scope:   {} ({} hosts)",
        cli.target.bold().yellow(),
        targets.len().to_string().bold()
    );
    println!(
        "    Portas:       {} selecionada(s)",
        target_ports.len().to_string().bold().yellow()
    );
    println!(
        "    Timeout TCP:  {} ms",
        cli.timeout.to_string().bold().yellow()
    );

    println!(
        "\n[*] Fase 1: Descoberta Ativa (ARP + Multicast UDP) em {} hosts...",
        targets.len().to_string().bold().cyan()
    );

    let discovered_hosts = Arc::new(Mutex::new(HashMap::new()));
    let discovered_names = Arc::new(Mutex::new(HashMap::new()));
    let running_udp = Arc::new(AtomicBool::new(true));

    let udp_names = Arc::clone(&discovered_names);
    let udp_running = Arc::clone(&running_udp);
    let udp_local_ip = iface.ip;
    let udp_handle = thread::spawn(move || {
        probes::udp::run_udp_discovery(udp_local_ip, udp_names, udp_running);
    });

    scanner::arp::run_arp_discovery(
        &iface.name,
        iface.mac,
        iface.ip,
        &targets,
        Arc::clone(&discovered_hosts),
    );

    running_udp.store(false, Ordering::Relaxed);
    let _ = udp_handle.join();

    let hosts_map = discovered_hosts.lock().unwrap().clone();
    let names_map = discovered_names.lock().unwrap().clone();
    let hosts_vec: Vec<(Ipv4Addr, scanner::arp::DiscoveredHostInfo)> =
        hosts_map.into_iter().collect();

    println!(
        "\n[*] Fase 2: Auditoria Concorrente (Reverse DNS, mDNS, NetBIOS & TCP) em {} host(s)...",
        hosts_vec.len().to_string().bold().cyan()
    );

    let start_time = Instant::now();

    let mut audited_hosts: Vec<HostAudit> = hosts_vec
        .par_iter()
        .map(|(host_ip, host_info)| {
            let hostname = names_map.get(host_ip).cloned();
            scanner::audit_host(
                *host_ip,
                host_info.mac,
                host_info.ttl,
                gateway,
                hostname,
                &target_ports,
                scan_timeout,
            )
        })
        .collect();

    let elapsed = start_time.elapsed();
    audited_hosts.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED));

    render_results_table(&audited_hosts, elapsed);

    if let Some(ref path) = cli.output {
        let report = ScanReport {
            target_scope: cli.target.clone(),
            local_ip: iface.ip.to_string(),
            gateway_dns: gateway.to_string(),
            scan_mode: "Concurrent Stealth/Banner Recon".to_string(),
            scanned_ports_count: target_ports.len(),
            execution_time_ms: elapsed.as_millis(),
            hosts: audited_hosts,
        };

        match File::create(path) {
            Ok(file) => {
                if let Err(e) = serde_json::to_writer_pretty(file, &report) {
                    eprintln!("{}: {}", "[!] Falha ao serializar JSON".bold().red(), e);
                } else {
                    println!(
                        "\n{}",
                        format!("[+] Relatório estruturado salvo com sucesso em '{}'", path)
                            .bold()
                            .green()
                    );
                }
            }
            Err(e) => eprintln!("{}: {}", "[!] Falha ao criar arquivo".bold().red(), e),
        }
    }

    println!("{}", "\n[*] Processo concluído.\n".bold().cyan());
}
