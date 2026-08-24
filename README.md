# netscanner

Scanner e ferramenta de diagnostico de rede para terminal, com interface TUI (Text User Interface) moderna, escrita em Rust.

## Descricao

O netscanner e uma aplicacao de linha de comando com interface interativa em modo texto (TUI), voltada para descoberta e diagnostico de redes locais. Ele reune em uma unica ferramenta funcionalidades que normalmente exigiriam varios utilitarios separados (como nmap, arp-scan, iw, dig), oferecendo visualizacao em tempo real diretamente no terminal.

## Funcionalidades

- Descoberta de hosts na rede local (varredura ARP/ICMP)
- Escaneamento de portas TCP/UDP abertas em hosts especificos
- Listagem de interfaces de rede (hardware) disponiveis
- Visualizacao e plotagem de sinais Wi-Fi no terminal
- Consultas DNS e mDNS (descoberta de dispositivos)
- Captura e inspecao de pacotes (TCP, UDP, ICMP, ARP)
- Troca dinamica de interface de rede durante a execucao
- Exportacao de dados coletados (clientes descobertos, portas escaneadas, logs de pacotes)
- Interface totalmente navegavel via teclado, sem necessidade de mouse

## Dependencias

### Fedora

sudo dnf install -y gcc pkgconf-pkg-config libpcap-devel openssl-devel

### Debian / Ubuntu

sudo apt update
sudo apt install -y build-essential pkg-config libpcap-dev libssl-dev

## Compilacao

git clone https://github.com/maarcelomdrs/netscanner.git
cd netscanner
cargo build --release

O binario final ficara disponivel em target/release/netscanner.

sudo chown root:USUARIO target/release/netscanner
sudo chmod u+s target/release/netscanner

## Exemplos de uso

sudo ./target/release/netscanner

sudo ./target/release/netscanner --frame-rate 30 --tick-rate 4

netscanner --version
netscanner --help

## Opcoes de linha de comando

| Opcao | Atalho | Descricao |
|---|---|---|
| --help | -h | Exibe a mensagem de ajuda |
| --version | -V | Exibe a versao da aplicacao |
| --tick-rate | | Define a taxa de atualizacao da logica interna |
| --frame-rate | | Define a taxa de renderizacao da interface |

## Licenca

Distribuido sob a licenca MIT.
