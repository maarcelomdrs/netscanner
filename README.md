# netscanner

Ferramenta de auditoria, reconhecimento e varredura concorrente de rede de alta performance desenvolvida em Rust.

---

### Funcionalidades

- **Descoberta ARP:** Varredura rápida de camada 2 para mapeamento de hosts na rede local.
- **Port Scanning Concorrente:** Varredura assíncrona baseada em Tokio para alta vazão e baixo tempo de resposta.
- **Banner Grabbing & TLS:** Extração de cabeçalhos de serviço e inspeção de certificados TLS/HTTP.
- **Passive OS Fingerprinting:** Identificação heurística de sistemas operacionais via análise de TTL e TCP Window Size.

---

### Instalação & Compilação

Certifique-se de ter o **Rust** e o gerenciador `cargo` instalados no sistema:

```bash
# Clone o repositório
git clone https://github.com/maarcelomdrs/netscanner.git
cd netscanner

# Compile para binário otimizado
cargo build --release
```

---

### Como Usar

> **Nota:** Algumas operações de rede de baixo nível (como ARP scan em camada 2) podem exigir privilégios de administrador/root (`sudo`).

**1. Varredura rápida na sub-rede local:**
```bash
cargo run --release -- --range 192.168.1.0/24
```

**2. Varredura direcionada com detecção de banners:**
```bash
cargo run --release -- --target 192.168.1.1 --ports 21,22,80,443,8080 --banners
```

---

### Arquitetura

O projeto utiliza um pipeline assíncrono orientado a eventos para evitar bloqueios em operações de I/O de sockets de rede, garantindo que o despacho e o processamento de pacotes ocorram de forma concorrente e sem gargalos de CPU.

---

### Licença

Distribuído sob a licença MIT.
