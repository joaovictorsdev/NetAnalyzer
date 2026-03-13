# 📡 NetAnalyzer — Analisador de Pacotes de Rede

Analisador de pacotes de rede em tempo real com dashboard web.  
Captura e decodifica tráfego TCP, UDP, ICMP, DNS e HTTP com estatísticas ao vivo.

---

## ⚠️ Requisitos de permissão

A captura de pacotes requer acesso a sockets RAW — **execute sempre com sudo:**
```bash
sudo python main.py
sudo python dashboard.py
```

---

## 🔍 O que analisa

| Protocolo | O que extrai |
|-----------|-------------|
| **TCP** | Portas, flags (SYN/ACK/FIN/RST), serviço destino |
| **UDP** | Portas, payload |
| **ICMP** | Tipo (Ping, TTL Exceeded, Unreachable) |
| **DNS** | Queries e respostas (A, AAAA, MX, CNAME, PTR) |
| **HTTP** | Método, host, path, status code |
| **ARP** | Quem tem qual IP na rede local |

---

## 📁 Estrutura do projeto

```
netanalyzer/
├── main.py                  ← CLI (ponto de entrada)
├── packet_capture.py        ← Motor de captura (Scapy)
├── protocol_analyzer.py     ← Decodificação de protocolos
├── traffic_stats.py         ← Estatísticas e detecção de anomalias
├── geo_resolver.py          ← Geolocalização de IPs
├── exporter.py              ← Exportação PCAP / JSON / CSV
├── dashboard.py             ← Interface web Flask
└── requirements.txt
```

---

## 🚀 Instalação

```bash
pip install -r requirements.txt

# No Ubuntu, pode ser necessário:
sudo apt install python3-scapy
```

---

## 💻 Uso — CLI

```bash
# Captura em todas as interfaces até Ctrl+C
sudo python main.py

# Interface específica com filtro BPF
sudo python main.py -i eth0 -f "tcp port 80"

# Captura por 60 segundos e exporta
sudo python main.py -t 60 --exportar

# Apenas DNS
sudo python main.py -f "udp port 53"

# Listar interfaces disponíveis
sudo python main.py --listar
```

### Filtros BPF úteis

| Filtro | O que captura |
|--------|--------------|
| `tcp` | Apenas TCP |
| `udp port 53` | Apenas DNS |
| `icmp` | Apenas pings |
| `host 8.8.8.8` | Tráfego de/para um IP |
| `tcp port 80 or port 443` | HTTP e HTTPS |
| `not port 22` | Tudo exceto SSH |

---

## 🌐 Uso — Dashboard Web

```bash
sudo python dashboard.py
# Acesse: http://localhost:5001
```

**Funcionalidades do dashboard:**
- Gráfico de tráfego em tempo real (atualiza a cada 2s)
- Gráfico de distribuição de protocolos
- Top 10 IPs de origem e destino
- Top 10 portas mais acessadas
- Feed ao vivo dos últimos pacotes
- Alertas de anomalias (flood, port scan)
- Exportação em JSON via botão

---

## 📊 Exportação

Os arquivos são salvos em `./captures/`:

| Formato | Uso |
|---------|-----|
| **PCAP** | Abrir no Wireshark, tcpdump, Zeek |
| **JSON** | Análise programática, integração |
| **CSV** | Excel, pandas, LibreOffice |

---

## 🗺️ Roadmap

- [ ] Detecção de port scan em tempo real
- [ ] Suporte a HTTPS/TLS (SNI extraction)
- [ ] Exportação para Elasticsearch/Kibana
- [ ] Filtros dinâmicos no dashboard
- [ ] Alertas por email/Telegram

---

## 📚 Referências

- [Scapy Documentation](https://scapy.readthedocs.io)
- [RFC 793 — TCP](https://tools.ietf.org/html/rfc793)
- [RFC 1035 — DNS](https://tools.ietf.org/html/rfc1035)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)
- [Wireshark](https://www.wireshark.org)

---

*Desenvolvido para fins educacionais — Portfólio de Cibersegurança/Redes*