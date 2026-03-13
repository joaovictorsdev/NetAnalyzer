"""
protocol_analyzer.py
====================
Módulo de decodificação e análise de protocolos de rede.

Decodifica pacotes Scapy e extrai campos relevantes de cada protocolo:

    Camada 3 (Rede):
        IP  — endereços de origem/destino, TTL, tamanho
        ARP — requisições e respostas ARP

    Camada 4 (Transporte):
        TCP — portas, flags (SYN/ACK/FIN/RST/PSH), número de sequência
        UDP — portas, tamanho do payload

    Camada 4 (ICMP):
        ICMP — tipo (Echo Request/Reply, Destination Unreachable, etc.)

    Camada 7 (Aplicação):
        DNS  — queries e respostas (A, AAAA, MX, CNAME, PTR)
        HTTP — método, host, path, status code (quando não criptografado)

Referências:
    RFC 791 (IP), RFC 793 (TCP), RFC 768 (UDP), RFC 792 (ICMP), RFC 1035 (DNS)
"""

from datetime import datetime
from packet_capture import PacoteInfo


# Mapeamento de portas conhecidas → nome do serviço
PORTAS_CONHECIDAS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 5900: "VNC",
}

# Mapeamento de tipos ICMP → descrição legível
TIPOS_ICMP = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request (Ping)",
    11: "Time Exceeded (TTL)",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# Flags TCP — mapeamento de bits para nomes
FLAGS_TCP = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


class ProtocolAnalyzer:
    """
    Decodifica pacotes Scapy em objetos PacoteInfo estruturados.

    Cada método _analisar_XXX() trata um protocolo específico e
    preenche os campos relevantes do PacoteInfo.
    """

    def analisar(self, pkt) -> PacoteInfo:
        """
        Ponto de entrada principal — decodifica qualquer pacote Scapy.

        Args:
            pkt: Pacote Scapy capturado pelo sniff()

        Returns:
            PacoteInfo: Pacote decodificado com campos estruturados,
                        ou None se o pacote não puder ser processado
        """
        try:
            from scapy.all import ARP
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            info = PacoteInfo(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                protocolo="Outro",
                tamanho_bytes=len(pkt),
            )

            # ── Camada IP (presença de endereços de rede) ──────────────────
            if pkt.haslayer(IP):
                ip = pkt[IP]
                info.ip_origem = ip.src
                info.ip_destino = ip.dst
                info.ttl = ip.ttl

                # ── TCP ────────────────────────────────────────────────────
                if pkt.haslayer(TCP):
                    self._analisar_tcp(pkt, info)

                # ── UDP ────────────────────────────────────────────────────
                elif pkt.haslayer(UDP):
                    self._analisar_udp(pkt, info)

                # ── ICMP ───────────────────────────────────────────────────
                elif pkt.haslayer(ICMP):
                    self._analisar_icmp(pkt, info)

                else:
                    info.protocolo = "IP"

            # ── ARP (sem camada IP) ────────────────────────────────────────
            elif pkt.haslayer(ARP):
                self._analisar_arp(pkt, info)

            # Monta resumo legível do pacote
            info.resumo = self._montar_resumo(info)

            return info

        except Exception:
            return None

    # ──────────────────────────────────────────
    # Analisadores por protocolo
    # ──────────────────────────────────────────

    def _analisar_tcp(self, pkt, info: PacoteInfo):
        """Extrai campos TCP: portas, flags e detecta HTTP."""
        from scapy.layers.inet import TCP

        tcp = pkt[TCP]
        info.porta_origem = tcp.sport
        info.porta_destino = tcp.dport

        # Decodifica flags TCP do campo flags do Scapy
        flags_str = str(tcp.flags)
        flags_nomes = [FLAGS_TCP[f] for f in flags_str if f in FLAGS_TCP]
        info.flags_tcp = "+".join(flags_nomes) if flags_nomes else flags_str

        # Detecta HTTP em portas padrão (80, 8080, 8000, etc.)
        if tcp.dport in (80, 8080, 8000, 8888) or tcp.sport in (80, 8080, 8000, 8888):
            if self._tentar_http(pkt, info):
                return

        # Detecta DNS sobre TCP (zona transfers, respostas grandes)
        if tcp.dport == 53 or tcp.sport == 53:
            if self._tentar_dns(pkt, info):
                return

        info.protocolo = "TCP"

    def _analisar_udp(self, pkt, info: PacoteInfo):
        """Extrai campos UDP e detecta DNS."""
        from scapy.layers.inet import UDP

        udp = pkt[UDP]
        info.porta_origem = udp.sport
        info.porta_destino = udp.dport

        # DNS usa UDP porta 53 (maioria das queries)
        if udp.dport == 53 or udp.sport == 53:
            if self._tentar_dns(pkt, info):
                return

        # DHCP — portas 67/68
        if udp.dport in (67, 68) or udp.sport in (67, 68):
            info.protocolo = "DHCP"
            return

        info.protocolo = "UDP"

    def _analisar_icmp(self, pkt, info: PacoteInfo):
        """Extrai tipo e código ICMP."""
        from scapy.layers.inet import ICMP

        icmp = pkt[ICMP]
        tipo_nome = TIPOS_ICMP.get(icmp.type, f"Tipo {icmp.type}")
        info.protocolo = "ICMP"
        info.resumo = tipo_nome

    def _analisar_arp(self, pkt, info: PacoteInfo):
        """Extrai campos ARP (quem tem qual IP?)."""
        from scapy.all import ARP

        arp = pkt[ARP]
        info.protocolo = "ARP"
        info.ip_origem = arp.psrc
        info.ip_destino = arp.pdst

        # op=1 → ARP Request (Quem tem X?), op=2 → ARP Reply (Eu tenho X!)
        if arp.op == 1:
            info.resumo = f"Quem tem {arp.pdst}? (de {arp.psrc})"
        elif arp.op == 2:
            info.resumo = f"{arp.psrc} está em {arp.hwsrc}"

    def _tentar_dns(self, pkt, info: PacoteInfo) -> bool:
        """
        Tenta decodificar camada DNS do pacote.

        Returns:
            bool: True se o pacote é DNS e foi decodificado com sucesso
        """
        try:
            from scapy.layers.dns import DNS, DNSQR, DNSRR

            if not pkt.haslayer(DNS):
                return False

            dns = pkt[DNS]
            info.protocolo = "DNS"

            # Query DNS (qr=0 → pergunta, qr=1 → resposta)
            if dns.qr == 0 and dns.qdcount > 0 and pkt.haslayer(DNSQR):
                query = pkt[DNSQR]
                nome = query.qname.decode(errors="replace").rstrip(".")
                tipo_query = {1: "A", 28: "AAAA", 15: "MX", 5: "CNAME", 12: "PTR"}.get(
                    query.qtype, f"T{query.qtype}"
                )
                info.dns_query = f"{nome} ({tipo_query})"

            # Resposta DNS
            elif dns.qr == 1 and pkt.haslayer(DNSRR):
                rr = pkt[DNSRR]
                nome = rr.rrname.decode(errors="replace").rstrip(".")
                info.dns_query = f"→ {nome} = {rr.rdata}"

            return True

        except Exception:
            return False

    def _tentar_http(self, pkt, info: PacoteInfo) -> bool:
        """
        Tenta decodificar camada HTTP do pacote (apenas HTTP, não HTTPS).

        Returns:
            bool: True se é HTTP e foi decodificado com sucesso
        """
        try:
            from scapy.layers.http import HTTPRequest, HTTPResponse

            if pkt.haslayer(HTTPRequest):
                req = pkt[HTTPRequest]
                info.protocolo = "HTTP"
                info.http_method = req.Method.decode(errors="replace") if req.Method else "?"
                info.http_host = req.Host.decode(errors="replace") if req.Host else ""
                info.http_path = req.Path.decode(errors="replace") if req.Path else "/"
                return True

            elif pkt.haslayer(HTTPResponse):
                resp = pkt[HTTPResponse]
                info.protocolo = "HTTP"
                status = resp.Status_Code.decode(errors="replace") if resp.Status_Code else "?"
                info.http_method = f"Response {status}"
                return True

        except Exception:
            pass

        return False

    # ──────────────────────────────────────────
    # Resumo legível
    # ──────────────────────────────────────────

    def _montar_resumo(self, info: PacoteInfo) -> str:
        """
        Monta uma descrição legível do pacote para exibição no dashboard.
        """
        if info.resumo:
            return info.resumo  # Já foi definido pelo analisador específico

        partes = []

        if info.protocolo == "DNS" and info.dns_query:
            partes.append(f"DNS Query: {info.dns_query}")

        elif info.protocolo == "HTTP":
            partes.append(f"{info.http_method} {info.http_host}{info.http_path}")

        elif info.protocolo == "TCP":
            servico = PORTAS_CONHECIDAS.get(info.porta_destino, "")
            if servico:
                partes.append(f"→ {servico}")
            if info.flags_tcp:
                partes.append(f"[{info.flags_tcp}]")

        elif info.protocolo == "UDP":
            servico = PORTAS_CONHECIDAS.get(info.porta_destino, "")
            if servico:
                partes.append(f"→ {servico}")

        if info.ip_origem and info.ip_destino:
            partes.insert(0, f"{info.ip_origem} → {info.ip_destino}")

        return " | ".join(partes) if partes else info.protocolo