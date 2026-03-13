"""
packet_capture.py
=================
Motor principal de captura de pacotes do NetAnalyzer.

Usa a biblioteca Scapy para capturar pacotes diretamente da interface
de rede em modo promíscuo, passando cada pacote para os módulos de
análise em tempo real.

Requer execução com privilégios de superusuário (sudo/root) para
acessar sockets RAW de rede.

Referências:
    - RFC 791  (IP)
    - RFC 793  (TCP)
    - RFC 768  (UDP)
    - RFC 792  (ICMP)
    - RFC 1035 (DNS)
"""

import threading
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ─────────────────────────────────────────────
# Estruturas de dados
# ─────────────────────────────────────────────

@dataclass
class PacoteInfo:
    """Representa um pacote capturado e decodificado."""
    timestamp: str                    # Horário de captura
    protocolo: str                    # TCP, UDP, ICMP, DNS, HTTP, ARP...
    ip_origem: str = ""               # IP de origem
    ip_destino: str = ""              # IP de destino
    porta_origem: int = 0             # Porta de origem (TCP/UDP)
    porta_destino: int = 0            # Porta de destino (TCP/UDP)
    tamanho_bytes: int = 0            # Tamanho total do pacote
    flags_tcp: str = ""               # SYN, ACK, FIN, RST, PSH...
    dns_query: str = ""               # Nome consultado (se DNS)
    http_method: str = ""             # GET, POST... (se HTTP)
    http_host: str = ""               # Host HTTP
    http_path: str = ""               # Path da requisição HTTP
    ttl: int = 0                      # Time To Live do pacote IP
    resumo: str = ""                  # Descrição legível do pacote


@dataclass
class SessaoCaptura:
    """Estado e estatísticas de uma sessão de captura."""
    interface: str
    filtro_bpf: str
    inicio: str
    fim: str = ""
    ativa: bool = True

    # Contadores gerais
    total_pacotes: int = 0
    total_bytes: int = 0

    # Contagem por protocolo
    por_protocolo: dict = field(default_factory=lambda: {
        "TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0,
        "HTTP": 0, "ARP": 0, "Outro": 0
    })

    # Top IPs e portas (dicionários ip→contagem)
    top_ips_origem: dict = field(default_factory=dict)
    top_ips_destino: dict = field(default_factory=dict)
    top_portas: dict = field(default_factory=dict)

    # Lista dos últimos pacotes capturados (janela deslizante)
    pacotes_recentes: list = field(default_factory=list)
    MAX_RECENTES: int = 500           # Máximo de pacotes na memória


# ─────────────────────────────────────────────
# Motor de captura
# ─────────────────────────────────────────────

class PacketCapture:
    """
    Motor de captura de pacotes de rede usando Scapy.

    Captura pacotes em background via thread separada,
    analisa cada pacote e mantém estatísticas atualizadas
    em tempo real.

    Args:
        interface (str): Interface de rede (ex: "eth0", "wlan0")
                         Use "" ou "any" para capturar em todas
        filtro_bpf (str): Filtro BPF para restringir captura
                          Exemplos: "tcp", "udp port 53", "host 8.8.8.8"
        verbose (bool): Exibe pacotes no terminal em tempo real
        callback (Callable): Função chamada a cada pacote capturado
    """

    def __init__(
        self,
        interface: str = "",
        filtro_bpf: str = "",
        verbose: bool = True,
        callback: Optional[Callable] = None
    ):
        if not SCAPY_OK:
            raise ImportError(
                "Scapy não encontrado. Instale com: pip install scapy"
            )

        self.interface = interface or self._detectar_interface()
        self.filtro_bpf = filtro_bpf
        self.verbose = verbose
        self.callback_externo = callback

        # Sessão atual
        self.sessao: Optional[SessaoCaptura] = None

        # Controle de thread
        self._thread: Optional[threading.Thread] = None
        self._parar = threading.Event()
        self._lock = threading.Lock()

        # Módulos auxiliares (inicializados ao iniciar captura)
        from protocol_analyzer import ProtocolAnalyzer
        from traffic_stats import TrafficStats
        self._analyzer = ProtocolAnalyzer()
        self._stats = TrafficStats()

    # ──────────────────────────────────────────
    # Controle de captura
    # ──────────────────────────────────────────

    def iniciar(self) -> SessaoCaptura:
        """
        Inicia a captura de pacotes em uma thread de background.

        Returns:
            SessaoCaptura: Objeto de sessão com estatísticas em tempo real
        """
        self._parar.clear()

        self.sessao = SessaoCaptura(
            interface=self.interface,
            filtro_bpf=self.filtro_bpf,
            inicio=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        )

        self._log(f"\n{'='*55}")
        self._log(f"  NetAnalyzer — Captura de Pacotes")
        self._log(f"{'='*55}")
        self._log(f"  Interface : {self.interface}")
        self._log(f"  Filtro BPF: {self.filtro_bpf or '(nenhum — captura tudo)'}")
        self._log(f"  Início    : {self.sessao.inicio}")
        self._log(f"{'='*55}\n")
        self._log("  Pressione Ctrl+C para parar.\n")

        # Inicia captura em thread separada para não bloquear o programa
        self._thread = threading.Thread(
            target=self._thread_captura,
            daemon=True,
            name="NetAnalyzer-Capture"
        )
        self._thread.start()

        return self.sessao

    def parar(self):
        """Para a captura de pacotes e finaliza a sessão."""
        self._parar.set()

        if self.sessao:
            self.sessao.ativa = False
            self.sessao.fim = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        self._log("\n[*] Captura encerrada.")

    def esta_ativo(self) -> bool:
        """Retorna True se a captura está em andamento."""
        return self._thread is not None and self._thread.is_alive()

    # ──────────────────────────────────────────
    # Thread de captura
    # ──────────────────────────────────────────

    def _thread_captura(self):
        """Loop principal de captura — executa em thread separada."""
        try:
            sniff(
                iface=self.interface if self.interface != "any" else None,
                filter=self.filtro_bpf or None,
                prn=self._processar_pacote,       # Callback por pacote
                stop_filter=lambda p: self._parar.is_set(),
                store=False,                       # Não armazena na memória do Scapy
            )
        except PermissionError:
            self._log(
                "\n[ERRO] Permissão negada. Execute com sudo:\n"
                "  sudo python main.py\n"
            )
        except Exception as e:
            self._log(f"\n[ERRO] Falha na captura: {e}")

    def _processar_pacote(self, pacote_scapy):
        """
        Processa um pacote capturado pelo Scapy.

        Chamado automaticamente pelo sniff() para cada pacote.
        Analisa, atualiza estatísticas e notifica callbacks.
        """
        try:
            # Analisa o pacote e extrai campos estruturados
            info = self._analyzer.analisar(pacote_scapy)

            if not info:
                return

            with self._lock:
                if not self.sessao:
                    return

                # Atualiza contadores da sessão
                self.sessao.total_pacotes += 1
                self.sessao.total_bytes += info.tamanho_bytes

                # Contagem por protocolo
                proto = info.protocolo if info.protocolo in self.sessao.por_protocolo else "Outro"
                self.sessao.por_protocolo[proto] = self.sessao.por_protocolo.get(proto, 0) + 1

                # Top IPs
                if info.ip_origem:
                    self.sessao.top_ips_origem[info.ip_origem] = \
                        self.sessao.top_ips_origem.get(info.ip_origem, 0) + 1
                if info.ip_destino:
                    self.sessao.top_ips_destino[info.ip_destino] = \
                        self.sessao.top_ips_destino.get(info.ip_destino, 0) + 1

                # Top portas
                if info.porta_destino:
                    porta_key = f"{info.porta_destino}/{info.protocolo}"
                    self.sessao.top_portas[porta_key] = \
                        self.sessao.top_portas.get(porta_key, 0) + 1

                # Janela deslizante de pacotes recentes
                self.sessao.pacotes_recentes.append(info)
                if len(self.sessao.pacotes_recentes) > self.sessao.MAX_RECENTES:
                    self.sessao.pacotes_recentes.pop(0)

            # Exibe no terminal se verbose
            if self.verbose:
                self._log_pacote(info)

            # Notifica callback externo (ex: dashboard Flask)
            if self.callback_externo:
                self.callback_externo(info)

        except Exception:
            pass  # Pacotes malformados são ignorados silenciosamente

    # ──────────────────────────────────────────
    # Utilitários
    # ──────────────────────────────────────────

    def _detectar_interface(self) -> str:
        """
        Detecta automaticamente a interface de rede padrão.
        Prioriza interfaces físicas (eth0, wlan0) sobre loopback.
        """
        try:
            interfaces = get_if_list()
            # Prioridade: eth0 > enp* > wlan0 > wlp* > qualquer outra > lo
            for prefixo in ("eth", "enp", "ens", "wlan", "wlp"):
                for iface in interfaces:
                    if iface.startswith(prefixo):
                        return iface
            # Fallback: primeira interface que não seja loopback
            for iface in interfaces:
                if iface != "lo":
                    return iface
            return "lo"
        except Exception:
            return "eth0"

    def _log(self, msg: str):
        """Exibe mensagem no terminal se verbose=True."""
        if self.verbose:
            print(msg)

    def _log_pacote(self, info: PacoteInfo):
        """Formata e exibe um pacote no terminal."""
        cor = {
            "TCP":  "\033[36m",   # Ciano
            "UDP":  "\033[33m",   # Amarelo
            "ICMP": "\033[35m",   # Magenta
            "DNS":  "\033[32m",   # Verde
            "HTTP": "\033[34m",   # Azul
        }.get(info.protocolo, "\033[0m")
        reset = "\033[0m"

        linha = (
            f"{cor}[{info.timestamp}] {info.protocolo:<6}{reset} "
            f"{info.ip_origem or '?':>15} → {info.ip_destino or '?':<15} "
            f"{info.tamanho_bytes:>5}B"
        )

        if info.porta_destino:
            linha += f" :{info.porta_destino}"

        if info.dns_query:
            linha += f" DNS:{info.dns_query}"
        elif info.http_host:
            linha += f" HTTP:{info.http_method} {info.http_host}{info.http_path}"
        elif info.flags_tcp:
            linha += f" [{info.flags_tcp}]"

        print(linha)


# ──────────────────────────────────────────────
# Utilitário: listar interfaces disponíveis
# ──────────────────────────────────────────────

def listar_interfaces() -> list:
    """Retorna lista de interfaces de rede disponíveis no sistema."""
    if not SCAPY_OK:
        return []
    try:
        return get_if_list()
    except Exception:
        return []