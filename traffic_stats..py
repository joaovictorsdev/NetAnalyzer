"""
traffic_stats.py
================
Módulo de estatísticas e análise de tráfego de rede.

Processa os dados da sessão de captura e calcula:
    - Taxa de pacotes por segundo (PPS)
    - Taxa de throughput em bytes/segundo
    - Top N IPs mais ativos (origem e destino)
    - Top N portas mais acessadas
    - Distribuição de protocolos (para gráfico de pizza)
    - Histórico de tráfego por janela de tempo (para gráfico de linha)
    - Detecção de anomalias simples (pico de tráfego, port scan)
"""

import time
from collections import deque
from datetime import datetime


class TrafficStats:
    """
    Calcula e mantém estatísticas de tráfego em tempo real.

    Usa uma janela deslizante de amostras temporais para calcular
    métricas de taxa (PPS, BPS) sem precisar armazenar todos os pacotes.
    """

    def __init__(self, janela_segundos: int = 60):
        """
        Args:
            janela_segundos (int): Tamanho da janela de histórico em segundos
                                   (usado para o gráfico de linha no dashboard)
        """
        self.janela_segundos = janela_segundos

        # Histórico de amostras: (timestamp, pacotes, bytes)
        # deque com maxlen descarta amostras antigas automaticamente
        self._historico = deque(maxlen=janela_segundos * 2)

        # Marca de tempo da última amostra
        self._ultima_amostra = time.time()
        self._pacotes_ultima_amostra = 0
        self._bytes_ultima_amostra = 0

    def calcular(self, sessao) -> dict:
        """
        Calcula todas as métricas da sessão atual.

        Args:
            sessao (SessaoCaptura): Sessão de captura com dados brutos

        Returns:
            dict: Dicionário com todas as métricas calculadas
        """
        agora = time.time()
        duracao = max(1, agora - time.mktime(
            datetime.strptime(sessao.inicio, "%d/%m/%Y %H:%M:%S").timetuple()
        ))

        # Taxa média geral
        pps_medio = sessao.total_pacotes / duracao
        bps_medio = sessao.total_bytes / duracao

        # Top 10 IPs origem
        top_origem = sorted(
            sessao.top_ips_origem.items(),
            key=lambda x: x[1], reverse=True
        )[:10]

        # Top 10 IPs destino
        top_destino = sorted(
            sessao.top_ips_destino.items(),
            key=lambda x: x[1], reverse=True
        )[:10]

        # Top 10 portas
        top_portas = sorted(
            sessao.top_portas.items(),
            key=lambda x: x[1], reverse=True
        )[:10]

        # Distribuição de protocolos (filtra zeros)
        distribuicao = {
            proto: count
            for proto, count in sessao.por_protocolo.items()
            if count > 0
        }

        # Tamanho médio de pacote
        tamanho_medio = (
            sessao.total_bytes / sessao.total_pacotes
            if sessao.total_pacotes > 0 else 0
        )

        return {
            "total_pacotes": sessao.total_pacotes,
            "total_bytes": sessao.total_bytes,
            "total_bytes_formatado": self._formatar_bytes(sessao.total_bytes),
            "duracao_segundos": int(duracao),
            "pps_medio": round(pps_medio, 1),
            "bps_medio": self._formatar_bytes(int(bps_medio)) + "/s",
            "tamanho_medio_pacote": round(tamanho_medio, 1),
            "top_ips_origem": top_origem,
            "top_ips_destino": top_destino,
            "top_portas": top_portas,
            "distribuicao_protocolos": distribuicao,
            "ativa": sessao.ativa,
        }

    def calcular_historico(self, sessao) -> dict:
        """
        Retorna série temporal para o gráfico de linha do dashboard.
        Agrupa pacotes recentes por segundo.

        Returns:
            dict: {"labels": [...], "pacotes": [...], "bytes": [...]}
        """
        # Agrupa os pacotes recentes por segundo
        grupos = {}  # segundo → (pacotes, bytes)

        for pkt in sessao.pacotes_recentes:
            # Extrai apenas HH:MM:SS (sem milissegundos) para agrupar
            segundo = pkt.timestamp[:8] if pkt.timestamp else "00:00:00"
            if segundo not in grupos:
                grupos[segundo] = {"pacotes": 0, "bytes": 0}
            grupos[segundo]["pacotes"] += 1
            grupos[segundo]["bytes"] += pkt.tamanho_bytes

        # Ordena por timestamp
        labels = sorted(grupos.keys())[-30:]  # Últimos 30 segundos
        pacotes = [grupos[l]["pacotes"] for l in labels]
        bytes_list = [grupos[l]["bytes"] for l in labels]

        return {
            "labels": labels,
            "pacotes": pacotes,
            "bytes": bytes_list,
        }

    def detectar_anomalias(self, sessao) -> list:
        """
        Detecção simples de anomalias de tráfego.

        Verifica:
            - Um único IP gerando mais de 30% do tráfego total
            - Muitas portas diferentes de um mesmo IP (possível port scan)
            - Alto volume de ICMP (possível ping flood)

        Returns:
            list[str]: Lista de alertas de anomalia detectados
        """
        alertas = []

        if sessao.total_pacotes < 100:
            return alertas  # Amostra muito pequena para análise

        # Verifica IP dominante (mais de 30% do tráfego)
        for ip, count in sessao.top_ips_origem.items():
            percentual = (count / sessao.total_pacotes) * 100
            if percentual > 30:
                alertas.append(
                    f"⚠️ IP {ip} gerou {percentual:.0f}% do tráfego total "
                    f"({count} pacotes) — possível flood ou varredura"
                )

        # Verifica volume alto de ICMP
        icmp_count = sessao.por_protocolo.get("ICMP", 0)
        icmp_percentual = (icmp_count / sessao.total_pacotes) * 100
        if icmp_percentual > 40:
            alertas.append(
                f"⚠️ Alto volume de ICMP: {icmp_percentual:.0f}% do tráfego "
                f"({icmp_count} pacotes) — possível ping flood"
            )

        return alertas

    @staticmethod
    def _formatar_bytes(n: int) -> str:
        """Converte bytes para formato legível (KB, MB, GB)."""
        for unidade in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {unidade}"
            n /= 1024
        return f"{n:.1f} PB"