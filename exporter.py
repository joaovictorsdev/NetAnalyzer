"""
exporter.py
===========
Módulo de exportação de capturas do NetAnalyzer.

Formatos suportados:
    PCAP — Formato padrão de captura de pacotes
           Compatível com Wireshark, tcpdump, Zeek, Snort
           Extensão: .pcap

    JSON — Dados estruturados da sessão de captura
           Inclui todos os pacotes decodificados + estatísticas
           Extensão: .json

    CSV  — Tabela simples de pacotes para análise em Excel/Python
           Extensão: .csv

O formato PCAP é o mais importante para portfólio:
demonstra integração com ferramentas da indústria (Wireshark).
"""

import json
import csv
import os
import struct
import time
from datetime import datetime


class Exporter:
    """
    Exporta dados de captura nos formatos PCAP, JSON e CSV.

    Args:
        diretorio_saida (str): Pasta onde os arquivos serão salvos
    """

    def __init__(self, diretorio_saida: str = "captures"):
        self.diretorio_saida = diretorio_saida
        os.makedirs(diretorio_saida, exist_ok=True)

        # Nome base com timestamp para identificação única
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.nome_base = f"netanalyzer_{ts}"

    def exportar_json(self, sessao, estatisticas: dict) -> str:
        """
        Exporta a sessão completa em JSON estruturado.

        Inclui metadados da sessão, estatísticas e lista
        dos últimos pacotes capturados.

        Returns:
            str: Caminho do arquivo gerado
        """
        caminho = os.path.join(self.diretorio_saida, f"{self.nome_base}.json")

        dados = {
            "meta": {
                "ferramenta": "NetAnalyzer",
                "versao": "1.0.0",
                "exportado_em": datetime.now().isoformat(),
            },
            "sessao": {
                "interface": sessao.interface,
                "filtro_bpf": sessao.filtro_bpf,
                "inicio": sessao.inicio,
                "fim": sessao.fim or datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "total_pacotes": sessao.total_pacotes,
                "total_bytes": sessao.total_bytes,
            },
            "estatisticas": estatisticas,
            "pacotes": [
                {
                    "timestamp": p.timestamp,
                    "protocolo": p.protocolo,
                    "ip_origem": p.ip_origem,
                    "ip_destino": p.ip_destino,
                    "porta_origem": p.porta_origem,
                    "porta_destino": p.porta_destino,
                    "tamanho_bytes": p.tamanho_bytes,
                    "flags_tcp": p.flags_tcp,
                    "dns_query": p.dns_query,
                    "http_method": p.http_method,
                    "http_host": p.http_host,
                    "http_path": p.http_path,
                    "resumo": p.resumo,
                }
                for p in sessao.pacotes_recentes
            ],
        }

        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, ensure_ascii=False, indent=2)

        return caminho

    def exportar_csv(self, sessao) -> str:
        """
        Exporta os pacotes capturados em formato CSV.

        Ideal para análise posterior com pandas, Excel ou scripts.

        Returns:
            str: Caminho do arquivo gerado
        """
        caminho = os.path.join(self.diretorio_saida, f"{self.nome_base}.csv")

        campos = [
            "timestamp", "protocolo", "ip_origem", "ip_destino",
            "porta_origem", "porta_destino", "tamanho_bytes",
            "flags_tcp", "dns_query", "http_method", "http_host",
            "http_path", "resumo",
        ]

        with open(caminho, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=campos)
            writer.writeheader()

            for p in sessao.pacotes_recentes:
                writer.writerow({
                    "timestamp": p.timestamp,
                    "protocolo": p.protocolo,
                    "ip_origem": p.ip_origem,
                    "ip_destino": p.ip_destino,
                    "porta_origem": p.porta_origem,
                    "porta_destino": p.porta_destino,
                    "tamanho_bytes": p.tamanho_bytes,
                    "flags_tcp": p.flags_tcp,
                    "dns_query": p.dns_query,
                    "http_method": p.http_method,
                    "http_host": p.http_host,
                    "http_path": p.http_path,
                    "resumo": p.resumo,
                })

        return caminho

    def exportar_pcap(self, pacotes_scapy: list) -> str:
        """
        Exporta pacotes Scapy no formato PCAP padrão da indústria.

        O arquivo gerado pode ser aberto diretamente no Wireshark,
        tcpdump, Zeek e outras ferramentas de análise de rede.

        Estrutura PCAP:
            Global Header (24 bytes) + N × (Packet Header + Packet Data)

        Args:
            pacotes_scapy (list): Lista de objetos Scapy (não PacoteInfo)

        Returns:
            str: Caminho do arquivo .pcap gerado
        """
        caminho = os.path.join(self.diretorio_saida, f"{self.nome_base}.pcap")

        with open(caminho, "wb") as f:
            # ── Global Header PCAP ─────────────────────────────────────────
            # magic_number: 0xa1b2c3d4 (identifica o arquivo como PCAP)
            # version_major/minor: 2.4
            # thiszone: GMT offset (0 = UTC)
            # sigfigs: precisão dos timestamps (0 = ignorado)
            # snaplen: tamanho máximo de captura (65535 bytes)
            # network: tipo de link (1 = Ethernet)
            f.write(struct.pack(
                "<IHHiIII",
                0xa1b2c3d4,  # magic number
                2, 4,         # versão 2.4
                0,            # timezone offset (UTC)
                0,            # sigfigs
                65535,        # snaplen
                1,            # link type: Ethernet
            ))

            # ── Packet Records ─────────────────────────────────────────────
            for pkt in pacotes_scapy:
                try:
                    dados_pkt = bytes(pkt)
                    ts = time.time()
                    ts_sec = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)

                    # Packet Header: ts_sec, ts_usec, incl_len, orig_len
                    f.write(struct.pack(
                        "<IIII",
                        ts_sec,
                        ts_usec,
                        len(dados_pkt),
                        len(dados_pkt),
                    ))

                    # Packet Data
                    f.write(dados_pkt)

                except Exception:
                    continue  # Ignora pacotes que não podem ser serializados

        return caminho

    def listar_capturas(self) -> list:
        """
        Lista todos os arquivos de captura salvos.

        Returns:
            list[dict]: Lista com nome, tamanho e data de cada arquivo
        """
        capturas = []

        for nome in sorted(os.listdir(self.diretorio_saida), reverse=True):
            caminho = os.path.join(self.diretorio_saida, nome)
            if os.path.isfile(caminho):
                tamanho = os.path.getsize(caminho)
                capturas.append({
                    "nome": nome,
                    "tamanho": self._formatar_bytes(tamanho),
                    "extensao": nome.rsplit(".", 1)[-1] if "." in nome else "",
                })

        return capturas

    @staticmethod
    def _formatar_bytes(n: int) -> str:
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"