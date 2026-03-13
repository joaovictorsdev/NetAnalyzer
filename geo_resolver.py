"""
geo_resolver.py
===============
Módulo de geolocalização de endereços IP.

Resolve IPs para informações geográficas usando:
    1. ip-api.com (gratuito, sem chave, 45 req/min)
       Retorna: país, cidade, ISP, coordenadas, ASN

O módulo implementa cache em memória para evitar
requisições repetidas ao mesmo IP.

IPs privados (RFC 1918) são identificados localmente
sem consulta externa:
    10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
"""

import requests
import ipaddress
import time
from typing import Optional
from dataclasses import dataclass


@dataclass
class GeoInfo:
    """Informações geográficas de um endereço IP."""
    ip: str
    pais: str = ""
    pais_codigo: str = ""
    cidade: str = ""
    regiao: str = ""
    isp: str = ""
    lat: float = 0.0
    lon: float = 0.0
    asn: str = ""
    eh_privado: bool = False
    eh_valido: bool = True


class GeoResolver:
    """
    Resolve IPs para informações geográficas com cache em memória.

    Args:
        timeout (int): Timeout das requisições HTTP em segundos
        cache_max (int): Número máximo de IPs em cache
    """

    # API gratuita — sem necessidade de chave de API
    API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,lat,lon,as"

    # Faixas de IPs privados (RFC 1918 + loopback + link-local)
    REDES_PRIVADAS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),  # Link-local
        ipaddress.ip_network("::1/128"),           # IPv6 loopback
        ipaddress.ip_network("fc00::/7"),          # IPv6 privado
    ]

    def __init__(self, timeout: int = 5, cache_max: int = 1000):
        self.timeout = timeout
        self.cache_max = cache_max
        self._cache: dict = {}             # ip → GeoInfo
        self._ultimo_request = 0.0         # Controle de rate limiting
        self._delay_minimo = 1.5           # Segundos entre requests (45/min = ~1.3s)

    def resolver(self, ip: str) -> Optional[GeoInfo]:
        """
        Resolve um IP para informações geográficas.

        Verifica cache primeiro. IPs privados são resolvidos localmente.
        IPs públicos são consultados na API com rate limiting automático.

        Args:
            ip (str): Endereço IP a resolver

        Returns:
            GeoInfo: Informações geográficas, ou None se inválido
        """
        if not ip:
            return None

        # Retorna do cache se disponível
        if ip in self._cache:
            return self._cache[ip]

        # Verifica se é IP privado/loopback
        if self._eh_privado(ip):
            info = GeoInfo(
                ip=ip,
                pais="Rede Local",
                cidade="Privado",
                isp="LAN",
                eh_privado=True,
            )
            self._adicionar_cache(ip, info)
            return info

        # Consulta API para IPs públicos
        try:
            # Rate limiting: espera o tempo mínimo entre requests
            agora = time.time()
            tempo_desde_ultimo = agora - self._ultimo_request
            if tempo_desde_ultimo < self._delay_minimo:
                time.sleep(self._delay_minimo - tempo_desde_ultimo)

            resp = requests.get(
                self.API_URL.format(ip=ip),
                timeout=self.timeout
            )
            self._ultimo_request = time.time()

            if resp.status_code == 200:
                dados = resp.json()

                if dados.get("status") == "success":
                    info = GeoInfo(
                        ip=ip,
                        pais=dados.get("country", ""),
                        pais_codigo=dados.get("countryCode", "").lower(),
                        cidade=dados.get("city", ""),
                        regiao=dados.get("regionName", ""),
                        isp=dados.get("isp", ""),
                        lat=dados.get("lat", 0.0),
                        lon=dados.get("lon", 0.0),
                        asn=dados.get("as", ""),
                    )
                else:
                    # IP reservado ou não encontrado
                    info = GeoInfo(ip=ip, pais="Desconhecido", eh_valido=False)

                self._adicionar_cache(ip, info)
                return info

        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass

        # Fallback em caso de erro
        info = GeoInfo(ip=ip, pais="Erro na consulta", eh_valido=False)
        self._adicionar_cache(ip, info)
        return info

    def resolver_lote(self, ips: list) -> dict:
        """
        Resolve uma lista de IPs em lote.

        Args:
            ips (list): Lista de endereços IP

        Returns:
            dict: {ip: GeoInfo} para cada IP resolvido
        """
        resultado = {}
        for ip in ips:
            info = self.resolver(ip)
            if info:
                resultado[ip] = info
        return resultado

    def limpar_cache(self):
        """Limpa o cache de resoluções."""
        self._cache.clear()

    # ──────────────────────────────────────────
    # Utilitários privados
    # ──────────────────────────────────────────

    def _eh_privado(self, ip: str) -> bool:
        """
        Verifica se um IP pertence a uma faixa privada/reservada.

        Returns:
            bool: True se o IP é privado, loopback ou link-local
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in rede for rede in self.REDES_PRIVADAS)
        except ValueError:
            return False

    def _adicionar_cache(self, ip: str, info: GeoInfo):
        """Adiciona ao cache, removendo entradas antigas se necessário."""
        if len(self._cache) >= self.cache_max:
            # Remove a primeira entrada (mais antiga)
            primeira_chave = next(iter(self._cache))
            del self._cache[primeira_chave]
        self._cache[ip] = info