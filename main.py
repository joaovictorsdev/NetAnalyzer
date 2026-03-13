"""
main.py
=======
Interface CLI do NetAnalyzer — Analisador de Pacotes de Rede.

Uso básico:
    sudo python main.py

Uso avançado:
    sudo python main.py -i eth0 -f "tcp port 80" -t 60
    sudo python main.py -i wlan0 -f "udp port 53" --exportar

Opções:
    -i / --interface   Interface de rede (padrão: detecta automaticamente)
    -f / --filtro      Filtro BPF (ex: "tcp", "udp port 53", "host 8.8.8.8")
    -t / --tempo       Duração da captura em segundos (0 = até Ctrl+C)
    -n / --max-pacotes Parar após N pacotes capturados
    --exportar         Exporta captura em JSON e CSV ao finalizar
    --listar           Lista interfaces disponíveis e sai
    --quiet            Sem output de pacotes no terminal (só estatísticas)

Filtros BPF úteis:
    tcp                     → Apenas tráfego TCP
    udp port 53             → Apenas DNS
    host 8.8.8.8            → Tráfego de/para um IP específico
    tcp port 80 or port 443 → HTTP e HTTPS
    icmp                    → Apenas pings
    not port 22             → Tudo exceto SSH
"""

import argparse
import sys
import time
import signal


def parse_args():
    parser = argparse.ArgumentParser(
        prog="netanalyzer",
        description="NetAnalyzer — Analisador de Pacotes de Rede",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python main.py
  sudo python main.py -i eth0 -f "tcp port 80" -t 30
  sudo python main.py -f "udp port 53" --exportar
  sudo python main.py --listar
        """,
    )

    parser.add_argument("-i", "--interface", default="",
                        help="Interface de rede (ex: eth0, wlan0)")
    parser.add_argument("-f", "--filtro", default="",
                        help="Filtro BPF (ex: 'tcp', 'udp port 53')",
                        metavar="BPF")
    parser.add_argument("-t", "--tempo", type=int, default=0,
                        help="Duração em segundos (0 = até Ctrl+C)")
    parser.add_argument("-n", "--max-pacotes", type=int, default=0,
                        help="Parar após N pacotes")
    parser.add_argument("--exportar", action="store_true",
                        help="Exporta captura em JSON e CSV ao finalizar")
    parser.add_argument("--listar", action="store_true",
                        help="Lista interfaces disponíveis e sai")
    parser.add_argument("--quiet", action="store_true",
                        help="Sem output de pacotes (só estatísticas finais)")

    return parser.parse_args()


def imprimir_banner():
    print(r"""
  _   _      _    _                _
 | \ | | ___| |_ / \   _ __   __ _| |_   _ _______ _ __
 |  \| |/ _ \ __/ _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 | |\  |  __/ |_/ ___ \| | | | (_| | | |_| |/ /  __/ |
 |_| \_|\___|\__/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                                        |___/
   Analisador de Pacotes de Rede v1.0.0
   Requer execução com sudo/root
    """)


def imprimir_estatisticas(sessao, stats_calc):
    """Exibe resumo estatístico final da captura."""
    stats = stats_calc.calcular(sessao)
    anomalias = stats_calc.detectar_anomalias(sessao)

    print(f"\n\n{'='*55}")
    print("  ESTATÍSTICAS DA CAPTURA")
    print(f"{'='*55}")
    print(f"  Interface     : {sessao.interface}")
    print(f"  Filtro BPF    : {sessao.filtro_bpf or '(nenhum)'}")
    print(f"  Início        : {sessao.inicio}")
    print(f"  Fim           : {sessao.fim or 'em andamento'}")
    print(f"  Total pacotes : {stats['total_pacotes']:,}")
    print(f"  Total tráfego : {stats['total_bytes_formatado']}")
    print(f"  Média         : {stats['pps_medio']} pkt/s | {stats['bps_medio']}")
    print(f"  Tamanho médio : {stats['tamanho_medio_pacote']} bytes/pkt")

    print(f"\n  Distribuição por protocolo:")
    for proto, count in sorted(
        stats["distribuicao_protocolos"].items(),
        key=lambda x: x[1], reverse=True
    ):
        barra = "█" * min(20, int(count / max(stats["total_pacotes"], 1) * 20))
        pct = count / max(stats["total_pacotes"], 1) * 100
        print(f"    {proto:<8} {barra:<20} {count:>6} ({pct:.1f}%)")

    print(f"\n  Top 5 IPs origem:")
    for ip, count in stats["top_ips_origem"][:5]:
        print(f"    {ip:<20} {count:>6} pacotes")

    print(f"\n  Top 5 portas de destino:")
    for porta, count in stats["top_portas"][:5]:
        print(f"    {porta:<20} {count:>6} acessos")

    if anomalias:
        print(f"\n  ⚠️  Anomalias detectadas:")
        for a in anomalias:
            print(f"    {a}")

    print(f"{'='*55}\n")


def main():
    args = parse_args()

    # Lista interfaces e sai
    if args.listar:
        from packet_capture import listar_interfaces
        ifaces = listar_interfaces()
        print("\nInterfaces disponíveis:")
        for iface in ifaces:
            print(f"  • {iface}")
        print()
        sys.exit(0)

    if not args.quiet:
        imprimir_banner()

    from packet_capture import PacketCapture
    from traffic_stats import TrafficStats

    stats_calc = TrafficStats()

    captura = PacketCapture(
        interface=args.interface,
        filtro_bpf=args.filtro,
        verbose=not args.quiet,
    )

    sessao = captura.iniciar()

    # Configura Ctrl+C para parada graciosa
    def sinal_parar(sig, frame):
        print("\n\n[!] Encerrando captura...")
        captura.parar()
        imprimir_estatisticas(sessao, stats_calc)

        if args.exportar:
            from exporter import Exporter
            exp = Exporter()
            stats = stats_calc.calcular(sessao)
            json_path = exp.exportar_json(sessao, stats)
            csv_path  = exp.exportar_csv(sessao)
            print(f"  📋 JSON : {json_path}")
            print(f"  📊 CSV  : {csv_path}\n")

        sys.exit(0)

    signal.signal(signal.SIGINT, sinal_parar)

    try:
        # Loop principal: aguarda condição de parada
        inicio = time.time()
        while captura.esta_ativo():
            time.sleep(1)

            # Para após N segundos
            if args.tempo and (time.time() - inicio) >= args.tempo:
                print(f"\n[*] Tempo limite de {args.tempo}s atingido.")
                break

            # Para após N pacotes
            if args.max_pacotes and sessao.total_pacotes >= args.max_pacotes:
                print(f"\n[*] Limite de {args.max_pacotes} pacotes atingido.")
                break

            # Exibe contador a cada 10 segundos (modo quiet)
            if args.quiet and int(time.time() - inicio) % 10 == 0:
                print(f"  [{sessao.total_pacotes:>6} pkts | {sessao.total_bytes:>10} bytes]")

    finally:
        captura.parar()
        imprimir_estatisticas(sessao, stats_calc)

        if args.exportar:
            from exporter import Exporter
            exp = Exporter()
            stats = stats_calc.calcular(sessao)
            json_path = exp.exportar_json(sessao, stats)
            csv_path  = exp.exportar_csv(sessao)
            print(f"  📋 JSON : {json_path}")
            print(f"  📊 CSV  : {csv_path}\n")


if __name__ == "__main__":
    main()