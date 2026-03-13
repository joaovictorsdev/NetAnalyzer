"""
dashboard.py
============
Dashboard web do NetAnalyzer — Interface Flask com atualização em tempo real.

Funcionalidades:
    - Iniciar/parar captura de pacotes via navegador
    - Gráfico de tráfego ao vivo (atualiza a cada 2 segundos)
    - Distribuição de protocolos em tempo real
    - Top IPs e portas mais ativas
    - Feed ao vivo dos últimos pacotes capturados
    - Exportar captura em JSON ou CSV

Rotas:
    GET  /                  → Dashboard principal
    POST /api/captura/iniciar → Inicia captura
    POST /api/captura/parar   → Para captura
    GET  /api/stats           → Estatísticas em tempo real (JSON)
    GET  /api/pacotes         → Últimos pacotes (JSON)
    POST /api/exportar        → Exporta captura
    GET  /api/interfaces      → Lista interfaces disponíveis

Como executar:
    sudo python dashboard.py
    Acesse: http://localhost:5001
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import threading
import os
import json

app = Flask(__name__)
app.secret_key = "netanalyzer-dev-2024"

# Estado global da captura
_captura = None          # Instância de PacketCapture
_sessao = None           # Instância de SessaoCaptura
_stats_calc = None       # Instância de TrafficStats
_lock = threading.Lock()

CAPTURES_DIR = "captures"
os.makedirs(CAPTURES_DIR, exist_ok=True)


# ─────────────────────────────────────────────
# Template HTML do Dashboard
# ─────────────────────────────────────────────

TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetAnalyzer Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0f1e; color: #e2e8f0; }

  nav { background: #0f172a; border-bottom: 1px solid #1e3a5f; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }
  nav h1 { font-size: 1.3rem; color: #38bdf8; }
  .live-dot { width: 10px; height: 10px; border-radius: 50%; background: #ef4444; margin-left: auto; }
  .live-dot.active { background: #22c55e; animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  .container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }

  /* Controles */
  .controls { background: #0f172a; border: 1px solid #1e3a5f; border-radius: 12px; padding: 1.2rem; margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: flex-end; flex-wrap: wrap; }
  .form-group { display: flex; flex-direction: column; gap: 0.3rem; min-width: 140px; }
  label { font-size: 0.78rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
  select, input[type=text] { background: #0a0f1e; border: 1px solid #1e3a5f; color: #e2e8f0; padding: 0.5rem 0.7rem; border-radius: 6px; font-size: 0.9rem; }
  .btn { padding: 0.55rem 1.2rem; border-radius: 6px; border: none; cursor: pointer; font-size: 0.9rem; font-weight: 600; }
  .btn-start { background: #16a34a; color: white; }
  .btn-start:hover { background: #15803d; }
  .btn-stop  { background: #dc2626; color: white; }
  .btn-stop:hover  { background: #b91c1c; }
  .btn-export { background: #0284c7; color: white; }
  .btn-export:hover { background: #0369a1; }
  .btn:disabled { background: #334155; color: #64748b; cursor: not-allowed; }

  /* Cards de métricas */
  .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
  .metric-card { background: #0f172a; border: 1px solid #1e3a5f; border-radius: 10px; padding: 1rem; }
  .metric-card .value { font-size: 1.8rem; font-weight: 700; color: #38bdf8; }
  .metric-card .label { font-size: 0.78rem; color: #64748b; margin-top: 0.2rem; }

  /* Grid de gráficos */
  .charts-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
  .chart-card { background: #0f172a; border: 1px solid #1e3a5f; border-radius: 10px; padding: 1.2rem; }
  .chart-card h3 { font-size: 0.9rem; color: #94a3b8; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.05em; }

  /* Tabelas */
  .tables-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
  .table-card { background: #0f172a; border: 1px solid #1e3a5f; border-radius: 10px; padding: 1rem; }
  .table-card h3 { font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .rank-item { display: flex; justify-content: space-between; align-items: center; padding: 0.35rem 0; border-bottom: 1px solid #1e293b; font-size: 0.85rem; }
  .rank-item:last-child { border-bottom: none; }
  .rank-ip { color: #94a3b8; font-family: monospace; }
  .rank-count { color: #38bdf8; font-weight: 600; }

  /* Feed de pacotes */
  .feed-card { background: #0f172a; border: 1px solid #1e3a5f; border-radius: 10px; padding: 1rem; }
  .feed-card h3 { font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .packet-feed { max-height: 260px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.78rem; }
  .packet-row { padding: 0.2rem 0.4rem; border-radius: 3px; margin-bottom: 1px; display: grid; grid-template-columns: 80px 60px 140px 140px auto; gap: 0.5rem; }
  .packet-row:hover { background: #0a0f1e; }
  .proto-tcp  { color: #38bdf8; }
  .proto-udp  { color: #facc15; }
  .proto-icmp { color: #c084fc; }
  .proto-dns  { color: #4ade80; }
  .proto-http { color: #fb923c; }
  .proto-arp  { color: #f472b6; }
  .proto-outro { color: #94a3b8; }

  /* Anomalias */
  .anomaly-box { background: #1c0a0a; border: 1px solid #7f1d1d; border-radius: 8px; padding: 0.8rem 1rem; margin-bottom: 1rem; display: none; }
  .anomaly-box.visible { display: block; }
  .anomaly-item { color: #fca5a5; font-size: 0.85rem; padding: 0.2rem 0; }

  @media (max-width: 768px) {
    .metrics { grid-template-columns: repeat(2,1fr); }
    .charts-grid { grid-template-columns: 1fr; }
    .tables-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<nav>
  <h1>📡 NetAnalyzer</h1>
  <span style="color:#64748b;font-size:.85rem">Analisador de Pacotes de Rede</span>
  <div class="live-dot" id="live-dot"></div>
</nav>

<div class="container">

  <!-- Controles -->
  <div class="controls">
    <div class="form-group">
      <label>Interface</label>
      <select id="interface-select"><option value="">Carregando...</option></select>
    </div>
    <div class="form-group">
      <label>Filtro BPF</label>
      <input type="text" id="filtro-bpf" placeholder="tcp, udp port 53, host 8.8.8.8" style="width:220px"/>
    </div>
    <button class="btn btn-start" id="btn-start" onclick="iniciarCaptura()">▶ Iniciar</button>
    <button class="btn btn-stop"  id="btn-stop"  onclick="pararCaptura()" disabled>⏹ Parar</button>
    <button class="btn btn-export" onclick="exportar()">💾 Exportar JSON</button>
  </div>

  <!-- Alertas de anomalia -->
  <div class="anomaly-box" id="anomaly-box">
    <strong style="color:#f87171">⚠️ Anomalias detectadas:</strong>
    <div id="anomaly-list"></div>
  </div>

  <!-- Métricas -->
  <div class="metrics">
    <div class="metric-card">
      <div class="value" id="m-pacotes">0</div>
      <div class="label">Pacotes capturados</div>
    </div>
    <div class="metric-card">
      <div class="value" id="m-bytes">0 B</div>
      <div class="label">Total tráfego</div>
    </div>
    <div class="metric-card">
      <div class="value" id="m-pps">0</div>
      <div class="label">Pacotes / segundo</div>
    </div>
    <div class="metric-card">
      <div class="value" id="m-bps">0 B/s</div>
      <div class="label">Throughput médio</div>
    </div>
  </div>

  <!-- Gráficos -->
  <div class="charts-grid">
    <div class="chart-card">
      <h3>📈 Tráfego em tempo real</h3>
      <canvas id="chart-linha" height="120"></canvas>
    </div>
    <div class="chart-card">
      <h3>🥧 Protocolos</h3>
      <canvas id="chart-pizza" height="160"></canvas>
    </div>
  </div>

  <!-- Top IPs e portas -->
  <div class="tables-grid">
    <div class="table-card">
      <h3>🔴 Top IPs Origem</h3>
      <div id="top-origem">—</div>
    </div>
    <div class="table-card">
      <h3>🔵 Top IPs Destino</h3>
      <div id="top-destino">—</div>
    </div>
    <div class="table-card">
      <h3>🚪 Top Portas</h3>
      <div id="top-portas">—</div>
    </div>
  </div>

  <!-- Feed de pacotes -->
  <div class="feed-card">
    <h3>📋 Feed ao vivo <span style="color:#334155;font-weight:400">(últimos 50 pacotes)</span></h3>
    <div class="packet-feed" id="packet-feed">
      <span style="color:#475569">Aguardando captura...</span>
    </div>
  </div>

</div>

<script>
// ── Gráficos Chart.js ──────────────────────────────────────────────────────

const ctxLinha = document.getElementById('chart-linha').getContext('2d');
const chartLinha = new Chart(ctxLinha, {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      label: 'Pacotes/s',
      data: [],
      borderColor: '#38bdf8',
      backgroundColor: 'rgba(56,189,248,0.08)',
      borderWidth: 1.5,
      pointRadius: 0,
      fill: true,
      tension: 0.4,
    }]
  },
  options: {
    animation: false,
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#475569', maxTicksLimit: 6 }, grid: { color: '#1e293b' } },
      y: { ticks: { color: '#475569' }, grid: { color: '#1e293b' }, beginAtZero: true },
    }
  }
});

const ctxPizza = document.getElementById('chart-pizza').getContext('2d');
const chartPizza = new Chart(ctxPizza, {
  type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], backgroundColor: ['#38bdf8','#facc15','#c084fc','#4ade80','#fb923c','#f472b6','#94a3b8'], borderWidth: 0 }] },
  options: {
    animation: false,
    responsive: true,
    plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 } } } }
  }
});

// ── Estado ──────────────────────────────────────────────────────────────────
let capturaAtiva = false;
let intervalId = null;

// ── Carregar interfaces ──────────────────────────────────────────────────────
async function carregarInterfaces() {
  const resp = await fetch('/api/interfaces');
  const data = await resp.json();
  const sel = document.getElementById('interface-select');
  sel.innerHTML = data.interfaces.map(i => `<option value="${i}">${i}</option>`).join('');
}

// ── Controles de captura ─────────────────────────────────────────────────────
async function iniciarCaptura() {
  const iface = document.getElementById('interface-select').value;
  const filtro = document.getElementById('filtro-bpf').value;

  const resp = await fetch('/api/captura/iniciar', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ interface: iface, filtro_bpf: filtro })
  });
  const data = await resp.json();

  if (data.sucesso) {
    capturaAtiva = true;
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').disabled = false;
    document.getElementById('live-dot').classList.add('active');
    intervalId = setInterval(atualizarDados, 2000);
  }
}

async function pararCaptura() {
  await fetch('/api/captura/parar', { method: 'POST' });
  capturaAtiva = false;
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-stop').disabled = true;
  document.getElementById('live-dot').classList.remove('active');
  if (intervalId) { clearInterval(intervalId); intervalId = null; }
}

// ── Atualização em tempo real ────────────────────────────────────────────────
async function atualizarDados() {
  try {
    const [statsResp, pktResp] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/pacotes?n=50')
    ]);
    const stats = await statsResp.json();
    const pkts  = await pktResp.json();

    // Métricas
    document.getElementById('m-pacotes').textContent = stats.total_pacotes.toLocaleString();
    document.getElementById('m-bytes').textContent   = stats.total_bytes_formatado;
    document.getElementById('m-pps').textContent     = stats.pps_medio;
    document.getElementById('m-bps').textContent     = stats.bps_medio;

    // Gráfico de linha
    if (stats.historico) {
      chartLinha.data.labels   = stats.historico.labels;
      chartLinha.data.datasets[0].data = stats.historico.pacotes;
      chartLinha.update('none');
    }

    // Gráfico de pizza
    const proto = stats.distribuicao_protocolos;
    chartPizza.data.labels = Object.keys(proto);
    chartPizza.data.datasets[0].data = Object.values(proto);
    chartPizza.update('none');

    // Top IPs origem
    document.getElementById('top-origem').innerHTML =
      renderRank(stats.top_ips_origem);

    // Top IPs destino
    document.getElementById('top-destino').innerHTML =
      renderRank(stats.top_ips_destino);

    // Top portas
    document.getElementById('top-portas').innerHTML =
      renderRank(stats.top_portas);

    // Feed de pacotes
    if (pkts.pacotes && pkts.pacotes.length > 0) {
      document.getElementById('packet-feed').innerHTML =
        pkts.pacotes.reverse().map(p => {
          const cls = `proto-${p.protocolo.toLowerCase()}`;
          const resumo = p.dns_query || p.http_host || p.resumo || '';
          return `<div class="packet-row">
            <span style="color:#475569">${p.timestamp}</span>
            <span class="${cls}">${p.protocolo}</span>
            <span style="color:#94a3b8;font-size:.75rem">${p.ip_origem || '—'}</span>
            <span style="color:#64748b;font-size:.75rem">${p.ip_destino || '—'}</span>
            <span style="color:#475569;font-size:.75rem">${resumo}</span>
          </div>`;
        }).join('');
    }

    // Anomalias
    if (stats.anomalias && stats.anomalias.length > 0) {
      document.getElementById('anomaly-box').classList.add('visible');
      document.getElementById('anomaly-list').innerHTML =
        stats.anomalias.map(a => `<div class="anomaly-item">${a}</div>`).join('');
    } else {
      document.getElementById('anomaly-box').classList.remove('visible');
    }

  } catch(e) { console.error(e); }
}

function renderRank(items) {
  if (!items || items.length === 0) return '<span style="color:#475569">—</span>';
  return items.map(([k, v]) =>
    `<div class="rank-item"><span class="rank-ip">${k}</span><span class="rank-count">${v}</span></div>`
  ).join('');
}

async function exportar() {
  const resp = await fetch('/api/exportar', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}' });
  const data = await resp.json();
  if (data.sucesso) alert('✅ Exportado: ' + data.arquivo);
  else alert('Erro: ' + data.erro);
}

// Init
carregarInterfaces();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# Rotas da API
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(TEMPLATE)


@app.route("/api/captura/iniciar", methods=["POST"])
def iniciar_captura():
    global _captura, _sessao, _stats_calc
    dados = request.get_json() or {}

    try:
        from packet_capture import PacketCapture
        from traffic_stats import TrafficStats

        with _lock:
            if _captura and _captura.esta_ativo():
                return jsonify({"sucesso": False, "erro": "Captura já em andamento"})

            _stats_calc = TrafficStats()
            _captura = PacketCapture(
                interface=dados.get("interface", ""),
                filtro_bpf=dados.get("filtro_bpf", ""),
                verbose=False,
            )
            _sessao = _captura.iniciar()

        return jsonify({"sucesso": True})

    except Exception as e:
        return jsonify({"sucesso": False, "erro": str(e)})


@app.route("/api/captura/parar", methods=["POST"])
def parar_captura():
    global _captura
    with _lock:
        if _captura:
            _captura.parar()
    return jsonify({"sucesso": True})


@app.route("/api/stats")
def get_stats():
    if not _sessao or not _stats_calc:
        return jsonify({"total_pacotes": 0, "total_bytes": 0,
                        "total_bytes_formatado": "0 B", "pps_medio": 0,
                        "bps_medio": "0 B/s", "distribuicao_protocolos": {},
                        "top_ips_origem": [], "top_ips_destino": [],
                        "top_portas": [], "anomalias": []})
    try:
        stats = _stats_calc.calcular(_sessao)
        stats["historico"] = _stats_calc.calcular_historico(_sessao)
        stats["anomalias"] = _stats_calc.detectar_anomalias(_sessao)
        return jsonify(stats)
    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@app.route("/api/pacotes")
def get_pacotes():
    n = int(request.args.get("n", 50))
    if not _sessao:
        return jsonify({"pacotes": []})
    pacotes = _sessao.pacotes_recentes[-n:]
    return jsonify({"pacotes": [
        {"timestamp": p.timestamp, "protocolo": p.protocolo,
         "ip_origem": p.ip_origem, "ip_destino": p.ip_destino,
         "porta_destino": p.porta_destino, "tamanho_bytes": p.tamanho_bytes,
         "dns_query": p.dns_query, "http_host": p.http_host,
         "flags_tcp": p.flags_tcp, "resumo": p.resumo}
        for p in pacotes
    ]})


@app.route("/api/exportar", methods=["POST"])
def exportar():
    if not _sessao or not _stats_calc:
        return jsonify({"sucesso": False, "erro": "Nenhuma sessão ativa"}), 400
    try:
        from exporter import Exporter
        exp = Exporter(diretorio_saida=CAPTURES_DIR)
        stats = _stats_calc.calcular(_sessao)
        caminho = exp.exportar_json(_sessao, stats)
        return jsonify({"sucesso": True, "arquivo": os.path.basename(caminho)})
    except Exception as e:
        return jsonify({"sucesso": False, "erro": str(e)})


@app.route("/api/interfaces")
def get_interfaces():
    from packet_capture import listar_interfaces
    return jsonify({"interfaces": listar_interfaces() or ["eth0", "wlan0", "lo"]})


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  NetAnalyzer Dashboard")
    print("  http://localhost:5001")
    print("  ATENÇÃO: Execute com sudo para capturar pacotes!")
    print("="*50 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5001)