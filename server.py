"""
server.py  —  Stage 5: Web UI (Flask)
──────────────────────────────────────
Responsibility:
  • Expose REST API endpoints backed by Logger + Detector
  • Optionally call an AI model (Groq / OpenAI) for natural-language insight
  • Serve the single-page dashboard HTML
  • Know nothing about packet capture or parsing

Run:
  python server.py
  → http://localhost:5000

API endpoints
-------------
  GET /                   — dashboard SPA
  GET /api/summary        — traffic stats + alerts
  GET /api/insight        — AI-generated summary
  GET /api/packets        — recent packet feed
  GET /api/flows          — recent flow table
  GET /api/ask?q=...      — natural-language Q&A
"""

import os
import sys
import json
import warnings
import logging
from pathlib import Path

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from dotenv import load_dotenv
load_dotenv(override=True)

from flask import Flask, jsonify, render_template_string, request as freq
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).parent))
from logger   import Logger
from detector import Detector

app      = Flask(__name__)
CORS(app)

_logger   = Logger()
_detector = Detector()
_logger.init_db()


# ─────────────────────────────────────────────
# AI helpers
# ─────────────────────────────────────────────

def _get_ai_client():
    try:
        from openai import OpenAI
        groq_key   = os.environ.get("GROQ_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")
        if groq_key:
            return OpenAI(api_key=groq_key, base_url="https://api.groq.com/openai/v1"), "llama-3.3-70b-versatile"
        if openai_key:
            return OpenAI(api_key=openai_key), "gpt-4o"
    except Exception:
        pass
    return None, None


def _ai_summarize(summary: dict, alerts: list) -> str:
    client, model = _get_ai_client()
    if not client:
        return "AI unavailable — set GROQ_API_KEY or OPENAI_API_KEY in .env"

    prompt = f"""You are a network analyst. Analyze this traffic data and respond in this EXACT format:

🔍 WHAT'S HAPPENING:
[1-2 sentences, plain English, no jargon]

⚠️  TOP PORTS:
[List top 3 ports with plain-English name and status: NORMAL/WATCH/ALERT]

🛡️  SECURITY STATUS: [CLEAN / CAUTION / DANGER]
[One sentence reason]

✅ ACTION NEEDED:
[Either "None - network looks healthy" or one specific thing to do]

Traffic data (last {summary['window_minutes']} min):
- Packets: {summary['total_packets']:,}
- Data: {summary['total_bytes']/1024:.1f} KB
- Top protocols: {list(summary['protocols'].keys())}
- Top dest ports: {list(summary['top_ports'].keys())[:5]}
- Alerts: {len(alerts)} detected

Keep the entire response under 120 words."""

    try:
        resp = client.chat.completions.create(
            model=model, max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content
    except Exception as exc:
        return f"AI error: {exc}"


def _ai_answer(question: str, summary: dict) -> str:
    client, model = _get_ai_client()
    if not client:
        return "AI unavailable — set GROQ_API_KEY or OPENAI_API_KEY in .env"

    prompt = f"""You are a network analyst assistant. Answer the question below
based only on the traffic data provided. Be concise and plain-English.

Traffic data (last 5 min):
{json.dumps(summary, indent=2)}

Question: {question}"""

    try:
        resp = client.chat.completions.create(
            model=model, max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content
    except Exception as exc:
        return f"AI error: {exc}"


# ─────────────────────────────────────────────
# REST API
# ─────────────────────────────────────────────

@app.route("/api/summary")
def api_summary():
    minutes = int(freq.args.get("minutes", 5))
    summary = _logger.get_recent_summary(minutes)
    alerts  = _detector.run_all()
    return jsonify({"summary": summary, "alerts": alerts})


@app.route("/api/insight")
def api_insight():
    summary = _logger.get_recent_summary(5)
    alerts  = _detector.run_all()
    insight = _ai_summarize(summary, alerts)
    return jsonify({"insight": insight})


@app.route("/api/packets")
def api_packets():
    packets = _logger.get_recent_packets(limit=100)
    return jsonify({"packets": packets})


@app.route("/api/flows")
def api_flows():
    flows = _logger.get_recent_flows(limit=20)
    return jsonify({"flows": flows})


@app.route("/api/ask")
def api_ask():
    question = freq.args.get("q", "").strip()
    if not question:
        return jsonify({"answer": "No question provided."})
    summary = _logger.get_recent_summary(5)
    answer  = _ai_answer(question, summary)
    return jsonify({"answer": answer})


# ─────────────────────────────────────────────
# Dashboard SPA
# ─────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetSniffer Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:           #0b1120;
    --surface:      #111827;
    --surface2:     #1f2937;
    --accent:       #38bdf8;
    --accent2:      #818cf8;
    --green:        #34d399;
    --yellow:       #fbbf24;
    --red:          #f87171;
    --dim:          #6b7280;
    --text:         #f1f5f9;
    --border:       #1e293b;
    --mono:         'JetBrains Mono', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 12px;
    min-height: 100vh;
  }

  /* ── Header ─────────────────────────── */
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 28px;
    border-bottom: 1px solid var(--border);
    background: rgba(11,17,32,0.9);
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(8px);
  }
  .logo { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: 1px; }
  .logo span { color: var(--accent2); }
  .header-right { display: flex; align-items: center; gap: 16px; color: var(--dim); font-size: 11px; }
  .live-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--green); display: inline-block; margin-right: 6px;
    box-shadow: 0 0 6px var(--green);
    animation: blink 2s infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.4} }
  .btn {
    background: none; border: 1px solid var(--border);
    color: var(--text); padding: 5px 14px; border-radius: 5px;
    cursor: pointer; font-family: var(--mono); font-size: 11px;
    transition: border-color .2s, color .2s;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); }

  /* ── Layout ─────────────────────────── */
  main {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    padding: 20px 28px;
  }
  .span2 { grid-column: span 2; }
  .span4 { grid-column: span 4; }

  /* ── Cards ──────────────────────────── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    transition: border-color .2s;
  }
  .card:hover { border-color: #2d3f55; }
  .card-title {
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--dim); margin-bottom: 14px;
  }

  /* ── Stat cards ─────────────────────── */
  .stat-val { font-size: 30px; font-weight: 700; line-height: 1; }
  .stat-sub { font-size: 11px; color: var(--dim); margin-top: 5px; }

  /* ── Bar charts ─────────────────────── */
  .bar-list { display: flex; flex-direction: column; gap: 9px; }
  .bar-row { display: grid; grid-template-columns: 140px 1fr 52px; align-items: center; gap: 10px; }
  .bar-label { font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bar-track { height: 5px; border-radius: 3px; background: var(--surface2); }
  .bar-fill  { height: 100%; border-radius: 3px; transition: width .6s ease; }
  .bar-count { font-size: 11px; color: var(--dim); text-align: right; }

  /* ── Protocol pills ─────────────────── */
  .proto-grid { display: flex; flex-wrap: wrap; gap: 8px; }
  .proto-pill {
    padding: 7px 14px; border-radius: 6px; border: 1px solid var(--border);
    min-width: 80px;
  }
  .proto-name  { font-size: 12px; font-weight: 600; }
  .proto-count { font-size: 10px; color: var(--dim); margin-top: 2px; }

  /* ── Alerts ─────────────────────────── */
  .alert-list { display: flex; flex-direction: column; gap: 8px; }
  .alert-item { padding: 10px 14px; border-radius: 6px; border-left: 4px solid; background: var(--surface2); }
  .alert-item.critical { border-color: var(--red); }
  .alert-item.high     { border-color: var(--yellow); }
  .alert-item.medium   { border-color: var(--accent2); }
  .alert-item.low      { border-color: var(--dim); }
  .alert-badge {
    display: inline-block; font-size: 9px; letter-spacing: 1px;
    text-transform: uppercase; padding: 2px 6px; border-radius: 3px;
    margin-right: 8px; font-weight: 700;
  }
  .no-alerts { color: var(--green); font-size: 12px; }

  /* ── AI insight ─────────────────────── */
  .insight-box {
    background: #0a1520; border: 1px solid var(--border);
    border-radius: 6px; padding: 14px 16px;
    font-size: 12px; line-height: 1.75; white-space: pre-wrap;
    min-height: 110px; color: var(--text);
  }
  .insight-box.loading { color: var(--dim); animation: blink 1s infinite; }

  /* ── Ask AI ─────────────────────────── */
  .ask-row { display: flex; gap: 8px; margin-bottom: 12px; }
  .ask-input {
    flex: 1; background: #0a1520; border: 1px solid var(--border);
    color: var(--text); padding: 8px 12px; border-radius: 5px;
    font-family: var(--mono); font-size: 12px; outline: none;
    transition: border-color .2s;
  }
  .ask-input:focus  { border-color: var(--accent); }
  .ask-input::placeholder { color: var(--dim); }
  .ask-btn {
    background: var(--accent); color: #000; border: none;
    padding: 8px 18px; border-radius: 5px; cursor: pointer;
    font-family: var(--mono); font-size: 12px; font-weight: 600;
    transition: opacity .2s;
  }
  .ask-btn:hover    { opacity: .85; }
  .ask-btn:disabled { opacity: .4; cursor: default; }

  /* ── Packet table ───────────────────── */
  .tbl-wrap { max-height: 280px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left; font-size: 10px; letter-spacing: 1px;
    text-transform: uppercase; color: var(--dim);
    padding: 0 8px 10px 0; border-bottom: 1px solid var(--border); font-weight: 400;
  }
  td { padding: 6px 8px 6px 0; border-bottom: 1px solid rgba(30,41,59,.5); }
  tr:hover td { background: rgba(56,189,248,.03); }
  .pbadge {
    padding: 2px 7px; border-radius: 3px; font-size: 10px; font-weight: 600;
  }
  .pbadge-TCP  { background: rgba(56,189,248,.15); color: var(--accent); }
  .pbadge-UDP  { background: rgba(52,211,153,.12); color: var(--green); }
  .pbadge-ICMP { background: rgba(251,191,36,.12); color: var(--yellow); }
  .pbadge-OTHER{ background: rgba(100,100,100,.2);  color: var(--dim); }
</style>
</head>
<body>

<header>
  <div class="logo">Net<span>Sniffer</span></div>
  <div class="header-right">
    <span><span class="live-dot"></span>LIVE</span>
    <span id="last-update">--:--:--</span>
    <button class="btn" onclick="loadAll()">↻ Refresh</button>
  </div>
</header>

<main>

  <!-- Stat cards -->
  <div class="card">
    <div class="card-title">Packets</div>
    <div class="stat-val" id="s-packets">—</div>
    <div class="stat-sub">last 5 min</div>
  </div>
  <div class="card">
    <div class="card-title">Data Volume</div>
    <div class="stat-val" id="s-bytes">—</div>
    <div class="stat-sub" id="s-bytes-unit">KB</div>
  </div>
  <div class="card">
    <div class="card-title">Alerts</div>
    <div class="stat-val" id="s-alerts" style="color:var(--green)">—</div>
    <div class="stat-sub">anomalies</div>
  </div>
  <div class="card">
    <div class="card-title">Top Protocol</div>
    <div class="stat-val" id="s-proto" style="font-size:20px;padding-top:4px">—</div>
    <div class="stat-sub" id="s-proto-pct"></div>
  </div>

  <!-- Sources / Destinations -->
  <div class="card span2">
    <div class="card-title">Top Source IPs</div>
    <div class="bar-list" id="src-bars"></div>
  </div>
  <div class="card span2">
    <div class="card-title">Top Destination IPs</div>
    <div class="bar-list" id="dst-bars"></div>
  </div>

  <!-- Protocols + Alerts -->
  <div class="card span2">
    <div class="card-title">Protocols</div>
    <div class="proto-grid" id="proto-pills"></div>
  </div>
  <div class="card span2">
    <div class="card-title">Anomaly Alerts</div>
    <div class="alert-list" id="alert-list"></div>
  </div>

  <!-- Top Ports -->
  <div class="card span2">
    <div class="card-title">Top Destination Ports</div>
    <div class="bar-list" id="port-bars"></div>
  </div>

  <!-- AI Insight -->
  <div class="card span2">
    <div class="card-title">AI Insight</div>
    <div class="insight-box loading" id="insight-box">Loading analysis…</div>
  </div>

  <!-- Live Packets -->
  <div class="card span4">
    <div class="card-title">Live Packet Feed</div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Bytes</th></tr></thead>
        <tbody id="pkt-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Ask AI -->
  <div class="card span4">
    <div class="card-title">Ask AI</div>
    <div class="ask-row">
      <input class="ask-input" id="ask-input" placeholder="e.g. Which host sent the most traffic?" />
      <button class="ask-btn" id="ask-btn" onclick="askAI()">Ask</button>
    </div>
    <div class="insight-box" id="ask-result" style="min-height:70px;color:var(--dim)">
      Ask anything about your network traffic…
    </div>
  </div>

</main>

<script>
const PROTO_COLORS = { TCP:'#38bdf8', UDP:'#34d399', ICMP:'#fbbf24', OTHER:'#6b7280' };
const SEV_COLORS   = { critical:'#f87171', high:'#fbbf24', medium:'#818cf8', low:'#6b7280' };

function bars(id, data, color) {
  const el = document.getElementById(id);
  if (!data || !Object.keys(data).length) { el.innerHTML = '<span style="color:var(--dim)">No data</span>'; return; }
  const max = Math.max(...Object.values(data));
  el.innerHTML = Object.entries(data).slice(0,8).map(([k,v]) =>
    `<div class="bar-row">
       <div class="bar-label" title="${k}">${k}</div>
       <div class="bar-track"><div class="bar-fill" style="width:${(v/max*100).toFixed(1)}%;background:${color}"></div></div>
       <div class="bar-count">${v.toLocaleString()}</div>
     </div>`).join('');
}

function protos(data) {
  const el    = document.getElementById('proto-pills');
  const total = Object.values(data).reduce((a,b)=>a+b,0);
  el.innerHTML = Object.entries(data).map(([n,c]) =>
    `<div class="proto-pill">
       <div class="proto-name" style="color:${PROTO_COLORS[n]||'var(--text)'}">${n}</div>
       <div class="proto-count">${c.toLocaleString()} · ${(c/total*100).toFixed(1)}%</div>
     </div>`).join('');
}

function alerts(list) {
  const el = document.getElementById('alert-list');
  const sv = document.getElementById('s-alerts');
  sv.textContent = list.length;
  sv.style.color = list.length ? 'var(--red)' : 'var(--green)';
  el.innerHTML = list.length
    ? list.map(a =>
        `<div class="alert-item ${a.severity}">
           <span class="alert-badge" style="background:${SEV_COLORS[a.severity]}22;color:${SEV_COLORS[a.severity]}">${a.severity}</span>
           <span style="color:var(--dim);font-size:10px">${a.type}</span> — ${a.detail}
         </div>`).join('')
    : '<div class="no-alerts">✓ No anomalies detected</div>';
}

function packets(rows) {
  document.getElementById('pkt-body').innerHTML = rows.map(p =>
    `<tr>
       <td style="color:var(--dim)">${p.time}</td>
       <td>${p.src}</td><td>${p.dst}</td>
       <td><span class="pbadge pbadge-${p.protocol}">${p.protocol}</span></td>
       <td style="color:var(--dim)">${p.length}B</td>
     </tr>`).join('');
}

async function loadSummary() {
  const { summary, alerts: al } = await fetch('/api/summary').then(r=>r.json());
  document.getElementById('s-packets').textContent = summary.total_packets.toLocaleString();
  const kb = summary.total_bytes/1024;
  if (kb > 1024) {
    document.getElementById('s-bytes').textContent = (kb/1024).toFixed(1);
    document.getElementById('s-bytes-unit').textContent = 'MB';
  } else {
    document.getElementById('s-bytes').textContent = kb.toFixed(1);
  }
  const top = Object.entries(summary.protocols)[0];
  if (top) {
    const total = Object.values(summary.protocols).reduce((a,b)=>a+b,0);
    document.getElementById('s-proto').textContent    = top[0];
    document.getElementById('s-proto-pct').textContent = `${(top[1]/total*100).toFixed(0)}% of traffic`;
  }
  bars('src-bars',  summary.top_sources,      'var(--accent)');
  bars('dst-bars',  summary.top_destinations, 'var(--green)');
  bars('port-bars', summary.top_ports,        'var(--yellow)');
  protos(summary.protocols);
  alerts(al);
}

async function loadInsight() {
  const el = document.getElementById('insight-box');
  el.className = 'insight-box loading'; el.textContent = 'Asking AI…';
  const { insight } = await fetch('/api/insight').then(r=>r.json());
  el.className = 'insight-box'; el.textContent = insight;
}

async function loadPackets() {
  const { packets: rows } = await fetch('/api/packets').then(r=>r.json());
  packets(rows);
}

async function askAI() {
  const input = document.getElementById('ask-input');
  const res   = document.getElementById('ask-result');
  const btn   = document.getElementById('ask-btn');
  const q = input.value.trim(); if (!q) return;
  btn.disabled = true;
  res.className = 'insight-box loading'; res.textContent = 'Thinking…';
  const { answer } = await fetch(`/api/ask?q=${encodeURIComponent(q)}`).then(r=>r.json());
  res.className = 'insight-box'; res.textContent = answer;
  btn.disabled = false;
}

async function loadAll() {
  document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
  await Promise.all([loadSummary(), loadPackets()]);
  loadInsight();
}

loadAll();
setInterval(loadAll, 30000);
document.getElementById('ask-input').addEventListener('keydown', e => { if (e.key==='Enter') askAI(); });
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    print("\n  ┌─────────────────────────────────────┐")
    print("  │  NetSniffer Dashboard                │")
    print("  │  http://localhost:5000               │")
    print("  └─────────────────────────────────────┘\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
