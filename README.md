This was built as a college project.

# NetSniffer

A modular network packet analysis tool with AI-powered insights.

```
Sniffer → Parser → Detector → Logger → UI
```

---

## Pipeline Architecture

| Stage      | File           | Responsibility |
|------------|----------------|----------------|
| **Sniffer**  | `sniffer.py`   | Capture raw packets from a live interface or .pcap file |
| **Parser**   | `parser.py`    | Parse Scapy packets into structured dicts; enrich with GeoIP |
| **Detector** | `detector.py`  | Run rule-based anomaly detectors against the DB |
| **Logger**   | `logger.py`    | Persist packets/flows to SQLite; write logs.txt; serve summary stats |
| **UI**       | `server.py`    | Flask REST API + single-page dashboard; AI insight via Groq/OpenAI |
| **CLI**      | `main.py`      | Orchestrator — wires all stages; `capture`, `analyze`, `report`, `ask` |

Each stage is **independently importable** and knows nothing about the others except through clearly defined data contracts.

---

## Setup

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your API key:

```
GROQ_API_KEY=gsk_...
# or
# OPENAI_API_KEY=sk-...
```

### Optional: GeoIP enrichment

Download **GeoLite2-City.mmdb** from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
and place it in the project root. GeoIP lookup is silently skipped if the file is absent.

---

## CLI Usage

```bash
# Live capture (requires root / admin)
sudo python main.py capture -i eth0
sudo python main.py capture -i WiFi --filter "tcp port 443"
sudo python main.py capture -i eth0 --count 500

# Replay a .pcap file (no root needed)
python main.py capture --pcap path/to/file.pcap

# Analyse and detect anomalies (last 10 minutes)
python main.py analyze --minutes 10

# Generate a Markdown report
python main.py report --minutes 60

# Ask a natural-language question
python main.py ask "Which IP sent the most data?"
python main.py ask "Are there any connections to port 23?"
```

## Web Dashboard

```bash
# Start the web server (no root needed — reads existing DB)
python server.py
# → http://localhost:5000
```

---

## Output Files

```
output/
  packets.db   — SQLite database (packets + flows tables)
  logs.txt     — timestamped event log

report/
  report_YYYYMMDD_HHMMSS.md   — generated Markdown reports
```

---

## Data Schema

### ParsedPacket (produced by `parser.py`, consumed by `logger.py`)

| Field      | Type      | Description |
|------------|-----------|-------------|
| `ts`       | float     | Unix timestamp |
| `src_ip`   | str       | Source IP |
| `dst_ip`   | str       | Destination IP |
| `src_port` | int\|None | Source port |
| `dst_port` | int\|None | Destination port |
| `protocol` | str       | `TCP` \| `UDP` \| `ICMP` \| `OTHER` |
| `length`   | int       | Total packet length in bytes |
| `flags`    | str       | TCP flag string (empty for other protos) |
| `flow_id`  | str       | 16-char hex bidirectional flow key |
| `country`  | str\|None | GeoIP country of `src_ip` |
| `city`     | str\|None | GeoIP city of `src_ip` |

### Alert (produced by `detector.py`)

| Field      | Type | Description |
|------------|------|-------------|
| `type`     | str  | Detector name e.g. `dos_flood`, `port_scan` |
| `severity` | str  | `low` \| `medium` \| `high` \| `critical` |
| `src_ip`   | str  | Offending source IP (when applicable) |
| `dst_ip`   | str  | Destination IP (when applicable) |
| `dst_port` | int  | Destination port (when applicable) |
| `detail`   | str  | Human-readable description |

---

## Detectors

| Name               | Trigger |
|--------------------|---------|
| `dos_flood`        | Single IP sends ≥200 packets in 10 s |
| `port_scan`        | Single IP probes ≥15 distinct ports in 60 s |
| `high_volume`      | Flow transfers ≥50 MB in 60 s |
| `suspicious_ports` | Traffic to known-bad ports (Telnet, Metasploit, IRC C2 …) |
| `icmp_flood`       | Single IP sends ≥100 ICMP packets in 30 s |
