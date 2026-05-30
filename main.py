"""
main.py  —  Pipeline Orchestrator + CLI
────────────────────────────────────────
Wires together:   Sniffer → Parser → Logger → Detector → (UI / report)

Usage:
  python main.py capture -i WiFi
  python main.py capture -i eth0 --filter "tcp port 443" --count 500
  python main.py capture --pcap path/to/file.pcap
  python main.py analyze  --minutes 10
  python main.py report   --minutes 60
  python main.py ask "Which host sent the most traffic?"
"""

import sys
import io
import os
import json
import warnings
import logging
from pathlib import Path
from datetime import datetime

# Windows UTF-8 fix
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from dotenv import load_dotenv
load_dotenv(override=True)

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# ── Pipeline stages ───────────────────────────────────────────────────────────
from sniffer  import Sniffer
from parser   import Parser
from detector import Detector
from logger   import Logger

console    = Console()
REPORT_DIR = Path("report")
REPORT_DIR.mkdir(exist_ok=True)

_logger   = Logger()
_parser   = Parser()
_detector = Detector()


# ─────────────────────────────────────────────
# AI helper
# ─────────────────────────────────────────────

def _get_ai_client():
    try:
        groq_key = os.environ.get("GROQ_API_KEY")
        if groq_key:
            from groq import Groq
            return Groq(api_key=groq_key), "llama-3.3-70b-versatile"
    except Exception:
        pass
    console.print("\n[bold red]ERROR: GROQ_API_KEY not found.[/bold red]")
    console.print("Add [yellow]GROQ_API_KEY=gsk_...[/yellow] to your [cyan].env[/cyan] file.\n")
    sys.exit(1)


def _ai_call(prompt: str) -> str:
    client, model = _get_ai_client()
    resp = client.chat.completions.create(
        model=model,
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content


def ai_summarize(summary: dict, alerts: list) -> str:
    return _ai_call(f"""You are a network analyst. Respond in this EXACT format:

🔍 WHAT'S HAPPENING:
[1-2 sentences, plain English, no jargon]

⚠️  TOP PORTS:
[List top 3 ports with plain-English name and status: NORMAL/WATCH/ALERT]

🛡️  SECURITY STATUS: [CLEAN / CAUTION / DANGER]
[One sentence reason]

✅ ACTION NEEDED:
[Either "None - network looks healthy" or one specific action]

Traffic data (last {summary['window_minutes']} min):
- Packets: {summary['total_packets']:,}
- Data: {summary['total_bytes']/1024:.1f} KB
- Protocols: {list(summary['protocols'].keys())}
- Top ports: {list(summary['top_ports'].keys())[:5]}
- Alerts: {len(alerts)}

Keep the response under 120 words.""")


def ai_answer(question: str, summary: dict) -> str:
    return _ai_call(f"""You are a network analyst assistant.
Answer the question based only on the traffic data below. Be concise.

Traffic Data:
{json.dumps(summary, indent=2)}

Question: {question}""")


# ─────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────

def print_banner():
    console.print()
    console.print(Panel(
        "[bold cyan]NetSniffer[/bold cyan]  ·  Sniffer → Parser → Detector → Logger → UI",
        border_style="cyan", padding=(0, 2),
    ))
    console.print()


def print_summary_table(summary: dict):
    kb = summary["total_bytes"] / 1024
    console.print(Panel(
        f"[bold]Window:[/bold] last {summary['window_minutes']} min   "
        f"[bold]Packets:[/bold] {summary['total_packets']:,}   "
        f"[bold]Data:[/bold] {kb:.1f} KB",
        title="[bold cyan]Traffic Overview[/bold cyan]",
        border_style="cyan", padding=(0, 2),
    ))

    for title, data, colour in [
        ("Top Source IPs",        summary["top_sources"],      "cyan"),
        ("Top Destination IPs",   summary["top_destinations"], "magenta"),
        ("Protocols",             summary["protocols"],        "green"),
        ("Top Destination Ports", summary["top_ports"],        "yellow"),
    ]:
        if not data:
            continue
        t = Table(title=f"[bold]{title}[/bold]", box=box.SIMPLE_HEAD,
                  show_header=True, title_justify="left",
                  border_style="dim", padding=(0, 1))
        t.add_column("Name",  style=colour, no_wrap=True)
        t.add_column("Count", justify="right", style="white")
        t.add_column("Bar",   style=colour, no_wrap=True)
        items   = list(data.items())[:8]
        max_val = items[0][1] if items else 1
        for name, count in items:
            bar = "█" * int((count / max_val) * 20)
            t.add_row(str(name), str(count), bar)
        console.print(t)


def print_alerts(alerts: list):
    if not alerts:
        console.print("[bold green]  No anomalies detected[/bold green]")
        return
    colour = {
        "low":      ("yellow",   "LOW"),
        "medium":   ("orange3",  "MED"),
        "high":     ("red",      "HIGH"),
        "critical": ("bold red", "CRIT"),
    }
    for a in alerts:
        sev = a.get("severity", "low")
        col, label = colour.get(sev, ("white", "???"))
        console.print(f"  [{col}][{label}][/{col}] [white]{a['type']}[/white] -- {a['detail']}")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

@click.group()
def cli():
    """NetSniffer — Sniffer → Parser → Detector → Logger → UI"""
    _logger.init_db()


@cli.command()
@click.option("--iface",  "-i", default="WiFi", show_default=True,  help="Interface name (WiFi, eth0 …)")
@click.option("--filter", "-f", "bpf", default="",                   help="BPF filter e.g. 'tcp port 80'")
@click.option("--count",  "-c", default=0, type=int,                 help="Stop after N packets (0 = unlimited)")
@click.option("--pcap",   "-p", default=None,                        help="Read from a .pcap file instead of live")
def capture(iface, bpf, count, pcap):
    """Stage 1+2+4 — Capture packets, parse them, and store in DB."""
    import socket

    def my_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    MY_IP = my_ip()
    console.print(f"[dim]My IP: {MY_IP}[/dim]")

    def on_packet(raw_pkt):
        """Sniffer → Parser → Logger pipeline callback."""
        parsed = _parser.parse(raw_pkt)          # Stage 2: parse
        if parsed is None:
            return
        _logger.save_packet(parsed)               # Stage 4: persist

        src = f"{parsed['src_ip']}:{parsed['src_port']}" if parsed["src_port"] else parsed["src_ip"]
        dst = f"{parsed['dst_ip']}:{parsed['dst_port']}" if parsed["dst_port"] else parsed["dst_ip"]
        ts  = datetime.fromtimestamp(parsed["ts"]).strftime("%H:%M:%S")

        direction = "OUTGOING" if parsed["src_ip"] == MY_IP else \
                    "INCOMING" if parsed["dst_ip"] == MY_IP else "OTHER"

        print(
            f"{ts}  [{direction:<8}]  {parsed['protocol']:<5}  {src} -> {dst}  {parsed['length']} B",
            flush=True,
        )

    _logger.log(f"Capture started on {iface}" + (f" filter={bpf}" if bpf else ""))

    if pcap:
        sniff = Sniffer.from_pcap(pcap, on_packet=on_packet)
    else:
        sniff = Sniffer(iface=iface, bpf_filter=bpf, count=count, on_packet=on_packet)

    sniff.start()
    try:
        sniff.join()
    except KeyboardInterrupt:
        sniff.stop()
        sniff.join(timeout=2)

    console.print(f"\n[bold green]Capture stopped.[/bold green] {sniff.packet_count} packets saved.\n")
    _logger.log(f"Capture stopped. {sniff.packet_count} packets saved.")


@cli.command()
@click.option("--minutes", "-m", default=5, show_default=True, help="Look-back window in minutes")
def analyze(minutes):
    """Stage 3 — Detect anomalies and show AI insight."""
    print_banner()
    summary = _logger.get_recent_summary(minutes)       # Logger read
    alerts  = _detector.run_all()                       # Detector

    if summary["total_packets"] == 0:
        console.print(f"[yellow]No packets found in the last {minutes} minutes.[/yellow]")
        console.print("Run [cyan]python main.py capture -i WiFi[/cyan] first.\n")
        return

    print_summary_table(summary)
    console.print()
    console.rule("[bold]Anomaly Alerts[/bold]", style="red")
    console.print()
    print_alerts(alerts)
    console.print()
    console.rule("[bold cyan]AI Insight[/bold cyan]", style="cyan")
    console.print()

    with console.status("[cyan]Asking AI…[/cyan]"):
        insight = ai_summarize(summary, alerts)

    console.print(Panel(insight, border_style="cyan", padding=(1, 2),
                        title="[bold cyan]AI Analysis[/bold cyan]"))
    console.print()
    _logger.log(f"Analysis — {summary['total_packets']} pkts, {len(alerts)} alerts")


@cli.command()
@click.option("--minutes", "-m", default=60, show_default=True, help="Look-back window in minutes")
def report(minutes):
    """Generate a Markdown report and save it to report/."""
    print_banner()
    summary = _logger.get_recent_summary(minutes)
    alerts  = _detector.run_all()

    if summary["total_packets"] == 0:
        console.print(f"[yellow]No packets in the last {minutes} minutes.[/yellow]\n")
        return

    with console.status("[cyan]Generating report…[/cyan]"):
        insight = ai_summarize(summary, alerts)

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"report_{ts}.md"

    alert_lines = "\n".join(
        f"- **[{a['severity'].upper()}]** `{a['type']}`: {a['detail']}" for a in alerts
    ) or "_None detected_"

    src_lines  = "\n".join(f"- `{ip}`: {c} packets" for ip, c in list(summary["top_sources"].items())[:10])      or "_No data_"
    dst_lines  = "\n".join(f"- `{ip}`: {c} packets" for ip, c in list(summary["top_destinations"].items())[:10]) or "_No data_"
    port_lines = "\n".join(f"- Port `{p}`: {c} packets" for p, c in list(summary["top_ports"].items())[:10])     or "_No data_"

    md = f"""# Network Traffic Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Window:** Last {minutes} minutes

---

## AI Summary

{insight}

---

## Traffic Statistics

| Metric         | Value |
|----------------|-------|
| Total Packets  | {summary['total_packets']:,} |
| Total Bytes    | {summary['total_bytes'] / 1024:.1f} KB |
| Protocols      | {', '.join(summary['protocols'].keys()) or 'N/A'} |
| Unique Sources | {len(summary['top_sources'])} |

---

## Top Source IPs

{src_lines}

## Top Destination IPs

{dst_lines}

## Top Destination Ports

{port_lines}

---

## Anomaly Alerts ({len(alerts)})

{alert_lines}
"""
    path.write_text(md, encoding="utf-8")
    console.print(f"[bold green]Report saved:[/bold green] [cyan]{path}[/cyan]\n")
    _logger.log(f"Report generated: {path}")


@cli.command()
@click.argument("question")
@click.option("--minutes", "-m", default=30, show_default=True, help="Look-back window in minutes")
def ask(question, minutes):
    """Ask a natural-language question about captured traffic."""
    print_banner()
    summary = _logger.get_recent_summary(minutes)

    if summary["total_packets"] == 0:
        console.print(f"[yellow]No packets in the last {minutes} minutes.[/yellow]\n")
        return

    console.print(f"[bold]Question:[/bold] {question}\n")
    with console.status("[cyan]Thinking…[/cyan]"):
        answer = ai_answer(question, summary)

    console.print(Panel(answer, title="[bold cyan]Answer[/bold cyan]",
                        border_style="cyan", padding=(1, 2)))
    console.print()


if __name__ == "__main__":
    cli()
