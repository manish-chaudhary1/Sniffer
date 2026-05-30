import sqlite3
import hashlib
import warnings
import logging

# Suppress all Scapy warnings
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH  = Path("output/packets.db")
LOG_PATH = Path("output/logs.txt")


# ──────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────

def init_db():
    """Create tables if they don't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            length      INTEGER,
            flags       TEXT,
            country     TEXT,
            city        TEXT,
            flow_id     TEXT
        );

        CREATE TABLE IF NOT EXISTS flows (
            flow_id     TEXT PRIMARY KEY,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            first_seen  REAL,
            last_seen   REAL,
            pkt_count   INTEGER DEFAULT 0,
            byte_count  INTEGER DEFAULT 0,
            country     TEXT
        );
    """)
    con.commit()
    con.close()


def save_packet(pkt_data: dict):
    """Insert a parsed packet record into the DB."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("""
            INSERT INTO packets
                (ts, src_ip, dst_ip, src_port, dst_port, protocol,
                 length, flags, country, city, flow_id)
            VALUES
                (:ts, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                 :length, :flags, :country, :city, :flow_id)
        """, pkt_data)
        con.commit()
        con.close()
    except Exception as e:
        log(f"[db error] save_packet: {e}")


def upsert_flow(pkt_data: dict):
    """Insert or update the flow record aggregated from this packet."""
    try:
        fid = pkt_data["flow_id"]
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT flow_id FROM flows WHERE flow_id = ?", (fid,))
        exists = cur.fetchone()
        if exists:
            cur.execute("""
                UPDATE flows SET
                    last_seen  = :ts,
                    pkt_count  = pkt_count + 1,
                    byte_count = byte_count + :length
                WHERE flow_id = :flow_id
            """, pkt_data)
        else:
            cur.execute("""
                INSERT INTO flows
                    (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                     first_seen, last_seen, pkt_count, byte_count, country)
                VALUES
                    (:flow_id, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                     :ts, :ts, 1, :length, :country)
            """, pkt_data)
        con.commit()
        con.close()
    except Exception as e:
        log(f"[db error] upsert_flow: {e}")


def get_recent_summary(minutes: int = 5) -> dict:
    """Pull aggregated stats for the last N minutes."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    since = datetime.now().timestamp() - (minutes * 60)

    cur.execute("SELECT COUNT(*) FROM packets WHERE ts >= ?", (since,))
    total_pkts = cur.fetchone()[0]

    cur.execute("SELECT SUM(length) FROM packets WHERE ts >= ?", (since,))
    total_bytes = cur.fetchone()[0] or 0

    cur.execute("""
        SELECT protocol, COUNT(*) as c FROM packets
        WHERE ts >= ? GROUP BY protocol ORDER BY c DESC LIMIT 10
    """, (since,))
    protocols = dict(cur.fetchall())

    cur.execute("""
        SELECT src_ip, COUNT(*) as c FROM packets
        WHERE ts >= ? GROUP BY src_ip ORDER BY c DESC LIMIT 10
    """, (since,))
    top_sources = dict(cur.fetchall())

    cur.execute("""
        SELECT dst_ip, COUNT(*) as c FROM packets
        WHERE ts >= ? GROUP BY dst_ip ORDER BY c DESC LIMIT 10
    """, (since,))
    top_destinations = dict(cur.fetchall())

    cur.execute("""
        SELECT dst_port, COUNT(*) as c FROM packets
        WHERE ts >= ? AND dst_port IS NOT NULL
        GROUP BY dst_port ORDER BY c DESC LIMIT 10
    """, (since,))
    top_ports = dict(cur.fetchall())

    cur.execute("""
        SELECT country, COUNT(*) as c FROM packets
        WHERE ts >= ? AND country IS NOT NULL
        GROUP BY country ORDER BY c DESC LIMIT 5
    """, (since,))
    top_countries = dict(cur.fetchall())

    con.close()
    return {
        "window_minutes":   minutes,
        "total_packets":    total_pkts,
        "total_bytes":      total_bytes,
        "protocols":        protocols,
        "top_sources":      top_sources,
        "top_destinations": top_destinations,
        "top_ports":        top_ports,
        "top_countries":    top_countries,
    }


# ──────────────────────────────────────────────
# Packet parsing
# ──────────────────────────────────────────────

def _safe_int(val) -> int:
    try:
        return int(val) if val is not None else 0
    except Exception:
        return 0


def _safe_str(val) -> str:
    try:
        return str(val) if val is not None else ""
    except Exception:
        return ""


def flow_id(src_ip, dst_ip, src_port, dst_port, proto) -> str:
    """Stable bidirectional flow key. Ports safely cast before sorting."""
    sp   = _safe_int(src_port)
    dp   = _safe_int(dst_port)
    pair = tuple(sorted([(_safe_str(src_ip), sp), (_safe_str(dst_ip), dp)]))
    key  = str(pair) + _safe_str(proto)
    return hashlib.md5(key.encode()).hexdigest()[:16]


def parse_scapy_packet(pkt) -> Optional[dict]:
    """
    Extract fields from a Scapy packet.
    Returns None for non-IP packets or any parse error.
    Every field access is wrapped defensively.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if not pkt.haslayer(IP):
            return None

        ip       = pkt[IP]
        src_ip   = _safe_str(ip.src)
        dst_ip   = _safe_str(ip.dst)
        length   = _safe_int(len(pkt))
        ts       = float(pkt.time) if pkt.time is not None else datetime.now().timestamp()
        proto    = "OTHER"
        src_port = None
        dst_port = None
        flags    = ""

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            proto    = "TCP"
            src_port = _safe_int(tcp.sport) if tcp.sport is not None else None
            dst_port = _safe_int(tcp.dport) if tcp.dport is not None else None
            try:
                flags = str(tcp.flags)
            except Exception:
                flags = ""

        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            proto    = "UDP"
            src_port = _safe_int(udp.sport) if udp.sport is not None else None
            dst_port = _safe_int(udp.dport) if udp.dport is not None else None

        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        fid = flow_id(src_ip, dst_ip, src_port, dst_port, proto)
        geo = geoip_lookup(src_ip)

        return {
            "ts":       ts,
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length":   length,
            "flags":    flags,
            "flow_id":  fid,
            "country":  geo.get("country"),
            "city":     geo.get("city"),
        }

    except Exception as e:
        log(f"[parse error] {type(e).__name__}: {e}")
        return None


# ──────────────────────────────────────────────
# GeoIP (optional — works without the .mmdb file)
# ──────────────────────────────────────────────

_geoip_reader = None


def _get_reader():
    global _geoip_reader
    if _geoip_reader is None:
        try:
            import geoip2.database
            _geoip_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        except Exception:
            pass
    return _geoip_reader


def geoip_lookup(ip: str) -> dict:
    reader = _get_reader()
    if reader is None:
        return {}
    try:
        r = reader.city(ip)
        return {
            "country": r.country.name,
            "city":    r.city.name,
            "lat":     r.location.latitude,
            "lon":     r.location.longitude,
        }
    except Exception:
        return {}


# ──────────────────────────────────────────────
# Logging — writes to file only, no console
# ──────────────────────────────────────────────

def log(msg: str):
    """Append a timestamped line to logs.txt."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass  # Never let a log failure crash anything