"""
parser.py  —  Stage 2: Packet Parsing & Normalisation
──────────────────────────────────────────────────────
Responsibility:
  • Accept a raw Scapy packet
  • Extract all structured fields into a plain Python dict (ParsedPacket)
  • Enrich with GeoIP data if available
  • Compute a stable bidirectional flow_id
  • Know nothing about storage, detection, or UI

Public API:
  parser = Parser()
  parsed = parser.parse(scapy_pkt)   → dict | None
"""

import hashlib
import warnings
import logging
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

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


def _flow_id(src_ip, dst_ip, src_port, dst_port, proto) -> str:
    """Stable bidirectional flow key — same for A→B and B→A."""
    sp = _safe_int(src_port)
    dp = _safe_int(dst_port)
    pair = tuple(sorted([(_safe_str(src_ip), sp), (_safe_str(dst_ip), dp)]))
    key = str(pair) + _safe_str(proto)
    return hashlib.md5(key.encode()).hexdigest()[:16]


# ─────────────────────────────────────────────
# GeoIP (optional — graceful fallback)
# ─────────────────────────────────────────────

class _GeoIPReader:
    """Lazy singleton wrapper around geoip2.database.Reader."""

    def __init__(self, mmdb_path: str = "GeoLite2-City.mmdb"):
        self._path = mmdb_path
        self._reader = None
        self._tried = False

    def _get(self):
        if not self._tried:
            self._tried = True
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(self._path)
            except Exception:
                pass
        return self._reader

    def lookup(self, ip: str) -> dict:
        reader = self._get()
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


# ─────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────

class Parser:
    """
    Converts a raw Scapy packet into a structured dict.

    ParsedPacket schema
    -------------------
    ts          float    — Unix timestamp
    src_ip      str
    dst_ip      str
    src_port    int|None
    dst_port    int|None
    protocol    str      — 'TCP' | 'UDP' | 'ICMP' | 'OTHER'
    length      int      — total packet length in bytes
    flags       str      — TCP flags string, empty for other protos
    flow_id     str      — 16-char hex bidirectional flow key
    country     str|None — GeoIP country of src_ip
    city        str|None — GeoIP city of src_ip
    """

    def __init__(self, geoip_mmdb: str = "GeoLite2-City.mmdb"):
        self._geo = _GeoIPReader(geoip_mmdb)

    def parse(self, pkt) -> Optional[dict]:
        """
        Parse a Scapy packet.
        Returns a ParsedPacket dict, or None if the packet is not IP-based.
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
                src_port = _safe_int(tcp.sport)
                dst_port = _safe_int(tcp.dport)
                try:
                    flags = str(tcp.flags)
                except Exception:
                    flags = ""

            elif pkt.haslayer(UDP):
                udp      = pkt[UDP]
                proto    = "UDP"
                src_port = _safe_int(udp.sport)
                dst_port = _safe_int(udp.dport)

            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            fid = _flow_id(src_ip, dst_ip, src_port, dst_port, proto)
            geo = self._geo.lookup(src_ip)

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

        except Exception as exc:
            # Parsing errors must never crash the pipeline
            return None
