"""
detector.py  —  Stage 3: Anomaly Detection
────────────────────────────────────────────
Responsibility:
  • Query the SQLite DB (written by Logger) for statistical patterns
  • Run rule-based detectors against recent traffic
  • Return structured alert dicts for Logger and UI to consume
  • Know nothing about capturing, parsing, or rendering

Public API:
  detector = Detector(db_path)
  alerts   = detector.run_all()          → list[Alert]
  alerts   = detector.run(names=[...])   → list[Alert]  (run specific detectors)

Alert schema
------------
  type       str   — detector name  e.g. 'dos_flood'
  severity   str   — 'low' | 'medium' | 'high' | 'critical'
  src_ip     str   — (optional) offending IP
  dst_ip     str   — (optional)
  dst_port   int   — (optional)
  detail     str   — human-readable description
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# IPs that should never trigger volume-based detectors
CDN_WHITELIST = {
    "23.217.111.138",   # Akamai
    "23.217.111.0",
    "104.16.0.0",       # Cloudflare
    "172.217.0.0",      # Google
    "13.107.0.0",       # Microsoft
}

# Ports worth flagging even for low traffic volumes
SUSPICIOUS_PORTS = {
    23,     # Telnet
    4444,   # Metasploit default
    1337,   # Common backdoor
    6667,   # IRC/botnet C2
    31337,  # "Elite" backdoor
    8080,   # Alt-HTTP proxy
    8443,   # Alt-HTTPS
}


# ─────────────────────────────────────────────
# Detector class
# ─────────────────────────────────────────────

class Detector:
    def __init__(self, db_path: str = "output/packets.db"):
        self.db_path = Path(db_path)

    # ── helpers ─────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _since(self, seconds: int) -> float:
        return datetime.now().timestamp() - seconds

    # ── individual detectors ─────────────────

    def detect_dos_flood(
        self, window_seconds: int = 10, threshold: int = 200
    ) -> list[dict]:
        """Single source IP sending an extreme packet burst."""
        alerts = []
        try:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                """
                SELECT src_ip, COUNT(*) AS c
                FROM packets WHERE ts >= ?
                GROUP BY src_ip HAVING c >= ?
                ORDER BY c DESC
                """,
                (self._since(window_seconds), threshold),
            )
            for src_ip, count in cur.fetchall():
                if src_ip in CDN_WHITELIST:
                    continue
                alerts.append({
                    "type":     "dos_flood",
                    "severity": "critical",
                    "src_ip":   src_ip,
                    "detail":   f"{src_ip} sent {count} packets in {window_seconds}s (possible DoS)",
                })
            con.close()
        except Exception as exc:
            alerts.append(_error_alert("dos_flood", exc))
        return alerts

    def detect_port_scan(
        self, window_seconds: int = 60, threshold: int = 15
    ) -> list[dict]:
        """IP probing many distinct destination ports."""
        alerts = []
        try:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                """
                SELECT src_ip, COUNT(DISTINCT dst_port) AS port_count
                FROM packets
                WHERE ts >= ? AND dst_port IS NOT NULL
                GROUP BY src_ip HAVING port_count >= ?
                ORDER BY port_count DESC
                """,
                (self._since(window_seconds), threshold),
            )
            for src_ip, count in cur.fetchall():
                if src_ip in CDN_WHITELIST:
                    continue
                alerts.append({
                    "type":     "port_scan",
                    "severity": "high",
                    "src_ip":   src_ip,
                    "detail":   f"{src_ip} probed {count} distinct ports in {window_seconds}s",
                })
            con.close()
        except Exception as exc:
            alerts.append(_error_alert("port_scan", exc))
        return alerts

    def detect_high_volume(
        self, window_seconds: int = 60, threshold_mb: float = 50.0
    ) -> list[dict]:
        """Flow transferring unusually large data volumes."""
        alerts = []
        try:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                """
                SELECT src_ip, dst_ip, SUM(length) AS total_bytes
                FROM packets WHERE ts >= ?
                GROUP BY src_ip, dst_ip
                HAVING total_bytes >= ?
                ORDER BY total_bytes DESC
                """,
                (self._since(window_seconds), threshold_mb * 1024 * 1024),
            )
            for src_ip, dst_ip, total_bytes in cur.fetchall():
                if src_ip in CDN_WHITELIST:
                    continue
                mb = total_bytes / (1024 * 1024)
                alerts.append({
                    "type":     "high_volume",
                    "severity": "medium",
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "detail":   f"{src_ip} → {dst_ip}: {mb:.1f} MB in {window_seconds}s",
                })
            con.close()
        except Exception as exc:
            alerts.append(_error_alert("high_volume", exc))
        return alerts

    def detect_suspicious_ports(
        self, ports: Optional[set] = None, window_seconds: int = 300
    ) -> list[dict]:
        """Traffic destined for known-malicious / unusual ports."""
        watched = ports or SUSPICIOUS_PORTS
        alerts = []
        try:
            con = self._connect()
            cur = con.cursor()
            placeholders = ",".join("?" * len(watched))
            cur.execute(
                f"""
                SELECT src_ip, dst_ip, dst_port, COUNT(*) AS c
                FROM packets
                WHERE ts >= ? AND dst_port IN ({placeholders})
                GROUP BY src_ip, dst_ip, dst_port
                ORDER BY c DESC
                """,
                (self._since(window_seconds), *watched),
            )
            for src_ip, dst_ip, port, count in cur.fetchall():
                if src_ip in CDN_WHITELIST:
                    continue
                alerts.append({
                    "type":     "suspicious_port",
                    "severity": "medium",
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "dst_port": port,
                    "detail":   f"{src_ip} → {dst_ip}:{port} ({count} packets)",
                })
            con.close()
        except Exception as exc:
            alerts.append(_error_alert("suspicious_port", exc))
        return alerts

    def detect_icmp_flood(
        self, window_seconds: int = 30, threshold: int = 100
    ) -> list[dict]:
        """Potential ICMP flood or ping sweep."""
        alerts = []
        try:
            con = self._connect()
            cur = con.cursor()
            cur.execute(
                """
                SELECT src_ip, COUNT(*) AS c
                FROM packets WHERE ts >= ? AND protocol = 'ICMP'
                GROUP BY src_ip HAVING c >= ?
                ORDER BY c DESC
                """,
                (self._since(window_seconds), threshold),
            )
            for src_ip, count in cur.fetchall():
                if src_ip in CDN_WHITELIST:
                    continue
                alerts.append({
                    "type":     "icmp_flood",
                    "severity": "high",
                    "src_ip":   src_ip,
                    "detail":   f"{src_ip} sent {count} ICMP packets in {window_seconds}s",
                })
            con.close()
        except Exception as exc:
            alerts.append(_error_alert("icmp_flood", exc))
        return alerts

    # ── aggregate runner ─────────────────────

    def run_all(self) -> list[dict]:
        """Run every detector and return a severity-sorted list of alerts."""
        alerts = []
        alerts += self.detect_dos_flood()
        alerts += self.detect_port_scan()
        alerts += self.detect_high_volume()
        alerts += self.detect_suspicious_ports()
        alerts += self.detect_icmp_flood()
        alerts.sort(
            key=lambda a: SEVERITY_RANK.get(a.get("severity", "low"), 0),
            reverse=True,
        )
        return alerts

    def run(self, names: list[str]) -> list[dict]:
        """Run only the named detectors."""
        _map = {
            "dos_flood":        self.detect_dos_flood,
            "port_scan":        self.detect_port_scan,
            "high_volume":      self.detect_high_volume,
            "suspicious_ports": self.detect_suspicious_ports,
            "icmp_flood":       self.detect_icmp_flood,
        }
        alerts = []
        for name in names:
            fn = _map.get(name)
            if fn:
                alerts += fn()
        alerts.sort(
            key=lambda a: SEVERITY_RANK.get(a.get("severity", "low"), 0),
            reverse=True,
        )
        return alerts


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _error_alert(detector_name: str, exc: Exception) -> dict:
    return {
        "type":     f"{detector_name}_error",
        "severity": "low",
        "detail":   f"Detector '{detector_name}' failed: {exc}",
    }
