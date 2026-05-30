"""
logger.py  —  Stage 4: Persistence & Structured Logging
─────────────────────────────────────────────────────────
Responsibility:
  • Receive ParsedPackets from the Parser
  • Persist them to SQLite (packets + flows tables)
  • Write human-readable timestamped lines to logs.txt
  • Provide read helpers (summary stats) for Detector and UI
  • Know nothing about capturing, parsing, detection, or rendering

Public API:
  logger = Logger(db_path, log_path)
  logger.init_db()
  logger.save_packet(parsed_pkt)          — write packet row + upsert flow
  logger.log(msg)                         — write to logs.txt
  logger.get_recent_summary(minutes)      — dict of aggregated stats
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


class Logger:
    """
    Handles all I/O for the pipeline.

    Parameters
    ----------
    db_path  : path to the SQLite database file
    log_path : path to the plain-text log file
    """

    def __init__(
        self,
        db_path:  str = "output/packets.db",
        log_path: str = "output/logs.txt",
    ):
        self.db_path  = Path(db_path)
        self.log_path = Path(log_path)

    # ─────────────────────────────────────────
    # Setup
    # ─────────────────────────────────────────

    def init_db(self):
        """Create tables if they don't already exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(str(self.db_path))
        con.executescript("""
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

            CREATE INDEX IF NOT EXISTS idx_packets_ts     ON packets(ts);
            CREATE INDEX IF NOT EXISTS idx_packets_src    ON packets(src_ip);
            CREATE INDEX IF NOT EXISTS idx_packets_proto  ON packets(protocol);
            CREATE INDEX IF NOT EXISTS idx_flows_last     ON flows(last_seen);
        """)
        con.commit()
        con.close()

    # ─────────────────────────────────────────
    # Write path
    # ─────────────────────────────────────────

    def save_packet(self, pkt: dict):
        """
        Persist a ParsedPacket dict.
        Writes one row to `packets` and upserts one row in `flows`.
        """
        try:
            con = sqlite3.connect(str(self.db_path))
            cur = con.cursor()

            # ── packets table ──────────────────
            cur.execute(
                """
                INSERT INTO packets
                    (ts, src_ip, dst_ip, src_port, dst_port, protocol,
                     length, flags, country, city, flow_id)
                VALUES
                    (:ts, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                     :length, :flags, :country, :city, :flow_id)
                """,
                pkt,
            )

            # ── flows table (upsert) ───────────
            fid = pkt["flow_id"]
            cur.execute("SELECT flow_id FROM flows WHERE flow_id = ?", (fid,))
            if cur.fetchone():
                cur.execute(
                    """
                    UPDATE flows SET
                        last_seen  = :ts,
                        pkt_count  = pkt_count + 1,
                        byte_count = byte_count + :length
                    WHERE flow_id = :flow_id
                    """,
                    pkt,
                )
            else:
                cur.execute(
                    """
                    INSERT INTO flows
                        (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                         first_seen, last_seen, pkt_count, byte_count, country)
                    VALUES
                        (:flow_id, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                         :ts, :ts, 1, :length, :country)
                    """,
                    pkt,
                )

            con.commit()
            con.close()

        except Exception as exc:
            self.log(f"[db error] save_packet: {exc}")

    def log(self, msg: str):
        """Append a timestamped line to logs.txt."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{ts}] {msg}\n"
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass  # logging must never crash the pipeline

    # ─────────────────────────────────────────
    # Read path — aggregated stats for UI / AI
    # ─────────────────────────────────────────

    def get_recent_summary(self, minutes: int = 5) -> dict:
        """
        Return aggregated traffic statistics for the last N minutes.

        Returns
        -------
        dict with keys:
            window_minutes, total_packets, total_bytes,
            protocols, top_sources, top_destinations,
            top_ports, top_countries
        """
        since = datetime.now().timestamp() - (minutes * 60)

        try:
            con = sqlite3.connect(str(self.db_path))
            cur = con.cursor()

            def q(sql, *params):
                cur.execute(sql, params)
                return cur.fetchall()

            total_pkts  = q("SELECT COUNT(*) FROM packets WHERE ts >= ?", since)[0][0]
            total_bytes = q("SELECT SUM(length) FROM packets WHERE ts >= ?", since)[0][0] or 0

            protocols = dict(q(
                "SELECT protocol, COUNT(*) AS c FROM packets "
                "WHERE ts >= ? GROUP BY protocol ORDER BY c DESC LIMIT 10", since
            ))
            top_sources = dict(q(
                "SELECT src_ip, COUNT(*) AS c FROM packets "
                "WHERE ts >= ? GROUP BY src_ip ORDER BY c DESC LIMIT 10", since
            ))
            top_destinations = dict(q(
                "SELECT dst_ip, COUNT(*) AS c FROM packets "
                "WHERE ts >= ? GROUP BY dst_ip ORDER BY c DESC LIMIT 10", since
            ))
            top_ports = dict(q(
                "SELECT dst_port, COUNT(*) AS c FROM packets "
                "WHERE ts >= ? AND dst_port IS NOT NULL "
                "GROUP BY dst_port ORDER BY c DESC LIMIT 10", since
            ))
            top_countries = dict(q(
                "SELECT country, COUNT(*) AS c FROM packets "
                "WHERE ts >= ? AND country IS NOT NULL "
                "GROUP BY country ORDER BY c DESC LIMIT 5", since
            ))

            con.close()

        except Exception as exc:
            self.log(f"[db error] get_recent_summary: {exc}")
            return {
                "window_minutes":   minutes,
                "total_packets":    0,
                "total_bytes":      0,
                "protocols":        {},
                "top_sources":      {},
                "top_destinations": {},
                "top_ports":        {},
                "top_countries":    {},
            }

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

    def get_recent_packets(self, limit: int = 100, window_seconds: int = 300) -> list[dict]:
        """Return the most recent packets for the live feed in the UI."""
        since = datetime.now().timestamp() - window_seconds
        try:
            con = sqlite3.connect(str(self.db_path))
            cur = con.cursor()
            cur.execute(
                """
                SELECT ts, src_ip, dst_ip, src_port, dst_port, protocol, length
                FROM packets WHERE ts >= ?
                ORDER BY ts DESC LIMIT ?
                """,
                (since, limit),
            )
            rows = cur.fetchall()
            con.close()
            return [
                {
                    "time":     datetime.fromtimestamp(r[0]).strftime("%H:%M:%S"),
                    "src":      f"{r[1]}:{r[3]}" if r[3] else r[1],
                    "dst":      f"{r[2]}:{r[4]}" if r[4] else r[2],
                    "protocol": r[5],
                    "length":   r[6],
                }
                for r in rows
            ]
        except Exception:
            return []

    def get_recent_flows(self, limit: int = 20, window_seconds: int = 300) -> list[dict]:
        """Return the top flows for the UI."""
        since = datetime.now().timestamp() - window_seconds
        try:
            con = sqlite3.connect(str(self.db_path))
            cur = con.cursor()
            cur.execute(
                """
                SELECT src_ip, dst_ip, protocol, pkt_count, byte_count
                FROM flows WHERE last_seen >= ?
                ORDER BY pkt_count DESC LIMIT ?
                """,
                (since, limit),
            )
            rows = cur.fetchall()
            con.close()
            return [
                {
                    "src":      r[0],
                    "dst":      r[1],
                    "protocol": r[2],
                    "packets":  r[3],
                    "bytes_kb": round(r[4] / 1024, 1),
                }
                for r in rows
            ]
        except Exception:
            return []
