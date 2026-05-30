"""
sniffer.py  —  Stage 1: Raw Packet Capture
─────────────────────────────────────────────
Responsibility:
  • Capture raw packets from a live interface OR read a .pcap file
  • Hand each raw Scapy packet to the Parser via a callback / queue
  • Know nothing about parsing, detection, logging, or UI

Public API:
  Sniffer(iface, bpf_filter, count, on_packet)   — live capture
  Sniffer.from_pcap(path, on_packet)              — offline replay
  sniffer.start()  /  sniffer.stop()
"""

import warnings
import logging
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import threading
from pathlib import Path
from typing import Callable, Optional

# Scapy is imported lazily so the module can be imported without Scapy installed
# (useful for tests or environments that only run the web UI).


class Sniffer:
    """
    Thin wrapper around Scapy sniff / rdpcap.

    Parameters
    ----------
    iface      : network interface name (e.g. 'eth0', 'WiFi')
    bpf_filter : optional BPF filter string
    count      : stop after N packets; 0 = unlimited
    on_packet  : callback(raw_scapy_pkt) called for every captured packet
    """

    def __init__(
        self,
        iface: str = "WiFi",
        bpf_filter: str = "",
        count: int = 0,
        on_packet: Optional[Callable] = None,
    ):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count
        self.on_packet = on_packet or (lambda pkt: None)

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pkt_count = 0

    # ──────────────────────────────────────────────
    # Factory: offline pcap replay
    # ──────────────────────────────────────────────

    @classmethod
    def from_pcap(cls, path: str, on_packet: Callable) -> "Sniffer":
        """Return a Sniffer pre-configured to replay a .pcap file."""
        obj = cls(on_packet=on_packet)
        obj._pcap_path = Path(path)
        return obj

    # ──────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────

    def start(self):
        """Start capture in a background thread."""
        self._stop_event.clear()
        if hasattr(self, "_pcap_path"):
            self._thread = threading.Thread(target=self._replay, daemon=True)
        else:
            self._thread = threading.Thread(target=self._live, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the capture loop to stop."""
        self._stop_event.set()

    def join(self, timeout: Optional[float] = None):
        """Block until the capture thread finishes."""
        if self._thread:
            self._thread.join(timeout=timeout)

    @property
    def packet_count(self) -> int:
        return self._pkt_count

    # ──────────────────────────────────────────────
    # Internal capture loops
    # ──────────────────────────────────────────────

    def _handle(self, pkt):
        """Called by Scapy for each captured packet."""
        if self._stop_event.is_set():
            return
        try:
            self.on_packet(pkt)
            self._pkt_count += 1
        except Exception:
            pass  # never let a bad packet kill the loop

    def _live(self):
        from scapy.all import sniff, conf
        conf.verb = 0
        print(f"[Sniffer] Capturing on '{self.iface}'"
              + (f"  filter='{self.bpf_filter}'" if self.bpf_filter else ""),
              flush=True)
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter=self.bpf_filter,
                    prn=self._handle,
                    count=self.count or 0,
                    store=False,
                    promisc=True,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
                if self.count:       # finite count reached — done
                    break
            except KeyboardInterrupt:
                break
            except Exception as exc:
                print(f"[Sniffer] Socket error: {exc} — restarting", flush=True)
        print(f"[Sniffer] Stopped. {self._pkt_count} packets captured.", flush=True)

    def _replay(self):
        from scapy.all import rdpcap
        print(f"[Sniffer] Replaying {self._pcap_path}", flush=True)
        try:
            pkts = rdpcap(str(self._pcap_path))
            for pkt in pkts:
                if self._stop_event.is_set():
                    break
                self._handle(pkt)
        except Exception as exc:
            print(f"[Sniffer] Failed to read pcap: {exc}", flush=True)
        print(f"[Sniffer] Replay done. {self._pkt_count} packets.", flush=True)
