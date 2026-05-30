from rich.console import Console
from rich.table import Table
from collections import defaultdict
import time

console = Console()
ip_counts = defaultdict(int)

def update_ui():
    console.clear()
    
    table = Table(title="📡 Network Traffic Monitor")
    table.add_column("IP Address", justify="left")
    table.add_column("Packets", justify="right")
    
    # Sort by highest traffic
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    
    for ip, count in sorted_ips[:10]:
        table.add_row(ip, str(count))
    
    console.print(table)

# Simulated packet processing (replace with your sniffer)
def process_packet(src, dst):
    ip_counts[src] += 1
    ip_counts[dst] += 1

# Demo loop (replace with real sniffing)
while True:
    # simulate traffic
    process_packet("172.16.43.127", "8.8.8.8")
    process_packet("172.16.44.136", "1.1.1.1")
    
    update_ui()
    time.sleep(1)