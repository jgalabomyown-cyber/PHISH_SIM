"""app/services/scanner.py

Modular scan engine. The API layer calls run_scan(); the implementation
is intentionally pluggable so it can later be replaced by:
  - Celery/RQ background workers (via enqueue)
  - Termux/native CLI agents streaming results over /ws/agent
  - Local subprocess wrappers (nmap, arp-scan, searchsploit)
"""
import asyncio
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Tune per deployment; a real worker would run these as nmap -sS -p- etc.
CONCURRENCY = 64
PING_TIMEOUT = 0.5
PORT_TIMEOUT = 0.3
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 8080]


@dataclass
class DiscoveredDeviceData:
    ip_address: str
    mac_address: str | None = None
    device_name: str | None = None
    os_fingerprint: str | None = None
    open_ports: list = field(default_factory=list)
    matched_cves: list = field(default_factory=list)


async def _probe_port(ip: str, port: int) -> int | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=PORT_TIMEOUT
        )
        writer.close()
        return port
    except (OSError, asyncio.TimeoutError):
        return None


async def _scan_host(ip: str) -> DiscoveredDeviceData | None:
    """ICMP-less liveness probe: any open port in TOP_PORTS means alive."""
    results = await asyncio.gather(*(_probe_port(ip, p) for p in TOP_PORTS))
    open_ports = [p for p in results if p is not None]
    if not open_ports:
        return None
    return DiscoveredDeviceData(
        ip_address=ip,
        open_ports=[{"port": p, "proto": "tcp", "service": ""} for p in open_ports],
    )


# --- CVE matching stub (Module 1.2) ---
# Later: load an offline CVE/Exploit-DB dictionary (e.g. searchsploit --json,
# or a version->CVE mapping table) and fingerprint banners instead of ports.
def match_cves(device: DiscoveredDeviceData) -> list:
    KNOWN = {
        445: [{"cve": "CVE-2017-0144", "cvss": 8.1, "summary": "SMBv1 EternalBlue"}],
        3389: [{"cve": "CVE-2019-0708", "cvss": 9.8, "summary": "RDP BlueKeep"}],
    }
    cves = []
    for p in device.open_ports:
        cves.extend(KNOWN.get(p["port"], []))
    return cves


async def run_scan(subnet: str) -> list[DiscoveredDeviceData]:
    """Sweep a CIDR. Pure-async so it can be awaited from a BackgroundTask,
    a worker, or an agent. Returns normalized device data."""
    network = ipaddress.ip_network(subnet, strict=False)
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def bounded(ip):
        async with semaphore:
            return await _scan_host(str(ip))

    hosts = [h for h in network.hosts()] if network.num_addresses > 2 else [network.network_address]
    results = await asyncio.gather(*(bounded(ip) for ip in hosts))
    devices = [d for d in results if d is not None]
    for d in devices:
        d.matched_cves = match_cves(d)
    return devices