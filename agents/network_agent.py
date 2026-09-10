#!/usr/bin/env python3
"""
agents/network_agent.py — Blackhole Local Network Scanner Agent

Runs natively on Kali Linux (full capability: ARP scan via scapy) or inside
Termux (fallback mode: ICMP/TCP liveness sweep, no root required).

Requirements:
    pip install websockets scapy

Usage:
    export BLACKHOLE_SERVER="ws://192.168.1.50:8000"
    export BLACKHOLE_TOKEN="<agent_token from GET /users/me/agent-token>"
    python3 network_agent.py --cidr 192.168.1.0/24

    Or all via flags:
    python3 network_agent.py --server ws://192.168.1.50:8000 \
        --token <JWT> --cidr 192.168.1.0/24

Auth: the JWT is attached to the WebSocket query string (?token=...) because
some minimal WS clients (including Termux-friendly ones) cannot set custom
handshake headers. The backend /ws/agent endpoint accepts both.
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import random
import socket
import sys
from dataclasses import dataclass, field

import websockets

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("blackhole-agent")

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
RECONNECT_BASE_DELAY = 2.0      # seconds; grows exponentially
RECONNECT_MAX_DELAY = 60.0
SCAN_CONCURRENCY = 128          # parallel port probes
PORT_TIMEOUT = 0.4              # seconds per port connect
BANNER_TIMEOUT = 1.0            # seconds to wait for a service banner
ARP_TIMEOUT = 2.0               # scapy ARP sweep timeout

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433,
             3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]

# Minimal offline CVE signature map (Module 1.2 stub).
# Replace with an offline searchsploit/CVE dictionary lookup later.
CVE_SIGNATURES = {
    21:   [{"cve": "CVE-2015-3306", "cvss": 10.0, "summary": "ProFTPD mod_copy RCE (verify version)"}],
    445:  [{"cve": "CVE-2017-0144", "cvss": 8.1, "summary": "SMBv1 EternalBlue (verify patch level)"}],
    3389: [{"cve": "CVE-2019-0708", "cvss": 9.8, "summary": "RDP BlueKeep (verify patch level)"}],
    6379: [{"cve": "CVE-2022-0543", "cvss": 10.0, "summary": "Redis Lua sandbox escape (verify version)"}],
    9200: [{"cve": "CVE-2015-1427", "cvss": 7.5, "summary": "Elasticsearch script injection (verify version)"}],
}


@dataclass
class DiscoveredDevice:
    """Normalized finding streamed to the backend."""
    ip_address: str
    mac_address: str | None = None
    device_name: str | None = None
    os_fingerprint: str | None = None
    open_ports: list = field(default_factory=list)
    matched_cves: list = field(default_factory=list)

    def to_payload(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "device_name": self.device_name,
            "os_fingerprint": self.os_fingerprint,
            "open_ports": self.open_ports,
            "matched_cves": self.matched_cves,
        }


# --------------------------------------------------------------------------
# Host discovery
# --------------------------------------------------------------------------
def arp_sweep(cidr: str) -> dict[str, str | None]:
    """
    Layer-2 ARP scan of the subnet. Requires root/CAP_NET_RAW on Linux.
    Returns {ip: mac}. MAC lookup also helps with device_name/OUI inference.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not installed — cannot ARP scan")
    log.info("ARP sweep of %s (raw sockets, requires root)…", cidr)
    net = ipaddress.ip_network(cidr, strict=False)
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
        timeout=ARP_TIMEOUT,
        verbose=0,
    )
    hosts = {}
    for snd, rcv in answered:
        hosts[rcv[ARP].psrc] = rcv[ARP].hwsrc
    return hosts


def ping_sweep(cidr: str) -> dict[str, None]:
    """
    Rootless fallback: async ICMP via /dev sockets is unreliable, so we probe
    TCP liveness on the port list instead (any open port == alive). Works on
    Termux and Kali alike. Returns {ip: None}.
    """
    log.info("TCP liveness sweep of %s (rootless fallback mode)…", cidr)
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = {}
    # Keep the address list sane for huge ranges
    if net.num_addresses > 65536:
        log.warning("Target range > /16 — truncated to first 65536 addresses")
        hosts_iter = list(net.hosts())[:65536]
    else:
        hosts_iter = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]

    async def probe(ip: str, sem: asyncio.Semaphore) -> str | None:
        async with sem:
            for port in (80, 22, 445):      # quick tri-probe for liveness
                try:
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=PORT_TIMEOUT)
                    w.close()
                    return ip
                except (OSError, asyncio.TimeoutError):
                    continue
        return None

    async def run() -> list[str | None]:
        sem = asyncio.Semaphore(SCAN_CONCURRENCY)
        return await asyncio.gather(*(probe(str(ip), sem) for ip in hosts_iter))

    for ip in filter(None, asyncio.run(run())):
        hosts[ip] = None
    return hosts


def discover_hosts(cidr: str) -> dict[str, str | None]:
    """ARP when we can (richer data), TCP sweep as fallback."""
    if SCAPY_AVAILABLE and os.geteuid() == 0:
        try:
            return arp_sweep(cidr)
        except Exception as exc:
            log.warning("ARP sweep failed (%s); falling back to TCP sweep", exc)
    elif SCAPY_AVAILABLE:
        log.warning("Not running as root — ARP scan unavailable, using TCP fallback "
                    "(sudo for full MAC/device resolution)")
    return ping_sweep(cidr)


# --------------------------------------------------------------------------
# Port scanning + banner grabbing
# --------------------------------------------------------------------------
async def probe_port(ip: str, port: int, sem: asyncio.Semaphore) -> dict | None:
    """Connect, then opportunistically read a banner for fingerprinting."""
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=PORT_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return None

        banner = ""
        try:
            # Many services (FTP, SMTP, SSH, HTTP servers) greet us first.
            raw = await asyncio.wait_for(reader.read(256), timeout=BANNER_TIMEOUT)
            banner = raw.decode(errors="replace").strip()
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        entry = {"port": port, "proto": "tcp", "service": "", "banner": banner[:256]}
        if banner:
            entry["service"] = banner.split("\n")[0][:64]
        return entry


def infer_os_banner(device: DiscoveredDevice) -> None:
    """Crude fingerprinting from captured banners (Module 1.3 groundwork)."""
    text = " ".join(p.get("banner", "") for p in device.open_ports).lower()
    if "windows" in text or "iis" in text:
        device.os_fingerprint = "Likely Windows"
    elif "ubuntu" in text:
        device.os_fingerprint = "Likely Ubuntu"
    elif "openssh" in text:
        device.os_fingerprint = "Linux/Unix (OpenSSH)"
    elif any("http" in p.get("banner", "").lower() for p in device.open_ports):
        device.os_fingerprint = "Unknown (HTTP server detected)"


def match_cves(device: DiscoveredDevice) -> list:
    """Signature stub — swap for an offline Exploit-DB lookup later."""
    cves = []
    for p in device.open_ports:
        for sig in CVE_SIGNATURES.get(p["port"], []):
            entry = dict(sig)
            entry["evidence_port"] = p["port"]
            entry["evidence_banner"] = p.get("banner", "")[:128]
            cves.append(entry)
    return cves


async def enumerate_device(ip: str, mac: str | None) -> DiscoveredDevice | None:
    """Full pass over one host: ports + banners + CVE matching."""
    sem = asyncio.Semaphore(SCAN_CONCURRENCY // 4)  # per-host fairness
    results = await asyncio.gather(*(probe_port(ip, port, sem) for port in TOP_PORTS))
    open_ports = [r for r in results if r is not None]
    if not open_ports:
        return None

    device = DiscoveredDevice(
        ip_address=ip,
        mac_address=mac,
        open_ports=open_ports,
    )
    infer_os_banner(device)
    device.device_name = reverse_dns(ip)
    device.matched_cves = match_cves(device)
    return device


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# --------------------------------------------------------------------------
# WebSocket communication
# --------------------------------------------------------------------------
class BlackholeAgent:
    def __init__(self, server: str, token: str, cidr: str):
        self.server = server.rstrip("/")
        self.token = token
        self.cidr = cidr

    def _uri(self) -> str:
        return f"{self.server}/ws/agent?token={self.token}"

    async def send_scan(self, ws, payload: dict) -> None:
        await ws.send(json.dumps(payload))

    async def read_acks(self, ws, results: dict) -> None:
        """Background reader: consumes server acks while we stream devices."""
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            mtype = msg.get("type")
            if mtype == "scan_started":
                results["scan_id"] = msg["scan_id"]
                log.info("Backend registered scan #%s", msg["scan_id"])
            elif mtype == "device_recorded":
                log.info("  [+] %s recorded (%s)", msg.get("ip"),
                         "VULNERABLE" if msg.get("vulnerable") else "clean")
            elif mtype == "error":
                log.error("Server: %s — %s", msg.get("code"), msg.get("detail"))
                if msg.get("code") == "auth_failed":
                    results["fatal"] = True

    async def run_scan_once(self) -> None:
        """One full connect -> scan -> stream -> finalize cycle."""
        log.info("Connecting to %s …", self.server)

        async with websockets.connect(
            self._uri(),
            open_timeout=10,
            ping_interval=20,       # keep-alive pings both directions
            ping_timeout=20,
            max_size=8 * 1024 * 1024,
        ) as ws:

            hello = json.loads(await ws.recv())
            if hello.get("type") == "error":
                raise PermissionError(hello.get("detail", "auth rejected"))
            log.info("Authenticated as agent owner #%s", hello.get("agent_owner"))

            # Announce the scan and wait for the backend scan_id
            await self.send_scan(ws, {
                "type": "scan_start",
                "target_subnet": self.cidr,
                "scan_type": "subnet",
            })
            acks: dict = {}
            reader_task = asyncio.create_task(self.read_acks(ws, acks))

            for _ in range(100):            # up to 10s waiting for scan_started
                if acks.get("scan_id") or acks.get("fatal"):
                    break
                await asyncio.sleep(0.1)
            if acks.get("fatal"):
                raise PermissionError("token rejected by backend")
            scan_id = acks.get("scan_id")
            if scan_id is None:
                raise ConnectionError("backend never confirmed scan_start")

            # ---- discovery ----
            log.info("Discovering live hosts in %s …", self.cidr)
            live_hosts = discover_hosts(self.cidr)
            log.info("Found %d live host(s)", len(live_hosts))

            # ---- per-host enumeration + streaming ----
            sem = asyncio.Semaphore(SCAN_CONCURRENCY // 4)

            async def handle(ip: str, mac: str | None) -> None:
                async with sem:
                    device = await enumerate_device(ip, mac)
                    if device is None:
                        return
                    await self.send_scan(ws, {
                        "type": "device_found",
                        "scan_id": scan_id,
                        "device": device.to_payload(),
                    })

            await asyncio.gather(*(handle(ip, mac) for ip, mac in live_hosts.items()))

            # ---- finalize ----
            await self.send_scan(ws, {
                "type": "scan_complete", "scan_id": scan_id, "error": None,
            })
            # Give the server a moment to ack finalization before closing
            await asyncio.sleep(1)
            reader_task.cancel()
            log.info("Scan #%s complete — results in Blackhole UI.", scan_id)

    async def run_forever(self) -> None:
        """Resilience loop: exponential backoff reconnect on any failure."""
        delay = RECONNECT_BASE_DELAY
        while True:
            try:
                await self.run_scan_once()
                delay = RECONNECT_BASE_DELAY       # reset after success
                log.info("Sleeping 5s before next scheduled run (Ctrl+C to quit)…")
                await asyncio.sleep(5)
            except PermissionError as exc:
                log.error("FATAL auth problem: %s — not retrying. Mint a new "
                          "agent token via /users/me/agent-token.", exc)
                sys.exit(2)
            except (websockets.exceptions.ConnectionClosed,
                    websockets.exceptions.InvalidURI,
                    ConnectionError, OSError) as exc:
                log.warning("Connection lost: %s — reconnecting in %.0fs", exc, delay)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("Scan cycle failed: %r — retrying in %.0fs", exc, delay)

            await asyncio.sleep(delay + random.uniform(0, 1))   # jitter
            delay = min(delay * 2, RECONNECT_MAX_DELAY)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Blackhole Local Network Scanner Agent")
    p.add_argument("--server", default=os.environ.get("BLACKHOLE_SERVER"),
                   help="Backend WS URL, e.g. ws://192.168.1.50:8000")
    p.add_argument("--token", default=os.environ.get("BLACKHOLE_TOKEN"),
                   help="Agent JWT from GET /users/me/agent-token")
    p.add_argument("--cidr", default=os.environ.get("BLACKHOLE_CIDR", "192.168.1.0/24"),
                   help="Target subnet in CIDR notation")
    args = p.parse_args()

    missing = [k for k, v in {
        "server": args.server, "token": args.token, "cidr": args.cidr
    }.items() if not v]
    if missing:
        p.error(f"missing required: {', '.join('--' + m for m in missing)} "
                f"(or env vars BLACKHOLE_{m.upper()}S)")
    return args


def main() -> None:
    args = parse_args()
    if SCAPY_AVAILABLE and os.geteuid() != 0:
        log.info("Running without root — ARP disabled, using TCP liveness fallback.")
    if not SCAPY_AVAILABLE:
        log.info("scapy not installed — pip install scapy for ARP/MAC resolution.")

    agent = BlackholeAgent(args.server, args.token, args.cidr)
    try:
        asyncio.run(agent.run_forever())
    except KeyboardInterrupt:
        log.info("Agent stopped by operator.")


if __name__ == "__main__":
    main()
