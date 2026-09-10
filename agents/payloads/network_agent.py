#!/usr/bin/env python3
"""agents/network_agent.py — Blackhole Termux/CLI scanner agent.

Connects to the Blackhole backend over WebSocket, runs a subnet sweep,
and streams results back in real time.

Usage (Termux or Kali):
    pip install websockets
    python network_agent.py --server ws://192.168.1.50:8000 \
        --token <agent_token> --cidr 192.168.1.0/24

Get an agent token from: GET /api/users/me/agent-token (requires login JWT)
"""
import argparse
import asyncio
import ipaddress
import json
import socket

import websockets

CONCURRENCY = 64
PORT_TIMEOUT = 0.3
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 8080]

# Minimal port -> CVE stub (Module 1.2). Swap for searchsploit/offline DB.
KNOWN_CVES = {
    445:  [{"cve": "CVE-2017-0144", "cvss": 8.1, "summary": "SMBv1 EternalBlue"}],
    3389: [{"cve": "CVE-2019-0708", "cvss": 9.8, "summary": "RDP BlueKeep"}],
}


def probe_port(ip: str, port: int, timeout: float = PORT_TIMEOUT) -> int | None:
    """Synchronous TCP connect probe (Termux-friendly; no scapy/root needed)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port
    except OSError:
        return None


def scan_host(ip: str) -> dict | None:
    open_ports = [p for p in (probe_port(ip, pt) for pt in TOP_PORTS) if p is not None]
    if not open_ports:
        return None
    cves = [c for p in open_ports for c in KNOWN_CVES.get(p, [])]
    return {
        "ip_address": ip,
        "open_ports": [{"port": p, "proto": "tcp", "service": ""} for p in open_ports],
        "matched_cves": cves,
    }


async def sweep(cidr: str, queue: asyncio.Queue):
    """Worker pool: push discovered devices into the queue as they're found."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts()) if network.num_addresses > 2 else [str(network.network_address)]
    sem = asyncio.Semaphore(CONCURRENCY)

    async def worker(ip):
        async with sem:
            # run sync scanner in a thread so the WS loop stays responsive
            result = await asyncio.get_running_loop().run_in_executor(None, scan_host, str(ip))
            if result:
                await queue.put(result)

    await asyncio.gather(*(worker(ip) for ip in hosts))
    await queue.put(None)  # sentinel: sweep finished


async def run(server: str, token: str, cidr: str):
    uri = f"{server.rstrip('/')}/ws/agent?token={token}"
    async with websockets.connect(uri, open_timeout=10) as ws:
        hello = json.loads(await ws.recv())
        if hello.get("type") == "error":
            print(f"[!] Auth rejected: {hello.get('detail')}")
            return
        print(f"[*] Connected as agent owner #{hello.get('agent_owner')}")

        # 1. announce the scan
        await ws.send(json.dumps({
            "type": "scan_start",
            "target_subnet": cidr,
            "scan_type": "subnet",
        }))

        # 2. kick off the sweep + read acks concurrently
        queue: asyncio.Queue = asyncio.Queue()
        sweep_task = asyncio.create_task(sweep(cidr, queue))
        scan_id = None

        async def reader():
            """Background reader: consumes server acks, captures scan_id."""
            nonlocal scan_id
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "scan_started":
                    scan_id = msg["scan_id"]
                    print(f"[*] Backend registered scan #{scan_id}")
                elif msg.get("type") == "device_recorded":
                    print(f"    [+] {msg.get('ip')} recorded "
                          f"({'VULNERABLE' if msg.get('vulnerable') else 'clean'})")
                elif msg.get("type") == "error":
                    print(f"[!] Server error: {msg.get('code')} — {msg.get('detail')}")

        reader_task = asyncio.create_task(reader())

        # 3. stream devices as they're discovered
        while True:
            device = await queue.get()
            if device is None:
                break
            if scan_id is None:          # wait for scan_started ack
                for _ in range(50):
                    if scan_id:
                        break
                    await asyncio.sleep(0.1)
            await ws.send(json.dumps({
                "type": "device_found",
                "scan_id": scan_id,
                "device": device,
            }))

        # 4. finalize
        await ws.send(json.dumps({
            "type": "scan_complete", "scan_id": scan_id, "error": None,
        }))
        await sweep_task
        reader_task.cancel()
        print("[*] Scan complete. Results visible in Blackhole UI under /api/scan/history.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Blackhole network scanner agent")
    p.add_argument("--server", required=True, help="e.g. ws://192.168.1.50:8000")
    p.add_argument("--token", required=True, help="agent token from /api/users/me/agent-token")
    p.add_argument("--cidr", default="192.168.1.0/24")
    args = p.parse_args()
    asyncio.run(run(args.server, args.token, args.cidr))