"""app/routers/agent_sync.py

Module 4.2: WebSocket ingestion channel for Termux/CLI scanner agents.

Auth: agent connects to  /ws/agent?token=<JWT>
  - JWT must be valid AND belong to a user with role pentester/admin.
  - The JWT claims also carry a dedicated 'scope=agent' flag (see below)
    so shell/CLI tokens can be distinguished from agent tokens if desired.

Protocol: JSON messages (scan_start / device_found / scan_complete / ping).
Results are written incrementally into NetworkScan + DiscoveredDevice.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import jwt as jose_jwt, JWTError

from app.core.config import settings
from app.database import SessionLocal
from app.models import User, Role, NetworkScan, DiscoveredDevice

router = APIRouter(tags=["module4-agent-sync"])


def _authenticate(token: str) -> User | None:
    """Validate JWT and return the owning user, or None."""
    if not token:
        return None
    try:
        payload = jose_jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
    except JWTError:
        return None
    username = payload.get("sub")
    if not username:
        return None
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=username, is_active=True).first()
        # Only operators may push scan data
        if user is None or user.role not in (Role.ADMIN, Role.PENTESTER):
            return None
        # Detach from session; we only need id/username downstream
        user_id, username = user.id, user.username
        return user_id
    finally:
        db.close()


def _json_error(code: str, detail: str) -> str:
    return json.dumps({"type": "error", "code": code, "detail": detail})


@router.websocket("/ws/agent")
async def agent_sync(ws: WebSocket):
    # ---- 1. Authentication (query param; also accept header fallback) ----
    token = ws.query_params.get("token") or ws.headers.get("authorization", "").removeprefix("Bearer ")
    user_id = _authenticate(token)
    if user_id is None:
        # Accept then close with policy violation so the client gets a clean signal
        await ws.accept()
        await ws.send_text(_json_error("auth_failed", "Invalid or missing agent token"))
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws.accept()
    await ws.send_text(json.dumps({
        "type": "connected",
        "agent_owner": user_id,
        "protocol": ["scan_start", "device_found", "scan_complete", "ping"],
    }))

    # Open a dedicated DB session for the lifetime of this socket.
    db = SessionLocal()
    active_scans: dict[int, int] = {}   # scan_id -> owner check cache
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(_json_error("bad_json", "Payload must be valid JSON"))
                continue

            mtype = msg.get("type")

            # ------------------------- scan_start -------------------------
            if mtype == "scan_start":
                subnet = (msg.get("target_subnet") or "").strip()
                scan_type = msg.get("scan_type", "subnet")
                if not subnet:
                    await ws.send_text(_json_error("missing_field", "target_subnet is required"))
                    continue

                scan = NetworkScan(
                    owner_id=user_id,
                    target_subnet=subnet,
                    scan_type=scan_type,
                    status="running",
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)
                active_scans[scan.id] = user_id
                await ws.send_text(json.dumps({
                    "type": "scan_started", "scan_id": scan.id,
                }))

            # ------------------------ device_found ------------------------
            elif mtype == "device_found":
                scan_id = msg.get("scan_id")
                device = msg.get("device") or {}
                if scan_id not in active_scans:
                    await ws.send_text(_json_error(
                        "unknown_scan", f"scan_id {scan_id} not started on this session"))
                    continue

                cves = device.get("matched_cves", []) or []
                db.add(DiscoveredDevice(
                    scan_id=scan_id,
                    ip_address=device.get("ip_address", "0.0.0.0"),
                    mac_address=device.get("mac_address"),
                    device_name=device.get("device_name"),
                    os_fingerprint=device.get("os_fingerprint"),
                    open_ports=device.get("open_ports", []),
                    matched_cves=cves,
                    remediation_status="Vulnerable" if cves else "Clean",
                ))
                # Incrementally bump the scan counters so the UI can poll live
                scan = db.query(NetworkScan).get(scan_id)
                scan.total_devices = (scan.total_devices or 0) + 1
                scan.total_vulnerabilities = (scan.total_vulnerabilities or 0) + len(cves)
                db.commit()
                await ws.send_text(json.dumps({
                    "type": "device_recorded",
                    "ip": device.get("ip_address"),
                    "vulnerable": bool(cves),
                }))

            # ------------------------ scan_complete -----------------------
            elif mtype == "scan_complete":
                scan_id = msg.get("scan_id")
                if scan_id not in active_scans:
                    await ws.send_text(_json_error("unknown_scan", f"scan_id {scan_id} not started on this session"))
                    continue
                scan = db.query(NetworkScan).get(scan_id)
                scan.status = "failed" if msg.get("error") else "completed"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
                active_scans.pop(scan_id, None)
                await ws.send_text(json.dumps({
                    "type": "scan_finalized", "scan_id": scan_id,
                    "status": scan.status,
                }))

            # ---------------------------- ping ----------------------------
            elif mtype == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))

            else:
                await ws.send_text(_json_error("unknown_type", f"Unsupported message type: {mtype}"))

    except WebSocketDisconnect:
        pass
    finally:
        # Any scans left open when the agent drops = mark failed so UI isn't stuck on "running"
        for scan_id in active_scans:
            scan = db.query(NetworkScan).get(scan_id)
            if scan and scan.status == "running":
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.close()