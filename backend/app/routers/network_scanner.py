"""app/routers/network_scanner.py

Module 1.2 endpoints. Scanning is dispatched asynchronously via FastAPI
BackgroundTasks so the API returns immediately; swap launch_scan() internals
for Celery/RQ or agent dispatch without touching the routes.
"""
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import models, schemas
from app.db.database import engine, get_db
from app.core.security import get_current_user
from app.services import scanner

router = APIRouter(prefix="/api/scan", tags=["module1-network-scanner"])


# ---------- async dispatch layer (swap for Celery/agents later) ----------

def launch_scan(scan_id: int, subnet: str, db_url: str):
    """Runs in a background thread with its own DB session.
    Replace this body with a worker/agent dispatch when ready."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    WorkerSession = sessionmaker(bind=create_engine(db_url))
    db = WorkerSession()
    try:
        scan = db.query(models.NetworkScan).get(scan_id)
        scan.status = "running"
        db.commit()

        devices = asyncio.run(scanner.run_scan(subnet))

        total_vulns = 0
        for d in devices:
            db.add(models.DiscoveredDevice(
                scan_id=scan_id,
                ip_address=d.ip_address,
                mac_address=d.mac_address,
                device_name=d.device_name,
                os_fingerprint=d.os_fingerprint,
                open_ports=d.open_ports,
                matched_cves=d.matched_cves,
                remediation_status="Vulnerable" if d.matched_cves else "Clean",
            ))
            total_vulns += len(d.matched_cves)

        scan.total_devices = len(devices)
        scan.total_vulnerabilities = total_vulns
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        scan = db.query(models.NetworkScan).get(scan_id)
        scan.status = "failed"
        db.commit()
        raise
    finally:
        db.close()


# ------------------------------ endpoints ------------------------------

@router.post("/start", response_model=schemas.NetworkScanOut, status_code=202)
def start_scan(
    payload: schemas.NetworkScanCreate,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Trigger an async scan of a subnet. Returns 202 immediately with the
    scan record; poll GET /api/scan/history or /{scan_id} for results."""
    import ipaddress
    try:
        ipaddress.ip_network(payload.target_subnet, strict=False)
    except ValueError:
        raise HTTPException(422, "Invalid CIDR subnet, e.g. 192.168.1.0/24")

    scan = models.NetworkScan(
        owner_id=user.id,
        target_subnet=payload.target_subnet,
        scan_type=payload.scan_type,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background.add_task(launch_scan, scan.id, payload.target_subnet, str(engine.url))
    return scan


@router.get("/history", response_model=list[schemas.NetworkScanOut])
def scan_history(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.NetworkScan)
        .filter_by(owner_id=user.id)
        .order_by(models.NetworkScan.started_at.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=schemas.NetworkScanDetail)
def scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    scan = db.query(models.NetworkScan).filter_by(id=scan_id, owner_id=user.id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("/resolve/{device_id}", response_model=schemas.DeviceStatusOut)
def resolve_device(
    device_id: int,
    payload: schemas.DevicePatchRequest | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Lifecycle: change a device from 'Vulnerable' to 'Patched'
    (Module 1.2 post-remediation verification)."""
    device = (
        db.query(models.DiscoveredDevice)
        .join(models.NetworkScan)
        .filter(
            models.DiscoveredDevice.id == device_id,
            models.NetworkScan.owner_id == user.id,
        )
        .first()
    )
    if not device:
        raise HTTPException(404, "Device not found")

    device.remediation_status = "Patched"
    device.remediation_notes = payload.remediation_notes if payload else None
    device.patched_at = datetime.now(timezone.utc)
    device.patched_by_id = user.id
    db.commit()
    db.refresh(device)
    return device