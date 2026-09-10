from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db import models, schemas
from app.core import security

router = APIRouter(prefix="/scans", tags=["module1-offense"])

@router.post("", response_model=schemas.ScanResultOut)
def ingest(result: schemas.ScanResultIn,
           user=Depends(security.any_operator),
           db: Session = Depends(get_db)):
    obj = models.ScanResult(owner_id=user.id, **result.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

@router.get("", response_model=list[schemas.ScanResultOut])
def list_scans(user=Depends(security.any_operator), db: Session = Depends(get_db)):
    return db.query(models.ScanResult).filter_by(owner_id=user.id).all()

@router.patch("/{scan_id}/patched", response_model=schemas.ScanResultOut)
def mark_patched(scan_id: int, user=Depends(security.any_operator), db: Session = Depends(get_db)):
    scan = db.query(models.ScanResult).filter_by(id=scan_id, owner_id=user.id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan.status = "patched"          # Module 1 lifecycle: post-remediation re-test
    db.commit()
    db.refresh(scan)
    return scan