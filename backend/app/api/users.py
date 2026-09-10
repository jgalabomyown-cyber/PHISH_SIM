from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db import models, schemas
from app.core import security

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(security.get_current_user)):
    return user

@router.get("", response_model=list[schemas.UserOut])
def list_users(admin=Depends(security.admin_required), db: Session = Depends(get_db)):
    return db.query(models.User).all()

@router.post("", response_model=schemas.UserOut)
def create_user(payload: schemas.UserCreate,
                admin=Depends(security.admin_required),
                db: Session = Depends(get_db)):
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=security.hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user