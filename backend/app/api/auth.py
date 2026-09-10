from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db import models, schemas
from app.core import security

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login", response_model=schemas.Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(username=form.username).first()
    if not user or not security.verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Incorrect username or password")
    return schemas.Token(access_token=security.create_access_token(user.username, user.role.value))

@router.post("/register", response_model=schemas.UserOut)
def register(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    # Self-registration is pentester-only; admins created by bootstrap or admin API
    if payload.role == models.Role.ADMIN:
        raise HTTPException(403, "Cannot self-register as admin")
    if db.query(models.User).filter(
        (models.User.username == payload.username) | (models.User.email == payload.email)
    ).first():
        raise HTTPException(409, "Username or email already exists")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=security.hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user