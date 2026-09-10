from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from app.core.config import settings
from app.db.database import get_db
from app.db import models
import bcrypt

# Replaced passlib oauth string with modern bearer structure
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(p: str) -> str:
    """Hashes a plaintext password using native bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(p.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain: str, hashed: str) -> bool:
    """Verifies a plaintext password against a native bcrypt hash safely."""
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def create_access_token(sub: str, role: str) -> str:
    """Generates an authenticated JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode(
        {"sub": sub, "role": role, "exp": expire},
        settings.secret_key,
        algorithm=settings.algorithm
    )

from sqlalchemy.orm import Session

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    """Decodes a JWT string token, validates the signature, and fetches the logged-in User database object."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def admin_required(current_user: models.User = Depends(get_current_user)) -> models.User:
    """Validates that the currently authenticated user has administrative privileges."""
    if current_user.role != models.Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to perform this action"
        )
    return current_user

def any_operator(current_user: models.User = Depends(get_current_user)) -> models.User:
    """Validates that the currently authenticated user is part of the operations roster."""
    if current_user.role not in [models.Role.ADMIN, models.Role.PENTESTER, "admin", "pentester"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation roster authentication required to access this subsystem."
        )
    return current_user

def admin_required(current_user: models.User = Depends(get_current_user)) -> models.User:
    """Validates that the currently authenticated user has administrative privileges."""
    if current_user.role != models.Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to perform this action"
        )
    return current_user

