import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.database import Base, engine, SessionLocal
from app.db import models
from app.core.config import settings
from app.core import security
from app.api import auth, users, scans, agent_ws, web_shell
from app.routers import network_scanner
from app.routers import phish_sim
from app.api import web_shell
from app.api import payloads


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(settings.payload_dir, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(models.User).filter_by(username=settings.first_admin_username).first():
            db.add(models.User(
                username=settings.first_admin_username,
                email="admin@blackhole.local",
                hashed_password=security.hash_password(settings.first_admin_password),
                role=models.Role.ADMIN,
            ))
            db.commit()
    finally:
        db.close()
    yield

app = FastAPI(title="Blackhole", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scans.router)
app.include_router(agent_ws.router)
app.include_router(network_scanner.router)
app.include_router(web_shell.router)
app.include_router(phish_sim.router)
app.include_router(web_shell.router)
app.include_router(payloads.router)