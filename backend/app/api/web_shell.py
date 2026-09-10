"""app/api/web_shell.py

Module 4.1: Embedded Web CLI — WebSocket-driven interactive PTY.

Auth:     ws://host:8000/ws/shell?token=<JWT>   (same token scheme as agents)
Transport: binary frames = raw terminal bytes (stdin/stdout)
           text frames  = JSON control messages, e.g. {"type":"resize",...}

Each WebSocket gets its own PTY + child shell, tracked in SHELL_SESSIONS so
operators can be audited and sessions can be reaped on disconnect.
"""
import asyncio
import fcntl
import json
import os
import pty
import select
import signal
import struct
import termios
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import jwt as jose_jwt, JWTError

from app.core.config import settings
from app.database import SessionLocal
from app.models import User, Role

router = APIRouter(tags=["module4-web-cli"])

SHELL = os.environ.get("BLACKHOLE_SHELL", "/bin/bash")
SHELL_CWD = os.environ.get("BLACKHOLE_SHELL_CWD", "/home/operator")
READ_CHUNK = 4096
SELECT_TIMEOUT = 0.5

# In-memory session registry (operator id -> active sessions) for audit/reaping
SHELL_SESSIONS: dict[int, list[dict]] = {}


def _authenticate(token: str) -> int | None:
    """Validate JWT; only admin/pentester operators may open a shell."""
    if not token:
        return None
    try:
        payload = jose_jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        username = payload.get("sub")
 |      if not username:
            return None
    except JWTError:
        return None
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username=username, is_active=True).first()
        if not user or user.role not in (Role.ADMIN, Role.PENTESTER):
            return None
        return user.id
    finally:
        db.close()


def _register_session(user_id: int, info: dict) -> None:
    SHELL_SESSIONS.setdefault(user_id, []).append(info)

def _unregister_session(user_id: int, info: dict) -> None:
    sessions = SHELL_SESSIONS.get(user_id, [])
    if info in sessions:
        sessions.remove(info)


@router.websocket("/ws/shell")
async def web_shell(ws: WebSocket):
    # ---------- 1. Auth handshake ----------
    token = (ws.query_params.get("token")
             or ws.headers.get("authorization", "").removeprefix("Bearer "))
    user_id = _authenticate(token)
    await ws.accept()
    if user_id is None:
        await ws.send_text(json.dumps({"type": "error", "detail": "auth failed"}))
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # ---------- 2. Spawn interactive shell on a PTY ----------
    master_fd, slave_fd = pty.openpty()
    proc = await asyncio.create_subprocess_exec(
        SHELL, "-i",
        preexec_fn=os.setsid,                 # new session -> controllable TTY
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        cwd=SHELL_CWD,
        env={**os.environ, "TERM": "xterm-256color"},
    )
    os.close(slave_fd)                        # child owns its end now

    session_info = {"pid": proc.pid, "started": datetime.now(timezone.utc).isoformat()}
    _register_session(user_id, session_info)
    await ws.send_text(json.dumps({
        "type": "ready", "pid": proc.pid, "shell": SHELL,
    }))

    loop = asyncio.get_running_loop()

    # ---------- 3. PTY stdout -> browser (binary frames) ----------
    async def pty_to_ws():
        while proc.returncode is None:
            ready, _, _ = await loop.run_in_executor(
                None, lambda: select.select([master_fd], [], [], SELECT_TIMEOUT)
            )
            if not ready:
                continue
            try:
                data = os.read(master_fd, READ_CHUNK)
            except OSError:                   # EOF — shell exited
                break
            if not data:
                break
            await ws.send_bytes(data)

    # ---------- 4. Browser -> PTY stdin (input + control) ----------
    async def ws_to_pty():
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            if msg.get("bytes"):
                os.write(master_fd, msg["bytes"])
            elif msg.get("text"):
                try:
                    ctrl = json.loads(msg["text"])
                except json.JSONDecodeError:
                    continue
                if ctrl.get("type") == "resize":
                    # Sync PTY winsize so vim/htop/nmap render correctly
                    winsize = struct.pack("HHHH",
                                          int(ctrl.get("rows", 24)),
                                          int(ctrl.get("cols", 80)), 0, 0)
                    try:
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                        os.kill(proc.pid, signal.SIGWINCH)
                    except (OSError, ProcessLookupError):
                        pass
                elif ctrl.get("type") == "signal":
                    # Optional: forward ^C-style signals explicitly
                    sig = {"SIGINT": signal.SIGINT, "SIGTERM": signal.SIGTERM}.get(
                        ctrl.get("name"))
                    if sig:
                        try:
                            os.kill(proc.pid, sig)
                        except ProcessLookupError:
                            pass

    # ---------- 5. Run both directions, clean up on exit ----------
    out_task = asyncio.create_task(pty_to_ws())
    try:
        await ws_to_pty()
    except WebSocketDisconnect:
        pass
    finally:
        out_task.cancel()
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        os.close(master_fd)
        _unregister_session(user_id, session_info)
        try:
            await ws.close()
        except RuntimeError:
            pass


@router.get("/shell/sessions")
async def list_sessions(user_id: int = None):
    """Ops dashboard: who has live shells open (audit view)."""
    return {"sessions": {uid: info for uid, info in SHELL_SESSIONS.items()}}