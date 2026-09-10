from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, status
from app.core import security
from app.db.database import SessionLocal
from app.db import models

router = APIRouter(tags=["module4-interface"])

ACTIVE_CONNECTIONS: dict[int, WebSocket] = {}

@router.websocket("/ws/agent")
async def agent_stream(ws: WebSocket):
    # Agents authenticate by passing their JWT as ?token=
    token = ws.query_params.get("token", "")
    try:
        payload = security.jwt.decode(token, security.settings.secret_key,
                                      algorithms=[security.settings.algorithm])
    except Exception:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await ws.accept()
    user_id = None
    db = SessionLocal()
    try:
        user = db.query(models.User).filter_by(username=payload.get("sub")).first()
        if not user:
            await ws.close()
            return
        user_id = user.id
        ACTIVE_CONNECTIONS[user_id] = ws
        while True:
            # Agent streams stdout/stderr JSON events: {"stream": "...", "data": "..."}
            msg = await ws.receive_json()
            if msg.get("type") == "scan_result":
                db.add(models.ScanResult(owner_id=user_id, scan_type=msg["scan_type"],
                                         target=msg.get("target"), findings=msg.get("findings", [])))
                db.commit()
            else:
                await ws.send_json({"ack": True})
    except WebSocketDisconnect:
        pass
    finally:
        ACTIVE_CONNECTIONS.pop(user_id, None)
        db.close()