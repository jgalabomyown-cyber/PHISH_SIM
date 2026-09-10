import asyncio, fcntl, os, pty, select, struct, termios
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from app.core import security

router = APIRouter(tags=["module4-interface"])

SHELL = os.environ.get("BLACKHOLE_SHELL", "/bin/bash")

@router.websocket("/ws/shell")
async def web_shell(ws: WebSocket):
    # Same JWT auth scheme as agents: /ws/shell?token=<JWT>
    token = ws.query_params.get("token", "")
    try:
        payload = security.jwt.decode(
            token, security.settings.secret_key,
            algorithms=[security.settings.algorithm],
        )
    except Exception:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await ws.accept()

    master_fd, slave_fd = pty.openpty()
    proc = await asyncio.create_subprocess_exec(
        SHELL, "-i",
        preexec_fn=os.setsid,
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        cwd=os.environ.get("BLACKHOLE_SHELL_CWD", "/home/operator"),
    )
    os.close(slave_fd)  # child owns it now

    loop = asyncio.get_running_loop()

    async def pty_to_ws():
        """Forward shell output -> browser."""
        loop = asyncio.get_running_loop()
        while proc.returncode is None:
            await loop.run_in_executor(None, lambda: select.select([master_fd], [], [], 0.5))
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            await ws.send_bytes(data)
        await ws.close()

    async def ws_to_pty():
        """Forward browser input -> shell, plus handle resize."""
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            if "bytes" in msg and msg["bytes"]:
                os.write(master_fd, msg["bytes"])
            elif "text" in msg and msg["text"]:
                # Control channel: {"type":"resize","cols":80,"rows":24}
                import json
                data = json.loads(msg["text"])
                if data.get("type") == "resize":
                    winsize = struct.pack("HHHH", data["rows"], data["cols"], 0, 0)
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

    to_ws = asyncio.create_task(pty_to_ws())
    try:
        await ws_to_pty()
    except WebSocketDisconnect:
        pass
    finally:
        to_ws.cancel()
        proc.kill()
        await proc.wait()
        os.close(master_fd)