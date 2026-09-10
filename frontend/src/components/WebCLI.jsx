import { useEffect, useRef, useState, useCallback } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";

const SHELL_WS_BASE =
  import.meta.env.VITE_SHELL_WS ?? "ws://localhost:8000";
const POLL_INTERVAL_MS = 1000;

export default function WebCLI() {
  const containerRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const wsRef = useRef(null);
  const [status, setStatus] = useState("connecting"); // connecting|ready|closed|error
  const [reconnectTick, setReconnectTick] = useState(0);

  const getToken = () => localStorage.getItem("blackhole_token") ?? "";

  // ---- connection lifecycle ----
  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'Cascadia Code', 'Fira Code', monospace",
      theme: {
        background: "#0a0a0f",
        foreground: "#e0e0e0",
        cursor: "#00ff9c",                 // Blackhole green
        selectionBackground: "#1e3a2f",
      },
      scrollback: 5000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const proto = location.protocol === "https:" ? "wss" : "ws";
    let ws = null;
    let disposed = false;

    const write = (s) => term.write(s);
    const writeErr = (s) => term.write(`\r\n\x1b[31m${s}\x1b[0m\r\n`);

    try {
      ws = new WebSocket(
        `${proto}://${SHELL_WS_BASE.replace(/^wss?:\/\//, "")}/ws/shell?token=${getToken()}`
      );
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;
    } catch {
      setStatus("error");
      writeErr("[Blackhole] Invalid WebSocket URL.");
    }

    if (ws) {
      ws.onopen = () => setStatus("ready");
      ws.onmessage = (ev) => {
        if (ev.data instanceof ArrayBuffer) {
          write(new TextDecoder().decode(ev.data));   // raw PTY bytes
        } else {
          try {
            const ctrl = JSON.parse(ev.data);
            if (ctrl.type === "ready") {
              setStatus("ready");
              write(`\x1b[32m[Blackhole] Shell session online (pid ${ctrl.pid}).\x1b[0m\r\n`);
            } else if (ctrl.type === "error") {
              writeErr(`[Blackhole] ${ctrl.detail ?? "error"}`);
              setStatus("error");
            }
          } catch { /* ignore non-JSON */ }
        }
      };
      ws.onclose = (ev) => {
        if (!disposed) {
          setStatus(ev.code === 1008 ? "error" : "closed");
          if (ev.code === 1008) {
            writeErr("[Blackhole] Authentication failed — token invalid or expired.");
          } else {
            writeErr("[Blackhole] Shell session ended.");
          }
        }
      };
      ws.onerror = () => { if (!disposed) setStatus("error"); };

      // Keystrokes -> PTY (no local echo; remote shell handles it)
      const dataSub = term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(new TextEncoder().encode(data));
        }
      });

      return () => {
        disposed = true;
        dataSub.dispose();
        ws.close();
        term.dispose();
      };
    }

    return () => { disposed = true; term.dispose(); };
  }, [reconnectTick]);

  // ---- resize sync: window + PTY winsize ----
  useEffect(() => {
    const onResize = () => {
      if (fitRef.current && termRef.current) {
        fitRef.current.fit();
        wsRef.current?.send(JSON.stringify({
          type: "resize", cols: termRef.current.cols, rows: termRef.current.rows,
        }));
      }
    };
    window.addEventListener("resize", onResize);
    const t = setTimeout(onResize, 300);   // settle layout after mount
    return () => { window.removeEventListener("resize", onResize); clearTimeout(t); };
  }, []);

  const handleReconnect = useCallback(() => {
    setStatus("connecting");
    setReconnectTick((t) => t + 1);   // remounts the terminal effect
  }, []);

  const statusColor = {
    connecting: "text-yellow-400", ready: "text-green-400",
    closed: "text-gray-400", error: "text-red-400",
  }[status];

  return (
    <div className="flex flex-col h-full bg-[#0a0a0f] rounded-lg overflow-hidden border border-gray-800">
      {/* Status bar */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border-b border-gray-800 text-xs">
        <span className="font-semibold text-gray-300">
          Blackhole Web CLI — <span className="text-gray-500">interactive PTY</span>
        </span>
        <span className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 ${statusColor}`}>
            <span className={`w-2 h-2 rounded-full ${
              status === "ready" ? "bg-green-400 animate-pulse" :
              status === "connecting" ? "bg-yellow-400 animate-pulse" :
              status === "error" ? "bg-red-500" : "bg-gray-500"
            }`} />
            {status}
          </span>
          {(status === "closed" || status === "error") && (
            <button onClick={handleReconnect}
              className="px-2 py-0.5 bg-blue-600 hover:bg-blue-700 text-white rounded">
              Reconnect
            </button>
          )}
        </span>
      </div>

      {/* Terminal viewport */}
      <div ref={containerRef} className="flex-1 p-2" style={{ minHeight: 0 }} />

      <p className="px-3 py-1 text-[10px] text-gray-600 border-t border-gray-800">
        Reverse shells: run listeners here (nc -lvnp), upgrade TTYs interactively.
      </p>
    </div>
  );
}