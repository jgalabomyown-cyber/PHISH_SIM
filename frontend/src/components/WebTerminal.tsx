import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";
import { WebShellClient } from "../utils/WebShellClient";

function getToken(): string {
  // Adjust to however you persist the JWT (context, localStorage, cookie)
  return localStorage.getItem("blackhole_token") ?? "";
}

export default function WebTerminal() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'Cascadia Code', 'Fira Code', monospace",
      theme: {
        background: "#0a0a0f",
        foreground: "#e0e0e0",
        cursor: "#00ff9c",        // Blackhole green
        selectionBackground: "#1e3a2f",
      },
      scrollback: 5000,
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(containerRef.current);
    fit.fit();

    const client = new WebShellClient();
    let disposed = false;

    client.connect(getToken(), {
      onData: (data) => term.write(data),
      onClose: () => term.write("\r\n\x1b[31m[Blackhole] Shell session ended.\x1b[0m\r\n"),
    }).then(() => {
      if (disposed) return;
      // Every keystroke goes straight to the PTY — no local echo needed,
      // the remote shell handles echoing/line editing.
      term.onData((data) => client.sendInput(data));
      client.resize(term.cols, term.rows);
    }).catch(() => {
      term.write("\r\n\x1b[31m[Blackhole] Failed to connect. Check auth token.\x1b[0m\r\n");
    });

    // Keep the PTY size synced with the browser window
    const onResize = () => {
      fit.fit();
      client.resize(term.cols, term.rows);
    };
    window.addEventListener("resize", onResize);

    return () => {
      disposed = true;
      window.removeEventListener("resize", onResize);
      client.disconnect();
      term.dispose();
    };
  }, []);

  return (
    <div
      ref={containerRef}
      style={{ width: "100%", height: "100%", padding: "8px", background: "#0a0a0f" }}
    />
  );
}