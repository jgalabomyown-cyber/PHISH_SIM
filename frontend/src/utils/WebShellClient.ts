export class WebShellClient {
  private ws: WebSocket | null = null;

  connect(token: string, handlers: {
    onData: (data: string) => void;
    onClose: () => void;
  }): Promise<void> {
    return new Promise((resolve, reject) => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      this.ws = new WebSocket(`${proto}://${location.host.replace(":3000", ":8000")}/ws/shell?token=${token}`);

      this.ws.binaryType = "arraybuffer";

      this.ws.onopen = () => resolve();
      this.ws.onerror = () => reject(new Error("Shell connection failed"));
      this.ws.onmessage = (ev) => handlers.onData(
        ev.data instanceof ArrayBuffer ? new TextDecoder().decode(ev.data) : ev.data
      );
      this.ws.onclose = handlers.onClose;
    });
  }

  /** Raw keystrokes -> PTY stdin */
  sendInput(data: string): void {
    this.ws?.send(new TextEncoder().encode(data));
  }

  /** xterm.js resize events -> TIOCSWINSZ on the PTY */
  resize(cols: number, rows: number): void {
    this.ws?.send(JSON.stringify({ type: "resize", cols, rows }));
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
  }
}