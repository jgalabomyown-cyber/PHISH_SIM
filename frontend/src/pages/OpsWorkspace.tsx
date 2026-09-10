// frontend/src/pages/OpsWorkspace.tsx
import WebTerminal from "../components/WebTerminal";

export default function OpsWorkspace() {
  return (
    <div style={{ display: "flex", height: "100vh" }}>
      <div style={{ flex: 1, borderRight: "1px solid #222" }}>
        {/* Exploitation documentation / notes pane */}
        <h3 style={{ color: "#00ff9c", padding: 12 }}>Engagement Notes</h3>
      </div>
      <div style={{ flex: 1 }}>
        <WebTerminal />
      </div>
    </div>
  );
}