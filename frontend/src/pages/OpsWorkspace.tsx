import { useState } from "react";
import WebCLI from "../components/WebCLI";

export default function OpsWorkspace() {
  const [doc, setDoc] = useState(
    "# Engagement Notes\n\n## Targets\n- [ ] 192.168.1.42 — SMB (445)\n- [ ] 192.168.1.50 — RDP (3389)\n\n## Commands tried\n```\nnmap -sS -p- 192.168.1.0/24\n```\n"
  );

  return (
    <div className="h-screen flex flex-col bg-gray-950">
      <header className="px-6 py-3 bg-gray-900 border-b border-gray-800">
        <h1 className="text-white font-bold">
          Blackhole Ops <span className="text-gray-500 font-normal">— Interactive Workspace</span>
        </h1>
      </header>
      <div className="flex flex-1 min-h-0">
        {/* Left: exploitation documentation */}
        <div className="w-1/2 border-r border-gray-800 flex flex-col">
          <div className="px-4 py-2 bg-gray-900 text-xs text-gray-400 border-b border-gray-800">
            Engagement Notes (Markdown)
          </div>
          <textarea
            value={doc}
            onChange={(e) => setDoc(e.target.value)}
            className="flex-1 p-4 bg-gray-950 text-green-200 font-mono text-xs resize-none outline-none"
            spellCheck={false}
          />
        </div>
        {/* Right: live Web CLI */}
        <div className="w-1/2 p-3">
          <WebCLI />
        </div>
      </div>
    </div>
  );
}