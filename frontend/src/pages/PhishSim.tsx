import { useState } from "react";
import CampaignBuilder from "../components/phish/CampaignBuilder";
import LiveTelemetry from "../components/phish/LiveTelemetry";

export default function PhishSim() {
  const [refreshKey, setRefreshKey] = useState(0);

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-gray-900 text-white px-6 py-4">
        <h1 className="text-lg font-bold">
          PHish_SIm <span className="text-gray-400 font-normal">— Social Engineering Suite</span>
        </h1>
      </header>
      <main className="py-6 space-y-8">
        <CampaignBuilder onCreated={() => setRefreshKey((k) => k + 1)} />
        <LiveTelemetry key={refreshKey} />
      </main>
    </div>
  );
}
