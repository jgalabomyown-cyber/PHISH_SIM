import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../utils/api";

interface CampaignSummary {
  id: number;
  name: string;
  engagement_ref?: string | null;
  status: string;
  tracker_id?: string | null;
  redirect_after?: string | null;
  target_count: number;
  total_clicks: number;
  total_captures: number;
  created_at?: string | null;
}

interface Telemetry {
  id: number;
  campaign_id: number;
  target_email?: string | null;
  public_ip?: string | null;
  private_ip?: string | null;
  geo_country?: string | null;
  geo_city?: string | null;
  browser?: string | null;
  os_name?: string | null;
  device_name?: string | null;
  click_timestamp?: string | null;
  captured_input?: string | null;
  captured_at?: string | null;
}

const POLL_INTERVAL_MS = 5000;

const statusBadge: Record<string, string> = {
  draft: "bg-gray-100 text-gray-700",
  running: "bg-green-100 text-green-700",
  completed: "bg-blue-100 text-blue-700",
  public: "bg-green-100 text-green-700",
};

function parseCaptured(json: string | null): { username?: string } {
  if (!json) return {};
  try {
    const obj = JSON.parse(json);
    return { username: obj.username };
  } catch {
    return {};
  }
}

export default function LiveTelemetry() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [telemetry, setTelemetry] = useState<Telemetry[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadCampaigns = useCallback(async () => {
    try {
      setCampaigns(await apiFetch<CampaignSummary[]>("/api/phish/campaigns"));
ecam    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load campaigns");
    }
  }, []);

  const loadTelemetry = useCallback(async (campaignId: number) => {
    try {
      setTelemetry(
        await apiFetch<Telemetry[]>(`/api/phish/campaigns/${campaignId}/telemetry`)
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load telemetry");
    }
  }, []);

  // Campaign list: initial load only
  useEffect(() => { loadCampaigns(); }, [loadCampaigns]);

  // Telemetry: poll live while a campaign is selected
  useEffect(() => {
    if (selected === null) return;
    loadTelemetry(selected);
    const t = setInterval(() => loadTelemetry(selected), POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, [selected, loadTelemetry]);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <h2 className="text-xl font-bold">PHish_SIm — Live Telemetry</h2>
      {error && <div className="p-3 bg-red-100 text-red-800 rounded">{error}</div>}

      {/* Campaign summary table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-3">Campaign</th>
              <th className="px-4 py-3">Engagement ref</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Targets</th>
              <th className="px-4 py-3">Clicks</th>
              <th className="px-4 py-3">Captures</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {campaigns.map((c) => (
              <tr key={c.id}
                  className={`border-t ${selected === c.id ? "bg-blue-50" : ""}`}>
                <td className="px-4 py-3 font-medium">{c.name}</td>
                <td className="px-4 py-3 text-gray-500">{c.engagement_ref ?? "—"}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs ${statusBadge[c.status] ?? "bg-gray-100"}`}>
                    {c.status}
                  </span>
                </td>
                <td className="px-4 py-3">{c.target_count}</td>
                <td className="px-4 py-3">{c.total_clicks}</td>
                <td className="px-4 py-3">
                  <span className={c.total_captures > 0 ? "text-red-600 font-semibold" : ""}>
                    {c.total_captures}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  <button onClick={() => setSelected(selected === c.id ? null : c.id)}
                    className="px-3 py-1 text-blue-600 hover:bg-blue-100 rounded text-xs">
                    {selected === c.id ? "Hide telemetry" : "View telemetry"}
                  </button>
                </td>
              </tr>
            ))}
            {campaigns.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-6 text-center text-gray-400">
                No campaigns yet — create one above.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Live telemetry detail */}
      {selected !== null && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b flex items-center justify-between">
            <h3 className="font-semibold text-sm">
              Target interaction profiles — Campaign #{selected}
            </h3>
            <span className="text-xs text-gray-400">
              auto-refreshing every {POLL_INTERVAL_MS / 1000}s
            </span>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Public IP</th>
                <th className="px-4 py-3">Private IP</th>
                <th className="px-4 py-3">Geo</th>
                <th className="px-4 py-3">Browser / OS</th>
                <th className="px-4 py-3">Device</th>
                <th className="px-4 py-3">Captured</th>
              </tr>
            </thead>
            <tbody>
              {telemetry.map((t) => {
                const creds = parseCaptured(t.captured_input);
                return (
                  <tr key={t.id} className="border-t">
                    <td className="px-4 py-3 whitespace-nowrap">
                      {t.click_timestamp
                        ? new Date(t.click_timestamp).toLocaleString()
                        : "—"}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{t.public_ip ?? "—"}</td>
                    <td className="px-4 py-3 font-mono text-xs">{t.private_ip ?? "—"}</td>
                    <td className="px-4 py-3 text-xs">
                      {[t.geo_city, t.geo_country].filter(Boolean).join(", ") || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {[t.browser, t.os_name].filter(Boolean).join(" / ") || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs">{t.device_name ?? "—"}</td>
                    <td className="px-4 py-3 text-xs">
                      {t.captured_input ? (
                        <span className="text-red-600 font-semibold">
                          ✓ {creds.username ?? "credentials captured"}
                        </span>
                      ) : (
                        <span className="text-gray-400">click only</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {telemetry.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-6 text-center text-gray-400">
                  No clicks recorded yet for this campaign.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
