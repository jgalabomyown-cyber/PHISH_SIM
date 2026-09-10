import { useState } from "react";
import { apiFetch } from "../../utils/api";

interface Target {
  email: string;
  first_name?: string;
  last_name?: string;
}

interface SMTPConfig {
  host: string;
  port: number;
  username: string;
  password: string;
  from_display: string;
}

interface CampaignCreate {
  name: string;
  description?: string;
  engagement_ref?: string;
  targets: Target[];
  smtp: SMTPConfig;
  subject: string;
  body_html: string;
  landing_title: string;
  redirect_after?: string;
  dispatch: boolean;
}

const initialForm: CampaignCreate = {
  name: "",
  description: "",
  engagement_ref: "",
  targets: [{ email: "" }],
  smtp: { host: "", port: 587, username: "", password: "", from_display: "" },
  subject: "",
  body_html: `<html><body>
<p>Hi {first_name},</p>
<p>We've detected unusual sign-in activity on your account. Please verify your
credentials immediately to prevent suspension.</p>
<p><a href="{tracker_url}">Verify my account now</a></p>
<p>— IT Security Team</p>
</body></html>`,
  landing_title: "Sign in to continue",
  redirect_after: "",
  dispatch: true,
};

export default function CampaignBuilder({ onCreated }: { onCreated: () => void }) {
  const [form, setForm] = useState<CampaignCreate>(initialForm);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const set = <K extends keyof CampaignCreate>(key: K, value: CampaignCreate[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const setTarget = (idx: number, key: "email" | "first_name" | "last_name", value: string) =>
    setForm((f) => {
      const targets = [...f.targets];
      targets[idx] = { ...targets[idx], [key]: value };
      return { ...f, targets };
    });

  const addTarget = () => setForm((f) => ({ ...f, targets: [...f.targets, { email: "" }] }));
  const removeTarget = (idx: number) =>
    setForm((f) => ({ ...f, targets: f.targets.filter((_, i) => i !== idx) }));

  const setSMTP = (key: keyof SMTPConfig, value: string | number) =>
    setForm((f) => ({ ...f, smtp: { ...f.smtp, [key]: value } }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus(null);
    setError(null);
    try {
      const created = await apiFetch<{ id: number; name: string }>("/api/phish/campaign", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setStatus(`Campaign #${created.id} (${created.name}) created successfully.`);
      setForm(initialForm);
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-6 bg-white rounded-lg shadow space-y-4">
      <h2 className="text-xl font-bold">PHish_SIm — New Campaign</h2>

      {status && <div className="p-3 bg-green-100 text-green-800 rounded">{status}</div>}
      {error && <div className="p-3 bg-red-100 text-red-800 rounded">{error}</div>}

      <form onSubmit={submit} className="space-y-4">
        {/* Engagement metadata */}
        <div className="grid grid-cols-2 gap-4">
          <label className="block">
            <span className="text-sm font-medium">Campaign name *</span>
            <input required className="w-full mt-1 p-2 border rounded" value={form.name}
              onChange={(e) => set("name", e.target.value)} />
          </label>
          <label className="block">
            <span className="text-sm font-medium">Engagement ref (RoE)</span>
            <input className="w-full mt-1 p-2 border rounded" value={form.engagement_ref}
              onChange={(e) => set("engagement_ref", e.target.value)} />
          </label>
        </div>

        {/* SMTP relay config */}
        <fieldset className="p-4 border rounded space-y-3">
          <legend className="text-sm font-bold px-1">SMTP relay (app-specific password)</legend>
          <div className="grid grid-cols-3 gap-3">
            <label className="block">
              <span className="text-xs">Host *</span>
              <input required className="w-full mt-1 p-2 border rounded" value={form.smtp.host}
                onChange={(e) => setSMTP("host", e.target.value)} />
            </label>
            <label className="block">
              <span className="text-xs">Port</span>
              <input type="number" className="w-full mt-1 p-2 border rounded"
                value={form.smtp.port} onChange={(e) => setSMTP("port", +e.target.value)} />
            </label>
            <label className="block">
              <span className="text-xs">From display *</span>
              <input required placeholder="IT Helpdesk <it@corp.example>"
                className="w-full mt-1 p-2 border rounded" value={form.smtp.from_display}
                onChange={(e) => setSMTP("from_display", e.target.value)} />
            </label>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs">SMTP username *</span>
              <input required className="w-full mt-1 p-2 border rounded" value={form.smtp.username}
                onChange={(e) => setSMTP("username", e.target.value)} />
            </label>
            <label className="block">
              <span className="text-xs">App-specific password *</span>
              <input required type="password" className="w-full mt-1 p-2 border rounded"
                value={form.smtp.password} onChange={(e) => setSMTP("password", e.target.value)} />
            </label>
          </div>
        </fieldset>

        {/* Targets */}
        <fieldset className="p-4 border rounded space-y-2">
          <legend className="text-sm font-bold px-1">Targets</legend>
          {form.targets.map((t, idx) => (
            <div key={idx} className="flex gap-2 items-end">
              <label className="flex-1">
                <span className="text-xs">Email *</span>
                <input required type="email" className="w-full mt-1 p-2 border rounded"
                  value={t.email} onChange={(e) => setTarget(idx, "email", e.target.value)} />
              </label>
              <label className="w-32">
                <span className="text-xs">First name</span>
                <input className="w-full mt-1 p-2 border rounded" value={t.first_name ?? ""}
                  onChange={(e) => setTarget(idx, "first_name", e.target.value)} />
              </label>
              <label className="w-32">
                <span className="text-xs">Last name</span>
                <input className="w-full mt-1 p-2 border rounded" value={t.last_name ?? ""}
                  onChange={(e) => setTarget(idx, "last_name", e.target.value)} />
              </label>
              {form.targets.length > 1 && (
                <button type="button" onClick={() => removeTarget(idx)}
                  className="p-2 text-red-600 hover:bg-red-50 rounded">Remove</button>
              )}
            </div>
          ))}
          <button type="button" onClick={addTarget}
            className="mt-2 px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200">
            + Add target
          </button>
        </fieldset>

        {/* Email body */}
        <label className="block">
          <span className="text-sm font-medium">Subject *</span>
          <input required className="w-full mt-1 p-2 border rounded" value={form.subject}
            onChange={(e) => set("subject", e.target.value)} />
        </label>
        <label className="block">
          <span className="text-sm font-medium">HTML body * (must embed {`{tracker_url}`} token)</span>
          <textarea required rows={10} className="w-full mt-1 p-2 border rounded font-mono text-xs"
            value={form.body_html} onChange={(e) => set("body_html", e.target.value)} />
          <p className="text-xs text-gray-500 mt-1">
            Tokens: {`{tracker_url}`} (required), {`{first_name}`} (
	  {/* Landing page + redirect config */}
        <fieldset className="p-4 border rounded space-y-3">
          <legend className="text-sm font-bold px-1">Landing page</legend>
          <label className="block">
            <span className="text-sm font-medium">Landing title</span>
            <input className="w-full mt-1 p-2 border rounded" value={form.landing_title}
              onChange={(e) => set("landing_title", e.target.value)} />
          </label>
          <label className="block">
            <span className="text-sm font-medium">
              Redirect after harvest (GoPhish-style — real corporate login URL)
            </span>
            <input type="url" placeholder="https://login.corp.example/login"
              className="w-full mt-1 p-2 border rounded" value={form.redirect_after}
              onChange={(e) => set("redirect_after", e.target.value)} />
            <p className="text-xs text-gray-500 mt-1">
              After credentials are captured, the victim is 302-redirected here so
              the flow appears seamless. Leave blank to resend the landing page.
            </p>
          </label>
        </fieldset>

        {/* Dispatch toggle */}
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={form.dispatch}
            onChange={(e) => set("dispatch", e.target.checked)} />
          <span className="text-sm">
            Dispatch immediately via SMTP (unchecked = save as draft)
          </span>
        </label>

        <button type="submit"
          className="w-full py-2 bg-blue-600 text-white rounded hover:bg-blue-700 font-medium">
          {form.dispatch ? "Create & Dispatch Campaign" : "Create Draft Campaign"}
        </button>
      </form>
    </div>
  );
}
