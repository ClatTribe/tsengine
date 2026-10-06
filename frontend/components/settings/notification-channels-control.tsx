"use client";

import { useState, useTransition } from "react";
import { MessageSquare, Users, Hash, BellRing, Webhook, Loader2, Check, Send } from "lucide-react";
import { setNotifyChannels, testNotifyChannel } from "@/app/(app)/settings/actions";
import type { NotifyChannel, NotifyPatch, NotifySettings } from "@/lib/types";

// The tenant's OWN alert destinations (Bucket B). Every value is a bearer capability — a webhook URL
// posts to the channel, a PagerDuty key pages the rotation — so each is sealed server-side and never
// returned. We only ever know whether one is set.
//
// Each configured channel has a Test button, because a destination saved and never exercised looks,
// from here, exactly like one that works. The result shown is what the destination itself answered.

type ChannelDef = {
  id: NotifyChannel;
  label: string;
  hint: string;
  field: keyof NotifyPatch;
  placeholder: string;
  icon: typeof MessageSquare;
  help: string;
};

const CHANNELS: ChannelDef[] = [
  {
    id: "slack", label: "Slack", hint: "New-incident heads-ups to your channel", field: "slack_webhook",
    placeholder: "https://hooks.slack.com/services/…", icon: MessageSquare,
    help: "Create an Incoming Webhook in your Slack workspace.",
  },
  {
    id: "teams", label: "Microsoft Teams", hint: "High and critical incidents to a Teams channel", field: "teams_webhook",
    placeholder: "https://….webhook.office.com/… or a Workflows URL", icon: Users,
    help: "An Incoming Webhook, or a Teams Workflows “post to a channel when a webhook request is received” URL.",
  },
  {
    id: "discord", label: "Discord", hint: "High and critical incidents to a Discord channel", field: "discord_webhook",
    placeholder: "https://discord.com/api/webhooks/…", icon: Hash,
    help: "Channel settings → Integrations → Webhooks.",
  },
  {
    id: "pagerduty", label: "PagerDuty", hint: "Pages your on-call rotation for high and critical", field: "pagerduty_routing_key",
    placeholder: "32-character Events API v2 integration key", icon: BellRing,
    help: "Service → Integrations → Events API v2. An escalation tier naming PagerDuty pages this rotation.",
  },
  {
    id: "webhook", label: "Signed webhook", hint: "Every incident as signed JSON — Zapier, n8n, a SIEM", field: "webhook_url",
    placeholder: "https://your-endpoint.example.com/tensorshield", icon: Webhook,
    help: "Must be a public https host. Add a signing secret to verify the X-TensorShield-Signature header.",
  },
];

export function NotificationChannelsControl({ initial }: { initial: NotifySettings }) {
  const [state, setState] = useState<NotifySettings>(initial);
  return (
    <div className="space-y-2">
      {CHANNELS.map((c) => (
        <ChannelRow key={c.id} def={c} configured={!!state.channels[c.id]} signed={state.webhook_signed} onSaved={setState} />
      ))}
      <p className="text-[11px] text-faint">
        Alerts go to every channel you configure here. Your escalation matrix decides which of them a given
        severity reaches; a channel it names that you have not set up here falls back to your administrator&rsquo;s.
      </p>
    </div>
  );
}

function ChannelRow({
  def, configured, signed, onSaved,
}: {
  def: ChannelDef;
  configured: boolean;
  signed: boolean;
  onSaved: (s: NotifySettings) => void;
}) {
  const [value, setValue] = useState("");
  const [secret, setSecret] = useState("");
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [test, setTest] = useState<{ ok: boolean; error?: string } | null>(null);
  const [pending, start] = useTransition();
  const Icon = def.icon;

  function save(clear: boolean) {
    setErr("");
    setSaved(false);
    setTest(null);
    const patch: NotifyPatch = { [def.field]: clear ? "" : value.trim() };
    if (def.id === "webhook" && !clear && secret.trim()) patch.webhook_secret = secret.trim();
    start(async () => {
      try {
        onSaved(await setNotifyChannels(patch));
        setValue("");
        setSecret("");
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  function runTest() {
    if (def.id === "pagerduty" && !window.confirm("This pages your on-call rotation now. Send a test page?")) return;
    setErr("");
    setTest(null);
    start(async () => {
      try {
        setTest(await testNotifyChannel(def.id));
      } catch (e) {
        setTest({ ok: false, error: e instanceof Error ? e.message : "Test failed" });
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{def.label}</div>
          <div className="text-xs text-muted">{def.hint}</div>
        </div>
        <span className={`text-[11px] ${configured ? "text-accent" : "text-faint"}`}>
          {configured ? (def.id === "webhook" ? (signed ? "configured · signed" : "configured · unsigned") : "configured") : "not set"}
        </span>
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={def.placeholder}
          aria-label={`${def.label} destination`}
          className="mono min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint"
        />
        {def.id === "webhook" && (
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="signing secret (optional, 16+ chars)"
            aria-label="Webhook signing secret"
            className="mono min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint"
          />
        )}
        <button
          onClick={() => save(false)}
          disabled={pending || !value.trim()}
          className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
          {configured ? "Replace" : "Save"}
        </button>
        {configured && (
          <>
            <button
              onClick={runTest}
              disabled={pending}
              className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-muted transition hover:text-ink disabled:opacity-50"
            >
              <Send className="h-3 w-3" /> Test
            </button>
            <button
              onClick={() => save(true)}
              disabled={pending}
              className="rounded-md border border-border px-2 py-1 text-xs text-muted transition hover:border-critical/40 hover:text-critical disabled:opacity-50"
            >
              Clear
            </button>
          </>
        )}
      </div>
      <p className="mt-1.5 text-[11px] text-faint">{def.help} Stored encrypted; never shown again.</p>
      {test && (
        <p className={`mt-1 text-[11px] ${test.ok ? "text-accent" : "text-critical"}`}>
          {test.ok
            ? `Test alert accepted by ${def.label}. Check that it arrived where you expect.`
            : `${def.label} did not accept the test: ${test.error ?? "unknown error"}`}
        </p>
      )}
      {err && <p className="mt-1 text-[11px] text-critical">{err}</p>}
    </div>
  );
}
