"use client";

import { useState, useTransition } from "react";
import { Brain, Loader2, Check } from "lucide-react";
import { setLLMConfig } from "@/app/(app)/settings/actions";

// LLMSettings lets the customer bring their own LLM for the engine's agent / autonomous
// pentest. The key is write-only — the server seals it and only ever reports whether one is
// set. Leaving the key blank when saving keeps the existing key (so you can switch models).
const PROVIDERS = [
  { id: "anthropic", label: "Anthropic (Claude)", placeholder: "claude-opus-4-8", selfHosted: false },
  { id: "openai", label: "OpenAI", placeholder: "gpt-4o", selfHosted: false },
  { id: "gemini", label: "Google (Gemini)", placeholder: "gemini-2.0-flash", selfHosted: false },
  { id: "ollama", label: "Ollama (self-hosted)", placeholder: "llama3.1", selfHosted: true },
  { id: "openai-compat", label: "Self-hosted (OpenAI-compatible)", placeholder: "your-model", selfHosted: true },
];

export function LLMSettings({ initial }: { initial: { provider: string; model: string; has_key: boolean; base_url?: string } }) {
  const [provider, setProvider] = useState(initial.provider || "anthropic");
  const [model, setModel] = useState(initial.model || "");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState(initial.base_url || "");
  const [hasKey, setHasKey] = useState(initial.has_key);
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  const selected = PROVIDERS.find((p) => p.id === provider);
  const ph = selected?.placeholder ?? "";
  const selfHosted = selected?.selfHosted ?? false;

  function save() {
    setErr("");
    setSaved(false);
    if (!model.trim()) {
      setErr("Enter a model.");
      return;
    }
    if (selfHosted && !baseUrl.trim()) {
      setErr("Enter the base URL of your self-hosted model (e.g. http://localhost:11434/v1).");
      return;
    }
    // Self-hosted models (Ollama) need no key; cloud providers need one on the first save.
    if (!selfHosted && !hasKey && !apiKey.trim()) {
      setErr("Enter an API key for the first save.");
      return;
    }
    start(async () => {
      try {
        const r = await setLLMConfig(provider, model.trim(), apiKey.trim(), selfHosted ? baseUrl.trim() : "");
        setHasKey(r.has_key);
        setApiKey("");
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "could not save LLM settings");
      }
    });
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">
        Bring your own LLM for the AI agent and autonomous pentest — a cloud key (Anthropic / OpenAI / Gemini) or a
        <span className="text-ink"> self-hosted model</span> (Ollama / vLLM / LM Studio) so no data leaves your infra.
        Your key is encrypted at rest and never shown again.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-muted">
          Provider
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="mt-1 block rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm outline-none focus:border-accent"
          >
            {PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Model
          <input
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder={ph}
            className="mt-1 block w-56 rounded-lg border border-border bg-surface px-3 py-1.5 text-sm outline-none focus:border-accent"
          />
        </label>
        {selfHosted && (
          <label className="text-xs text-muted">
            Base URL
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:11434/v1"
              className="mono mt-1 block w-64 rounded-lg border border-border bg-surface px-3 py-1.5 text-sm outline-none focus:border-accent"
            />
          </label>
        )}
        <label className="text-xs text-muted">
          API key {selfHosted && <span className="text-faint">· optional</span>}{hasKey && <span className="text-pulse">· set</span>}
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={selfHosted ? "(none needed for Ollama)" : hasKey ? "•••••••• (leave blank to keep)" : "sk-…"}
            autoComplete="off"
            className="mt-1 block w-56 rounded-lg border border-border bg-surface px-3 py-1.5 text-sm outline-none focus:border-accent"
          />
        </label>
        <button
          onClick={save}
          disabled={pending}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <Check className="h-4 w-4" /> : <Brain className="h-4 w-4" />}
          {saved ? "Saved" : "Save"}
        </button>
      </div>
      {err && <div className="rounded-lg bg-critical/10 px-3 py-2 text-xs text-critical">{err}</div>}
    </div>
  );
}
