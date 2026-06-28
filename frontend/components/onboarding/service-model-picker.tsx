"use client";

import { useState, useTransition } from "react";
import { Rocket, UserCheck, Building2, Check, Loader2 } from "lucide-react";
import { setServiceModel } from "@/app/(app)/settings/actions";

// Onboarding service-model picker — so a managed/MSP tenant sets WHO owns the human-in-the-loop up front
// instead of being silently defaulted to self_serve. Writes through the same setServiceModel action as
// Settings (one source of truth); changeable any time in Settings → Service model.
const MODELS = [
  { value: "self_serve", icon: Rocket, label: "I'll run it myself", hint: "Your own team makes the judgment calls" },
  { value: "managed", icon: UserCheck, label: "Run it for me", hint: "We provide the named expert, on your behalf" },
  { value: "msp", icon: Building2, label: "I'm an MSP / partner", hint: "Deliver it to your own clients" },
];

export function ServiceModelPicker({ current = "self_serve" }: { current?: string }) {
  const [model, setModel] = useState(current || "self_serve");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function pick(v: string) {
    setModel(v);
    setSaved(false);
    start(async () => {
      await setServiceModel(v);
      setSaved(true);
    });
  }

  return (
    <div>
      <div className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-wider text-faint">
        How do you want to run it?
        {pending && <Loader2 className="h-3 w-3 animate-spin text-muted" />}
        {saved && !pending && (
          <span className="inline-flex items-center gap-1 normal-case tracking-normal text-pulse">
            <Check className="h-3 w-3" /> saved
          </span>
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        {MODELS.map(({ value, icon: Icon, label, hint }) => (
          <button
            key={value}
            onClick={() => pick(value)}
            disabled={pending}
            className={`card flex flex-col gap-1.5 p-4 text-left transition disabled:opacity-60 ${
              model === value ? "border-accent bg-accent-soft/40" : "hover:border-accent/40"
            }`}
          >
            <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent-soft text-accent">
              <Icon className="h-4 w-4" />
            </span>
            <span className="text-sm font-medium text-ink">{label}</span>
            <span className="text-xs leading-snug text-muted">{hint}</span>
          </button>
        ))}
      </div>
      <p className="mt-2 text-[11px] text-faint">
        It decides who owns the human-in-the-loop approvals. Change it any time in Settings → Service model.
      </p>
    </div>
  );
}
