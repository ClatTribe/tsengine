"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { Check } from "lucide-react";
import { operatorPublishPolicy } from "@/app/operator/actions";

// PublishPolicyInline is the act-on-behalf control on a draft-policy queue item: the operator publishes
// the client's policy from the desk. Roster-gated + ledger-signed server-side.
export function PublishPolicyInline({ tenant, policy }: { tenant: string; policy: string }) {
  const [error, action] = useActionState(operatorPublishPolicy, null);
  return (
    <form action={action} className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
      <input type="hidden" name="tenant" value={tenant} />
      <input type="hidden" name="policy" value={policy} />
      <span className="flex-1 text-[11px] text-faint">Publishing names you as the owner, signed into the ledger.</span>
      <Submit />
      {error ? <span className="w-full text-[11px] text-critical">{error}</span> : null}
    </form>
  );
}

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-60"
    >
      <Check className="h-3.5 w-3.5" /> {pending ? "Publishing…" : "Publish"}
    </button>
  );
}
