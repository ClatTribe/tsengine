// Service-model HITL framing — the ONE thing that differs across the three GTM models (§18.5): WHO owns
// the human-in-the-loop decisions (approvals, risk acceptance, sign-offs). self_serve = the tenant's own
// team; managed = our hired expert; msp = a partner firm's expert. The app should DEFER its HITL framing
// accordingly instead of nagging a managed/MSP customer to approve work their expert already handles
// (via the cross-tenant /operator console). This is the reusable switch every HITL surface reads.

export type ServiceModel = "self_serve" | "msp" | "managed";

export const SERVICE_MODEL_LABEL: Record<string, string> = {
  self_serve: "Self-managed",
  msp: "Partner-managed",
  managed: "Managed service",
};

export type Practitioner = { name?: string; firm?: string } | null | undefined;

export type HitlOwner = {
  // Does the logged-in tenant user own the HITL acts (so we show action-required controls)?
  selfOwned: boolean;
  // A lowercase noun phrase for who does the acts: "you" / "your managed security team (Acme)" / "Acme".
  actor: string;
};

// hitlOwner resolves who owns the human-in-the-loop acts for a tenant's service model. self_serve → the
// tenant user (action-required UX); managed/msp → the named expert (informational, "handled by X" UX).
export function hitlOwner(serviceModel: string | undefined, practitioner?: Practitioner): HitlOwner {
  const who = practitioner?.firm || practitioner?.name;
  switch (serviceModel) {
    case "managed":
      return { selfOwned: false, actor: who ? `your managed security team (${who})` : "your managed security team" };
    case "msp":
      return { selfOwned: false, actor: who || "your security partner" };
    default:
      return { selfOwned: true, actor: "you" };
  }
}

// capitalize is a tiny helper for sentence-leading an actor phrase ("you" → "You").
export function capitalize(s: string): string {
  return s.length ? s[0].toUpperCase() + s.slice(1) : s;
}
