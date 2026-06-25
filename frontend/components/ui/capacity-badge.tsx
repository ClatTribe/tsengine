// CapacityBadge shows WHO the human-in-the-loop works for on a HITL artifact — the difference between
// the two product models. internal = the tenant's own person; msp = a partner firm's expert; managed
// = our delivery expert. Hidden for plain internal acts with no firm (the default, not worth a badge).
const LABEL: Record<string, string> = { internal: "Internal", msp: "MSP / partner", managed: "Managed" };
const TONE: Record<string, string> = {
  internal: "text-muted bg-surface-2 border-border",
  msp: "text-accent bg-accent-soft/60 border-accent/30",
  managed: "text-pulse bg-pulse-soft border-pulse/30",
};

export function CapacityBadge({ capacity, firm }: { capacity?: string; firm?: string }) {
  if (!capacity || (capacity === "internal" && !firm)) return null;
  const label = LABEL[capacity] ?? capacity;
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${TONE[capacity] ?? TONE.internal}`}>
      {label}
      {firm ? ` · ${firm}` : ""}
    </span>
  );
}
