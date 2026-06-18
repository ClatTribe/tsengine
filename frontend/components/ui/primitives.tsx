import { cn } from "@/lib/utils";

const SEV_CLS: Record<string, string> = {
  critical: "text-critical border-critical/30 bg-critical/10",
  high: "text-high border-high/30 bg-high/10",
  medium: "text-medium border-medium/30 bg-medium/10",
  low: "text-low border-low/30 bg-low/10",
  info: "text-muted border-border bg-surface-2",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium capitalize",
        SEV_CLS[severity] ?? SEV_CLS.info,
        className,
      )}
    >
      {severity || "info"}
    </span>
  );
}

export function Tag({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("mono inline-flex items-center rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-muted", className)}>
      {children}
    </span>
  );
}

export function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("card p-5 animate-fade-rise", className)}>{children}</div>;
}

export function SectionTitle({ children, action }: { children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <h2 className="text-xs font-medium uppercase tracking-wider text-muted">{children}</h2>
      {action}
    </div>
  );
}

const RISK_CLS: Record<string, string> = {
  Critical: "text-critical",
  High: "text-high",
  Medium: "text-medium",
  Low: "text-low",
  Clear: "text-pulse",
};

export function RiskPill({ rating, className }: { rating: string; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-2.5 py-1 text-xs font-medium", className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", rating === "Clear" ? "bg-pulse" : "bg-current", RISK_CLS[rating] ?? "text-muted")} />
      <span className={RISK_CLS[rating] ?? "text-muted"}>{rating}</span>
    </span>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="rounded-lg border border-dashed border-border px-4 py-6 text-center text-sm text-muted">{children}</div>;
}
