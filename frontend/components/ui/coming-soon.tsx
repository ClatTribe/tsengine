import { Construction } from "lucide-react";

export function ComingSoon({ title, phase, blurb }: { title: string; phase: string; blurb: string }) {
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">{title}</h1>
      <div className="card flex items-center gap-4 p-6 animate-fade-rise">
        <div className="grid h-10 w-10 place-items-center rounded-lg bg-surface-2 text-accent">
          <Construction className="h-5 w-5" />
        </div>
        <div>
          <div className="text-sm">{blurb}</div>
          <div className="mt-0.5 text-xs text-faint">Lands in {phase}. The data + API are already live.</div>
        </div>
      </div>
    </div>
  );
}
