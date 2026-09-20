"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { CheckCircle2, CircleAlert, Loader2, ArrowUpRight } from "lucide-react";
import type { Job } from "@/lib/types";

// The post-connect banner, now telling the truth about WHEN. The OAuth callback queues the first
// discover+scan as a background job and lands the browser here with its id; this polls the job and
// moves through "scanning" → "done: N assets scanned, review issues" (or the real failure). Before
// this the banner said "findings land in a few minutes" over a scan that had, in fact, already run
// inside the redirect — or been cancelled with it — and nothing ever changed on screen.
//
// Three honest states, never a fourth:
//   - queued/running: scanning now (with how long we've been at it, so a stuck job looks stuck);
//   - done: how many assets scanned, and a warning when the pass was PARTIAL — one repository that
//     failed must be visible, not folded into a green tick;
//   - failed: the platform's real reason, because an empty findings list on a security product
//     reads as "nothing wrong" when the truth is "nothing ran".
// When the job is done the page is refreshed so the server-rendered asset list and posture catch up.
export function ConnectScanStatus({ jobId, kindLabel }: { jobId: string; kindLabel: string }) {
  const router = useRouter();
  const [job, setJob] = useState<Job | null>(null);
  const [lost, setLost] = useState(false);
  const [startedAt] = useState(() => Date.now());
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    let stop = false;
    let refreshed = false;
    const tick = async () => {
      try {
        const res = await fetch(`/api/job?id=${encodeURIComponent(jobId)}`, { cache: "no-store" });
        if (res.status === 404) {
          // The pool retains a bounded number of finished jobs; a very old link can outlive its job.
          setLost(true);
          return true;
        }
        if (!res.ok) return false;
        const j = (await res.json()) as Job;
        setJob(j);
        const finished = j.status === "done" || j.status === "failed";
        if (finished && !refreshed) {
          refreshed = true;
          router.refresh();
        }
        return finished;
      } catch {
        return false; // transient — keep polling
      }
    };
    void tick();
    const iv = setInterval(async () => {
      if (stop) return;
      setElapsed(Math.round((Date.now() - startedAt) / 1000));
      if (await tick()) {
        stop = true;
        clearInterval(iv);
      }
    }, 2000);
    return () => {
      stop = true;
      clearInterval(iv);
    };
  }, [jobId, router, startedAt]);

  const links = (
    <span className="ml-auto inline-flex items-center gap-3 text-[13px] font-medium">
      <Link href="/issues" className="inline-flex items-center gap-0.5 hover:underline">
        Review issues <ArrowUpRight className="h-3.5 w-3.5" />
      </Link>
      <Link href="/compliance" className="inline-flex items-center gap-0.5 hover:underline">
        Compliance posture <ArrowUpRight className="h-3.5 w-3.5" />
      </Link>
    </span>
  );

  if (lost) {
    return (
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-muted">
        <CheckCircle2 className="h-4 w-4 shrink-0 text-pulse" />
        <span>{kindLabel} connected. The first scan finished a while ago — its findings are in the list below.</span>
        {links}
      </div>
    );
  }

  if (job?.status === "failed") {
    return (
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
        <CircleAlert className="h-4 w-4 shrink-0" />
        <span>
          {kindLabel} connected, but the first scan did not run{job.error ? `: ${job.error}` : "."} Nothing below reflects this system yet —
          fix the cause and use Scan now.
        </span>
      </div>
    );
  }

  if (job?.status === "done") {
    const n = job.result?.assets_scanned ?? 0;
    const warn = job.result?.warning;
    return (
      <div className={`flex flex-wrap items-center gap-x-2 gap-y-1.5 rounded-lg border px-3 py-2 text-sm ${warn ? "border-medium/30 bg-medium/10 text-medium" : "border-pulse/30 bg-pulse/10 text-pulse"}`}>
        {warn ? <CircleAlert className="h-4 w-4 shrink-0" /> : <CheckCircle2 className="h-4 w-4 shrink-0" />}
        <span>
          {kindLabel} connected — first scan complete: {n} {n === 1 ? "asset" : "assets"} scanned.
          {warn ? ` Partial: ${warn}` : ""}
        </span>
        {links}
      </div>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 rounded-lg border border-pulse/30 bg-pulse/10 px-3 py-2 text-sm text-pulse">
      <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
      <span>
        {kindLabel} connected — discovering and scanning your assets now{elapsed >= 5 ? ` (${elapsed}s)` : ""}. This page updates when the first pass finishes.
      </span>
      {links}
    </div>
  );
}
