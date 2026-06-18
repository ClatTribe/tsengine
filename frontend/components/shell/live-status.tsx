"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";

// The real-time pulse. Opens an EventSource to the same-origin SSE proxy and, when the
// server pushes a changed `state` snapshot, re-renders the current Server Component view
// (router.refresh()) — so the dashboard updates live without per-navigation polling. The
// dot reflects the live connection; EventSource auto-reconnects on drop.
export function LiveStatus() {
  const router = useRouter();
  const [live, setLive] = useState(false);
  const last = useRef<string>("");

  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onopen = () => setLive(true);
    es.onerror = () => setLive(false); // browser will retry automatically
    es.addEventListener("state", (e) => {
      setLive(true);
      const data = (e as MessageEvent).data as string;
      // first snapshot just primes the baseline; later changes refresh the view
      if (last.current && last.current !== data) router.refresh();
      last.current = data;
    });
    return () => es.close();
  }, [router]);

  return (
    <span
      className={cn("inline-flex items-center gap-1.5 text-[11px] transition-colors", live ? "text-pulse" : "text-faint")}
      title={live ? "Live — updates stream in real time" : "Reconnecting to the live feed…"}
      aria-live="polite"
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", live ? "bg-pulse animate-breathe" : "bg-faint")} />
      {live ? "Live" : "Offline"}
    </span>
  );
}
