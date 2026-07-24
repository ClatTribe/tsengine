"use client";

import { useRef, useTransition } from "react";
import { useRouter } from "next/navigation";

// useAction wraps a Server Action call so a benign failure never crashes the page to the
// error boundary ("Something went sideways"). A mutation action (approve, acknowledge, decide,
// publish, sign off, ignore) can throw for reasons that are NOT bugs — the item was already
// decided by another operator/Slack, a rapid double-click raced itself, or the API blipped.
// Left unguarded (`start(() => action())`), that throw propagates out of the transition and
// unmounts the whole view. Here it's caught and reconciled with a refetch instead.
//
// Usage:
//   const [pending, run] = useAction();
//   <button disabled={pending} onClick={() => run(() => acknowledgeIncident(id))}>Ack</button>
//
// Pass `guardKey` to also drop a re-entrant call on the same target (double-click / click racing
// a keyboard shortcut) so it can't fire the mutation twice.
export function useAction(): [boolean, (fn: () => Promise<unknown>, guardKey?: string) => void] {
  const [pending, start] = useTransition();
  const router = useRouter();
  const inFlight = useRef<Set<string>>(new Set());

  const run = (fn: () => Promise<unknown>, guardKey?: string) => {
    if (guardKey) {
      if (inFlight.current.has(guardKey)) return;
      inFlight.current.add(guardKey);
    }
    start(async () => {
      try {
        await fn();
      } catch {
        // Reconcile optimistic UI / stale state by refetching rather than throwing to the
        // error boundary. The server is the source of truth; a refresh reflects what actually
        // happened (e.g. the item really is decided now).
        router.refresh();
      } finally {
        if (guardKey) inFlight.current.delete(guardKey);
      }
    });
  };

  return [pending, run];
}
