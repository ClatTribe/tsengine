"use client";

import { useState, useTransition } from "react";
import { Loader2, Plus, X } from "lucide-react";
import { addNote, removeNote } from "./actions";

export function AddNote() {
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();
  return (
    <div className="space-y-1.5">
      <div className="flex gap-2">
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={500}
          placeholder="e.g. payments-api deploys only on Tuesdays; route database findings to the platform team"
          className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-xs"
        />
        <button
          disabled={pending || !text.trim()}
          onClick={() =>
            start(async () => {
              const r = await addNote(text);
              if (r.ok) setText("");
              else setErr(r.error ?? "could not save");
            })
          }
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60"
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} Tell it
        </button>
      </div>
      {err && <p className="text-xs text-critical">{err}</p>}
    </div>
  );
}

export function RemoveNote({ id }: { id: string }) {
  const [pending, start] = useTransition();
  return (
    <button
      aria-label="Remove note"
      disabled={pending}
      onClick={() => start(() => removeNote(id))}
      className="rounded p-1 text-faint hover:text-high disabled:opacity-50"
    >
      <X className="h-3.5 w-3.5" />
    </button>
  );
}
