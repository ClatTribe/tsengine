"use client";

import { Printer } from "lucide-react";

// The browser's own print dialog is the PDF exporter: "Save as PDF" gives the board a document that
// matches the page exactly, with no second renderer to drift from it.
export function PrintButton() {
  return (
    <button onClick={() => window.print()}
      className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent-soft px-2.5 py-1 text-xs font-medium text-accent hover:border-accent">
      <Printer className="h-3.5 w-3.5" /> Print or save as PDF
    </button>
  );
}
