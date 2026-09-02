import { apiBase } from "@/lib/auth";

// PUBLIC proxy for the sample VAPT report — no session, by design. This is the marketing
// asset a prospect reads before they have an account, so requiring one would defeat it.
//
// The document is GENERATED on each request by the same grc renderer a paying customer's
// report goes through (internal/samplereport). That is the whole claim being made on the
// /sample-report page: everyone else hosts a PDF somebody exported once and the reader has to
// trust it still describes the product. Proxying rather than checking in a static file is
// what keeps that true — a committed PDF would start drifting the day it landed.
//
//   ?format=html  → the print-ready deliverable, opened INLINE so the reader reaches the
//                   browser's print dialog (Save as PDF). Downloading an .html file instead
//                   would hand them something most people cannot open usefully.
//   default       → Markdown, as an attachment (the developer-facing deliverable).
export async function GET(req: Request) {
  const html = new URL(req.url).searchParams.get("format") === "html";
  const res = await fetch(`${apiBase()}/v1/sample-report?format=${html ? "html" : "md"}`, {
    // The report is deterministic for a given instant but its timestamps move, and a stale
    // cached copy is exactly the drift this endpoint exists to avoid.
    cache: "no-store",
  });
  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    headers: html
      ? { "Content-Type": "text/html; charset=utf-8", "Content-Disposition": "inline" }
      : {
          "Content-Type": "text/markdown; charset=utf-8",
          "Content-Disposition": `attachment; filename="tensorshield-sample-vapt-report.md"`,
        },
  });
}
