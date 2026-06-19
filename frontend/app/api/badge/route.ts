// The embeddable "Secured by TensorShield" trust badge — a public, cacheable SVG a customer
// drops on their own site. It's generic (no tenant data), so it's safe to serve unauthenticated
// and CDN-cache; the per-tenant part is the LINK wrapped around it (→ that tenant's Trust
// Center), which is the viral entry point: a visitor on the customer's site clicks the badge,
// lands on the Trust Center, and discovers TensorShield.

const BADGE = `<svg xmlns="http://www.w3.org/2000/svg" width="196" height="40" viewBox="0 0 196 40" role="img" aria-label="Secured by TensorShield">
  <rect x="0.5" y="0.5" width="195" height="39" rx="8" fill="#ffffff" stroke="#E5E7EB"/>
  <g transform="translate(14 11)">
    <path d="M9 0 L17 3 V9 C17 14 13.5 17.5 9 19 C4.5 17.5 1 14 1 9 V3 Z" fill="#EEF2FF"/>
    <path d="M9 1.3 L15.7 3.8 V9 C15.7 13.2 12.8 16.3 9 17.6 C5.2 16.3 2.3 13.2 2.3 9 V3.8 Z" fill="none" stroke="#4F46E5" stroke-width="1.1"/>
    <path d="M5.6 9.2 L8 11.6 L12.6 6.6" fill="none" stroke="#4F46E5" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
  <g font-family="ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif">
    <text x="40" y="17" font-size="10" fill="#6B7280">Secured by</text>
    <text x="40" y="30" font-size="13" font-weight="700" fill="#111827">TensorShield</text>
  </g>
</svg>`;

export function GET() {
  return new Response(BADGE, {
    headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      // long, immutable cache — the badge graphic doesn't change per request
      "Cache-Control": "public, max-age=86400, s-maxage=604800, immutable",
    },
  });
}
