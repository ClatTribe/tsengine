import { SITE_URL } from "@/lib/site";

// schema.org structured data (JSON-LD) for the public marketing surface. Rendered once in the
// marketing layout, so every public page carries it — this is what lets Google show rich
// results and AI crawlers understand what TensorShield is. Kept to factual, verifiable claims
// only (no fabricated ratings, prices, or social links — grounding, CLAUDE.md §10).
export function MarketingJsonLd() {
  const graph = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": `${SITE_URL}/#organization`,
        name: "TensorShield",
        url: SITE_URL,
        logo: `${SITE_URL}/opengraph-image`,
        description:
          "TensorShield is an AI security team for growing companies — continuous monitoring, automated fixes with a human in the loop, and audit-ready compliance.",
      },
      {
        "@type": "WebSite",
        "@id": `${SITE_URL}/#website`,
        url: SITE_URL,
        name: "TensorShield",
        publisher: { "@id": `${SITE_URL}/#organization` },
      },
      {
        "@type": "SoftwareApplication",
        name: "TensorShield",
        applicationCategory: "SecurityApplication",
        operatingSystem: "Web",
        url: SITE_URL,
        description:
          "AI security and compliance platform: continuous vulnerability discovery across code, cloud, web, and SaaS; AI-driven penetration testing; attack-path analysis; and automated SOC 2, ISO 27001, and PCI evidence — all with a human-in-the-loop gate.",
        offers: { "@type": "Offer", category: "SaaS" },
      },
    ],
  };
  return (
    <script
      type="application/ld+json"
      // JSON.stringify output is safe to inline; no user input is interpolated.
      dangerouslySetInnerHTML={{ __html: JSON.stringify(graph) }}
    />
  );
}
