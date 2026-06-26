import type { MetadataRoute } from "next";
import { FRAMEWORKS } from "@/lib/frameworks";
import { SITE_URL } from "@/lib/site";

// The public, crawlable surface — marketing pages + the programmatic per-framework SEO pages.
// Authed app routes (under (app)) are intentionally excluded; they redirect to /login.
export default function sitemap(): MetadataRoute.Sitemap {
  const staticPaths = [
    "", "/product", "/cross-detection", "/ai-security-engineer", "/ai-pentest", "/vapt", "/supply-chain",
    "/saas-posture", "/ci-cd", "/pricing", "/security", "/integrations", "/about", "/frameworks", "/scan", "/demo",
    // GTM pages that were crawlable but missing from the sitemap
    "/vs-consulting", "/partners", "/managed", "/soc2-readiness", "/sample-report", "/blog",
    // per-asset SEO landing pages (content in lib/asset-marketing.ts)
    "/cloud-security", "/api-security", "/web-application-security", "/code-security", "/container-security",
    "/mobile-app-security", "/network-security", "/dns-domain-security",
    // free email-gated resources (lead magnets)
    "/resources", "/resources/soc2-readiness-checklist", "/resources/security-questionnaire-template",
    // honest competitor-comparison pages
    "/vs-vanta", "/vs-drata", "/vs-sprinto", "/vs-secureframe", "/vs-aikido",
  ];
  const pages = staticPaths.map((p) => ({
    url: `${SITE_URL}${p}`,
    changeFrequency: "weekly" as const,
    priority: p === "" ? 1 : 0.8,
  }));
  const frameworkPages = FRAMEWORKS.map((f) => ({
    url: `${SITE_URL}/frameworks/${f}`,
    changeFrequency: "monthly" as const,
    priority: 0.7,
  }));
  return [...pages, ...frameworkPages];
}
