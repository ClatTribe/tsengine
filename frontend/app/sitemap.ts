import type { MetadataRoute } from "next";
import { FRAMEWORKS } from "@/lib/frameworks";
import { SITE_URL } from "@/lib/site";

// The public, crawlable surface — marketing pages + the programmatic per-framework SEO pages.
// Authed app routes (under (app)) are intentionally excluded; they redirect to /login.
export default function sitemap(): MetadataRoute.Sitemap {
  const staticPaths = ["", "/product", "/vapt", "/pricing", "/security", "/integrations", "/about", "/frameworks", "/scan", "/demo"];
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
