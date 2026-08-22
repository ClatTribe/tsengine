import type { MetadataRoute } from "next";
import { FRAMEWORKS } from "@/lib/frameworks";
import { POSTS } from "@/lib/blog";
import { RESOURCE_LIST } from "@/lib/resources";
import { SITE_URL } from "@/lib/site";

// The public, crawlable surface — marketing pages + the programmatic per-framework SEO pages.
// Authed app routes (under (app)) are intentionally excluded; they redirect to /login.
//
// CONTENT ROUTES ARE DERIVED, NEVER HAND-LISTED. Blog posts and resources are generated from the
// same arrays their pages render from (POSTS, RESOURCE_LIST), so publishing a post is enough to
// submit it. The hand-maintained list is what broke here: all three posts existed with correct
// metadata and generateStaticParams, and none of them were in the sitemap — only the /blog index
// was — while all 25 templated framework pages were listed. The pages written to rank were the
// ones not submitted. A derived list cannot drift out of sync with the content it describes.
export default function sitemap(): MetadataRoute.Sitemap {
  const staticPaths = [
    "", "/product", "/cross-detection", "/ai-security-engineer", "/ai-pentest", "/vapt",
    "/saas-posture", "/ci-cd", "/pricing", "/security", "/integrations", "/about", "/frameworks", "/scan", "/demo",
    // GTM pages that were crawlable but missing from the sitemap
    "/vs-consulting", "/partners", "/managed", "/startups", "/soc2-readiness", "/sample-report", "/blog",
    // per-asset SEO landing pages (content in lib/asset-marketing.ts)
    "/cloud-security", "/api-security", "/web-application-security", "/code-security", "/container-security",
    "/mobile-app-security", "/network-security", "/dns-domain-security",
    // free resources hub (the individual resources are derived below)
    "/resources",
    // honest competitor-comparison pages
    "/vs-vanta", "/vs-drata", "/vs-sprinto", "/vs-secureframe", "/vs-aikido",
    // legal
    "/privacy", "/terms", "/dpa", "/subprocessors",
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
  // Editorial content — the pages built to rank. lastModified comes from the post's own date so a
  // crawler can tell a revised post from an untouched one.
  const blogPages = POSTS.map((p) => ({
    url: `${SITE_URL}/blog/${p.slug}`,
    lastModified: new Date(p.date),
    changeFrequency: "monthly" as const,
    priority: 0.7,
  }));
  const resourcePages = RESOURCE_LIST.map((r) => ({
    url: `${SITE_URL}/resources/${r.slug}`,
    changeFrequency: "monthly" as const,
    priority: 0.7,
  }));
  return [...pages, ...frameworkPages, ...blogPages, ...resourcePages];
}
