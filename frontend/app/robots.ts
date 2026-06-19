import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/site";

// Allow crawling the public marketing + framework pages; keep crawlers out of the authed app
// surface and API proxies (they redirect/401 anyway, but this avoids wasted crawl budget).
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/dashboard", "/findings", "/compliance", "/inbox", "/incidents", "/assets", "/reports", "/reviews", "/settings", "/activity"] },
    sitemap: `${SITE_URL}/sitemap.xml`,
    host: SITE_URL,
  };
}
