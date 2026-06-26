import { pageMeta } from "@/lib/seo";
import { AssetMarketingPage } from "@/components/marketing/asset-marketing-page";
import { ASSET_PAGES } from "@/lib/asset-marketing";

// Per-asset SEO landing page (content single-sourced from lib/asset-marketing.ts).
const data = ASSET_PAGES.network;
export const metadata = pageMeta({ title: data.seoTitle, description: data.seoDesc, path: "/network-security" });
export default function Page() {
  return <AssetMarketingPage data={data} />;
}
