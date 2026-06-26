import { pageMeta } from "@/lib/seo";
import { ComparisonPage } from "@/components/marketing/comparison-page";
import { COMPETITORS } from "@/lib/competitors";

// Honest competitor-comparison SEO page (content single-sourced from lib/competitors.ts).
const data = COMPETITORS.secureframe;
export const metadata = pageMeta({ title: data.seoTitle, description: data.seoDesc, path: "/vs-secureframe" });
export default function Page() {
  return <ComparisonPage data={data} />;
}
