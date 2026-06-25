import { MarketingNav } from "@/components/marketing/nav";
import { MarketingFooter } from "@/components/marketing/footer";
import { MarketingJsonLd } from "@/components/marketing/json-ld";

// Public marketing surface — no auth. The app lives behind /login under the (app) group.
export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      {/* schema.org structured data — emitted on every public page for rich results. */}
      <MarketingJsonLd />
      <MarketingNav />
      <main className="flex-1">{children}</main>
      <MarketingFooter />
    </div>
  );
}
