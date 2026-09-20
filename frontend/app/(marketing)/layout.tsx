import { RefCapture } from "@/components/marketing/ref-capture";
import { MarketingNav } from "@/components/marketing/nav";
import { MarketingFooter } from "@/components/marketing/footer";
import { MarketingJsonLd } from "@/components/marketing/json-ld";

// Public marketing surface — no auth. The app lives behind /login under the (app) group.
export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      {/* With JS off, the scroll-reveal wrapper can never un-hide itself — so un-hide it here.
          The marketing copy is already in the DOM for crawlers; this is what makes it visible to
          a human whose JS failed or was blocked. Paired with the guards in <Reveal>. */}
      <noscript>
        {/* eslint-disable-next-line react/no-danger */}
        <style dangerouslySetInnerHTML={{ __html: ".ts-reveal{opacity:1!important;transform:none!important}" }} />
      </noscript>
      {/* schema.org structured data — emitted on every public page for rich results. */}
      <MarketingJsonLd />
      <MarketingNav />
      <RefCapture />
      <main className="flex-1">{children}</main>
      <MarketingFooter />
    </div>
  );
}
