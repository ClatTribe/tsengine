// FaqJsonLd emits schema.org FAQPage structured data so a page's questions can surface as
// Google rich results (the expandable Q&A under a search listing). It is driven by the SAME
// Q&A array the page renders, so the structured markup can never drift from the visible
// content — which Google requires (the FAQ in the markup must match what the user sees).
export function FaqJsonLd({ items }: { items: readonly (readonly string[])[] }) {
  const data = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: items.map(([q, a]) => ({
      "@type": "Question",
      name: q,
      acceptedAnswer: { "@type": "Answer", text: a },
    })),
  };
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}
