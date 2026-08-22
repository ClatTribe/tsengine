import type { ReactNode } from "react";
import { noIndex } from "@/lib/seo";

// A server layout exists here solely to carry metadata: login/page.tsx is a client component,
// and a client component cannot export `metadata`. That is why all four auth routes shipped
// with none — they fell through to the root layout's marketing defaults and published
// byte-identical titles and descriptions, all `index, follow`, leaving four thin pages
// competing with the homepage on the brand query. ADR 0023 decision 3.
export const metadata = noIndex("Sign in", "Sign in to your TensorShield workspace.");

export default function LoginLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
