import type { ReactNode } from "react";
import { noIndex } from "@/lib/seo";

// Server layout carrying metadata for a client-component page — see app/login/layout.tsx
// for why all four auth routes need one. ADR 0023 decision 3.
export const metadata = noIndex(
  "Create your workspace",
  "Create a TensorShield workspace and see your security posture free.",
);

export default function SignupLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
