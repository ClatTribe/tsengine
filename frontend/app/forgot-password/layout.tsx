import type { ReactNode } from "react";
import { noIndex } from "@/lib/seo";

// Server layout carrying metadata for a client-component page — see app/login/layout.tsx
// for why all four auth routes need one. ADR 0023 decision 3.
export const metadata = noIndex(
  "Reset your password",
  "Request a password reset link for your TensorShield account.",
);

export default function ForgotPasswordLayout({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
