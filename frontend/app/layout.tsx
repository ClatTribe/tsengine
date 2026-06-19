import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "TensorShield — your fractional security team",
  description:
    "TensorShield is the AI security team for growing companies — it monitors your systems continuously, fixes what it safely can, and proves your compliance, with a human in the loop.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="min-h-screen bg-bg font-sans">{children}</body>
    </html>
  );
}
