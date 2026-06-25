import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { SITE_URL } from "@/lib/site";
import "./globals.css";

const TITLE = "TensorShield — your fractional security team";
const DESCRIPTION =
  "TensorShield is the AI security team for growing companies — it monitors your systems continuously, fixes what it safely can, and proves your compliance, with a human in the loop.";

// Site-wide metadata. metadataBase makes the dynamic OG image (app/opengraph-image.tsx)
// and any relative URLs resolve to absolute, which OpenGraph/Twitter cards require. Child
// pages override title/description and may set their own per-page canonical; the OG, Twitter,
// and robots defaults below are correct to inherit everywhere.
export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: TITLE,
  description: DESCRIPTION,
  applicationName: "TensorShield",
  keywords: [
    "AI security",
    "fractional security team",
    "vulnerability management",
    "continuous penetration testing",
    "SOC 2 compliance",
    "cloud security posture management",
    "SAST",
    "DAST",
    "software composition analysis",
    "SSPM",
    "attack path analysis",
    "AI pentest",
  ],
  authors: [{ name: "TensorShield" }],
  creator: "TensorShield",
  publisher: "TensorShield",
  formatDetection: { telephone: false, address: false, email: false },
  openGraph: {
    type: "website",
    siteName: "TensorShield",
    title: TITLE,
    description: DESCRIPTION,
    url: SITE_URL,
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="min-h-screen bg-bg font-sans">{children}</body>
    </html>
  );
}
