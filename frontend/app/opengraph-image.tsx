import { ImageResponse } from "next/og";

// The default social-share card for every page that doesn't supply its own. Generated at
// request time by next/og (no extra dependency, no static asset to maintain). Node runtime
// so it works in the self-hosted standalone Docker build.
export const alt = "TensorShield — your fractional AI security team";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const ACCENT = "#6366f1";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: "72px",
          backgroundColor: "#0a0a0f",
          backgroundImage: "linear-gradient(135deg, #1e1b4b 0%, #0a0a0f 58%)",
          color: "#fafafa",
          fontFamily: "sans-serif",
        }}
      >
        {/* Wordmark row */}
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: "64px",
              height: "64px",
              borderRadius: "18px",
              background: ACCENT,
              boxShadow: `0 0 0 1px rgba(255,255,255,0.06), 0 18px 40px -12px ${ACCENT}`,
            }}
          >
            {/* simple shield glyph */}
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z"
                fill="#ffffff"
              />
              <path
                d="M8.5 12.2l2.4 2.4 4.6-4.8"
                stroke={ACCENT}
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div style={{ fontSize: "40px", fontWeight: 700, letterSpacing: "-0.02em" }}>
            TensorShield
          </div>
        </div>

        {/* Headline */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          <div
            style={{
              fontSize: "68px",
              fontWeight: 700,
              lineHeight: 1.05,
              letterSpacing: "-0.03em",
              maxWidth: "1000px",
            }}
          >
            Your fractional AI security team
          </div>
          <div style={{ fontSize: "30px", color: "#a1a1aa", maxWidth: "920px", lineHeight: 1.35 }}>
            Finds, fixes, and proves — continuous security &amp; compliance, with a human in the loop.
          </div>
        </div>

        {/* Capability chips */}
        <div style={{ display: "flex", gap: "14px", flexWrap: "wrap" }}>
          {["Pentest", "Cloud & code", "SOC 2 · ISO 27001 · PCI", "Attack paths", "SSPM"].map(
            (c) => (
              <div
                key={c}
                style={{
                  display: "flex",
                  fontSize: "24px",
                  color: "#d4d4d8",
                  padding: "10px 22px",
                  borderRadius: "999px",
                  background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.08)",
                }}
              >
                {c}
              </div>
            ),
          )}
        </div>
      </div>
    ),
    { ...size },
  );
}
