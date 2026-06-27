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
              background: "#0b1220",
              boxShadow: "0 0 0 1px rgba(255,255,255,0.08), 0 18px 50px -12px rgba(34,211,238,0.5)",
            }}
          >
            {/* brand mark — cyan shield + network + up-right arrow + warm clasp */}
            <svg width="38" height="38" viewBox="0 0 24 24" fill="none">
              <path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" fill="#0ea5e9" fillOpacity="0.14" stroke="#38bdf8" strokeWidth="1.4" strokeLinejoin="round" />
              <g stroke="#38bdf8" strokeWidth="0.8" opacity="0.7">
                <path d="M12 6.5L7.5 10.5M12 6.5L16.5 10.5M7.5 10.5L9.5 15.5M16.5 10.5L14.5 15.5M9.5 15.5L14.5 15.5" />
              </g>
              <g fill="#38bdf8">
                <circle cx="12" cy="6.5" r="0.9" />
                <circle cx="7.5" cy="10.5" r="0.9" />
                <circle cx="16.5" cy="10.5" r="0.9" />
                <circle cx="9.5" cy="15.5" r="0.9" />
                <circle cx="14.5" cy="15.5" r="0.9" />
              </g>
              <path d="M8.7 15L16 7.8" stroke="#7dd3fc" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M12.6 7.3H16.5V11.2" stroke="#7dd3fc" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="11.5" cy="12" r="2.6" fill="#fb923c" />
              <circle cx="11.5" cy="12" r="1" fill="#fff7ed" />
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
