import { ImageResponse } from "next/og";

// The iOS "add to home screen" icon — same shield mark, sized for the Apple touch icon.
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() { 
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          backgroundColor: "#0b1220",
          borderRadius: "40px",
        }}
      >
        <svg width="116" height="116" viewBox="0 0 24 24" fill="none">
          {/* cyan shield + network + up-right arrow + warm clasp — the brand mark */}
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
    ),
    { ...size },
  );
}
