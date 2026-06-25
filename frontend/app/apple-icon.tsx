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
          backgroundColor: "#6366f1",
          borderRadius: "40px",
        }}
      >
        <svg width="112" height="112" viewBox="0 0 24 24" fill="none">
          <path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" fill="#ffffff" />
          <path
            d="M8.5 12.2l2.4 2.4 4.6-4.8"
            stroke="#6366f1"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
    ),
    { ...size },
  );
}
