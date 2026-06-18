import type { Config } from "tailwindcss";

// Sentinel design system — light, warm, premium (DESIGN.md §3). Built for the SMB buyer:
// calm and trustworthy, not a dark "hacker" console. Off-white canvas so white cards lift,
// soft layered shadows (not heavy borders) for depth, one confident indigo accent used
// sparingly, emerald for "handled / live". The same semantic tokens the dark theme used —
// only their VALUES change — so the whole app re-themes from here.
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#F6F7F9", // app canvas — cool off-white so white surfaces pop
        surface: "#FFFFFF", // cards / panels
        "surface-2": "#F1F3F7", // subtle raised / hover / skeleton
        "surface-3": "#E8EBF1", // deeper fill
        border: "#E7E9EF", // soft hairline
        "border-strong": "#D3D8E2",
        ink: "#171A21", // primary text — near-black, faintly cool
        muted: "#5A6473", // secondary text
        faint: "#8B95A6", // tertiary / placeholder
        accent: "#4F46E5", // "the agent" — indigo, primary + focus
        "accent-hover": "#4338CA",
        "accent-soft": "#EEF0FE", // light indigo wash for chips/CTAs
        pulse: "#059669", // live / working / fixed — emerald
        "pulse-soft": "#E7F6EF",
        critical: "#DC2626",
        high: "#EA580C",
        medium: "#D97706",
        low: "#2563EB",
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
      boxShadow: {
        // soft, layered — depth comes from shadow, not borders (the premium-light trick)
        card: "0 1px 2px rgba(16,24,40,0.04), 0 1px 3px rgba(16,24,40,0.06)",
        "card-hover": "0 6px 16px -4px rgba(16,24,40,0.10), 0 2px 6px -2px rgba(16,24,40,0.06)",
        elevated: "0 16px 40px -12px rgba(16,24,40,0.16)",
        glow: "0 0 0 4px rgba(79,70,229,0.12)",
      },
      keyframes: {
        "fade-rise": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        breathe: {
          "0%,100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.45", transform: "scale(0.82)" },
        },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        "fade-rise": "fade-rise 240ms cubic-bezier(0.16,1,0.3,1) both",
        breathe: "breathe 2.2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
export default config;
