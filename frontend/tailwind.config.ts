import type { Config } from "tailwindcss";

// The "command-center" design system (DESIGN.md §3). Dark, technical, one confident accent.
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0A0B0F",
        surface: "#111318",
        "surface-2": "#161922",
        "surface-3": "#1C212C",
        border: "#222632",
        "border-strong": "#2E3442",
        ink: "#E6E9EF",
        muted: "#8B94A7",
        faint: "#5A6173",
        accent: "#5B8CFF", // "the agent" — primary, focus
        "accent-soft": "#1B2742",
        pulse: "#36E2A4", // live / working / fixed
        critical: "#FF4D4F",
        high: "#FF7A45",
        medium: "#FAAD14",
        low: "#52C41A",
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.02) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        glow: "0 0 0 1px rgba(91,140,255,0.4), 0 0 24px -6px rgba(91,140,255,0.45)",
      },
      keyframes: {
        "fade-rise": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        breathe: {
          "0%,100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.5", transform: "scale(0.82)" },
        },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        "fade-rise": "fade-rise 200ms ease-out both",
        breathe: "breathe 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
export default config;
