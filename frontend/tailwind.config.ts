import type { Config } from "tailwindcss";

// TensorShield design system — light, warm, premium (DESIGN.md §3). Built for the SMB buyer:
// calm and trustworthy, not a dark "hacker" console. Off-white canvas so white cards lift,
// soft layered shadows (not heavy borders) for depth, one confident indigo accent used
// sparingly, emerald for "handled / live". The same semantic tokens the dark theme used —
// only their VALUES change — so the whole app re-themes from here.
const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Tokens resolve from CSS variables (globals.css :root / .dark) as RGB channels, so the
        // whole app re-themes by toggling the `.dark` class on <html>, and opacity modifiers still
        // work (e.g. bg-accent/40). The semantic names are unchanged — only their source moved.
        bg: "rgb(var(--c-bg) / <alpha-value>)", // app canvas
        surface: "rgb(var(--c-surface) / <alpha-value>)", // cards / panels
        "surface-2": "rgb(var(--c-surface-2) / <alpha-value>)", // subtle raised / hover / skeleton
        "surface-3": "rgb(var(--c-surface-3) / <alpha-value>)", // deeper fill
        border: "rgb(var(--c-border) / <alpha-value>)", // soft hairline
        "border-strong": "rgb(var(--c-border-strong) / <alpha-value>)",
        ink: "rgb(var(--c-ink) / <alpha-value>)", // primary text
        muted: "rgb(var(--c-muted) / <alpha-value>)", // secondary text
        faint: "rgb(var(--c-faint) / <alpha-value>)", // tertiary / placeholder
        accent: "rgb(var(--c-accent) / <alpha-value>)", // "the agent" — indigo, primary + focus
        "accent-hover": "rgb(var(--c-accent-hover) / <alpha-value>)",
        "accent-soft": "rgb(var(--c-accent-soft) / <alpha-value>)", // indigo wash for chips/CTAs
        pulse: "rgb(var(--c-pulse) / <alpha-value>)", // live / working / fixed — emerald
        "pulse-soft": "rgb(var(--c-pulse-soft) / <alpha-value>)",
        critical: "rgb(var(--c-critical) / <alpha-value>)",
        high: "rgb(var(--c-high) / <alpha-value>)",
        medium: "rgb(var(--c-medium) / <alpha-value>)",
        low: "rgb(var(--c-low) / <alpha-value>)",
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
        aurora: {
          "0%,100%": { transform: "translate3d(0,0,0) scale(1)", opacity: "0.55" },
          "50%": { transform: "translate3d(2%,-3%,0) scale(1.12)", opacity: "0.8" },
        },
        "row-in": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(900%)" },
        },
      },
      animation: {
        "fade-rise": "fade-rise 240ms cubic-bezier(0.16,1,0.3,1) both",
        breathe: "breathe 2.2s ease-in-out infinite",
        aurora: "aurora 14s ease-in-out infinite",
        "row-in": "row-in 360ms cubic-bezier(0.16,1,0.3,1) both",
        scanline: "scanline 2.6s linear infinite",
      },
    },
  },
  plugins: [],
};
export default config;
