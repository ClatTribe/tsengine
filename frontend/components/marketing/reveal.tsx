"use client";

// Scroll-reveal wrapper — fades + lifts its children in the first time they enter the viewport, the
// subtle motion that makes a modern marketing site feel alive. IntersectionObserver, no deps. SSR-safe
// (the text is in the DOM for crawlers, only visually transitioned). prefers-reduced-motion collapses
// the transition to instant via the global CSS guard, so content still appears.
//
// The `ts-reveal` class is a styling hook, not behaviour: with JS disabled this component can never
// un-hide itself, so every section below the hero would stay at opacity 0 forever. The marketing
// layout carries a <noscript> rule keyed on that class which forces them visible. Crawlers already
// see the text (it is in the DOM); that rule is for humans whose JS is off or whose bundle failed.

import { useEffect, useRef, useState } from "react";

export function Reveal({
  children,
  className,
  delay = 0,
  as: Tag = "div",
}: {
  children: React.ReactNode;
  className?: string;
  delay?: number;
  as?: "div" | "section";
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setShown(true);
          io.disconnect();
        }
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.12 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <Tag
      ref={ref as React.Ref<HTMLDivElement & HTMLElement>}
      style={{ transitionDelay: shown ? `${delay}ms` : "0ms" }}
      className={`ts-reveal transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] ${
        shown ? "translate-y-0 opacity-100" : "translate-y-5 opacity-0"
      } ${className ?? ""}`}
    >
      {children}
    </Tag>
  );
}
