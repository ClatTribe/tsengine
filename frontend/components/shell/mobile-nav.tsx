"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { usePathname } from "next/navigation";

// The shell's mobile navigation state — ADR 0022 §1.
//
// The app had no responsive treatment at all: the sidebar stayed at a fixed 224px, leaving 151px
// for application content at 375px, with no hamburger and no collapse. The Inbox — the approval
// queue a founder opens when Slack says "3 fixes ready for your approval" — was unusable on the
// device they were holding.
//
// This is deliberately a context rather than props threaded through the server layout: the trigger
// lives in the TopBar and the drawer is the Sidebar, two sibling client components with a server
// component between them. A context is the only thing that reaches both without making the layout
// a client component and pulling the whole authed data fetch into the browser.
type MobileNavState = { open: boolean; setOpen: (v: boolean) => void };

const Ctx = createContext<MobileNavState>({ open: false, setOpen: () => {} });

export function useMobileNav() {
  return useContext(Ctx);
}

export function MobileNavProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  // Close on navigation. Without this the drawer stays open over the page the user just chose,
  // which reads as a broken tap rather than a successful one.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Escape closes, and the body must not scroll behind an open drawer — on a phone that produces
  // the "I scrolled and nothing moved" confusion where the page under the overlay is what moved.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return <Ctx.Provider value={{ open, setOpen }}>{children}</Ctx.Provider>;
}

/** The trigger. Rendered in the TopBar, hidden from `md` up where the sidebar is always present. */
export function MobileNavTrigger() {
  const { setOpen } = useMobileNav();
  return (
    <button
      type="button"
      onClick={() => setOpen(true)}
      aria-label="Open navigation"
      // 44px target: this is the one control that unlocks every other one on a phone.
      className="-ml-1 grid h-11 w-11 shrink-0 place-items-center rounded-lg text-muted transition hover:bg-surface-2 hover:text-ink md:hidden"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5" aria-hidden="true">
        <path d="M4 7h16M4 12h16M4 17h16" strokeLinecap="round" />
      </svg>
    </button>
  );
}

/** The scrim behind an open drawer. Tapping it closes — the gesture people try first. */
export function MobileNavBackdrop() {
  const { open, setOpen } = useMobileNav();
  if (!open) return null;
  return (
    <div
      onClick={() => setOpen(false)}
      aria-hidden="true"
      className="fixed inset-0 z-40 bg-ink/40 backdrop-blur-[2px] md:hidden"
    />
  );
}
