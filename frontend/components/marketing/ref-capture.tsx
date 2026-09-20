"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { captureSignupSource } from "@/lib/signup-source";

// Records a `?ref=` attribution tag the moment any marketing page is opened with one, so it is
// still there when the reader reaches /signup several pages later. Renders nothing.
export function RefCapture() {
  const pathname = usePathname();
  useEffect(() => {
    captureSignupSource(window.location.search);
  }, [pathname]);
  return null;
}
