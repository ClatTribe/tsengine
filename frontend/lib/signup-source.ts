// Signup attribution — the one field every GTM motion turns out to need.
//
// A partner listing, a VC portfolio-perk page, an outbound sequence and an accelerator batch each
// link to the site with `?ref=<tag>`. The tag has to survive the reader's wander from the landing
// page to /scan to /pricing to /signup, so the FIRST one seen is kept in sessionStorage (first-touch;
// a later ?ref= does not overwrite it) and sent with the signup. Nothing else is stored, nothing is
// sent anywhere but our own signup call, and it clears when the tab closes — this is not analytics.
//
// Every access is guarded: sessionStorage throws in some private/embedded contexts, and a missing
// tag is simply "" (direct / unknown), never invented.
const KEY = "ts_ref";

export function captureSignupSource(search: string): void {
  try {
    const ref = new URLSearchParams(search).get("ref");
    if (!ref) return;
    if (!window.sessionStorage.getItem(KEY)) window.sessionStorage.setItem(KEY, ref.slice(0, 64));
  } catch {
    /* storage unavailable — attribution is best-effort */
  }
}

export function readSignupSource(): string {
  try {
    const fromURL = new URLSearchParams(window.location.search).get("ref");
    return (fromURL || window.sessionStorage.getItem(KEY) || "").slice(0, 64);
  } catch {
    return "";
  }
}
