"use server";

import { api, ApiError } from "@/lib/api";

// Sets the signed-in user's password (and clears the forced-rotation flag for an invited member).
// Usually the session stays valid and the client navigates back into the app — but the server can
// report that it could not revoke the OTHER sessions, or that the wipe took this one too, and both
// are passed through rather than flattened into a bare success.
export async function changePasswordAction(
  current: string,
  next: string,
): Promise<{ ok: true; warning?: string; signedOut?: boolean } | { error: string }> {
  if (next.length < 8) return { error: "Your new password must be at least 8 characters." };
  if (next === current) return { error: "Your new password must be different from the current one." };
  try {
    const res = await api.changePassword(current, next);
    // The password change SUCCEEDED either way — never turn this into an error, because a user who
    // cannot change their password at all is worse off. But a failed revocation is reported: it is
    // the reason most people are on this page.
    if (res?.signed_out) {
      return { ok: true, signedOut: true, warning: res.detail };
    }
    if (res && res.sessions_revoked === false) {
      return { ok: true, warning: res.detail };
    }
    return { ok: true };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return { error: "Your current password is incorrect." };
    if (e instanceof ApiError && e.status === 400) return { error: "Please choose a different password (at least 8 characters)." };
    return { error: "Couldn't update your password. Please try again." };
  }
}
