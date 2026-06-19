"use server";

import { api, ApiError } from "@/lib/api";

// Sets the signed-in user's password (and clears the forced-rotation flag for an invited
// member). The session stays valid, so the client just navigates back into the app.
export async function changePasswordAction(
  current: string,
  next: string,
): Promise<{ ok: true } | { error: string }> {
  if (next.length < 8) return { error: "Your new password must be at least 8 characters." };
  if (next === current) return { error: "Your new password must be different from the current one." };
  try {
    await api.changePassword(current, next);
    return { ok: true };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return { error: "Your current password is incorrect." };
    if (e instanceof ApiError && e.status === 400) return { error: "Please choose a different password (at least 8 characters)." };
    return { error: "Couldn't update your password. Please try again." };
  }
}
