"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";
import type { DatabaseScanResult } from "@/lib/types";

// Scan a Postgres the customer names, once, from a connection string they paste.
//
// The DSN is passed through to the API and never stored — not by us, not in the form. It is the one
// integration in this segment's stack that needs no OAuth app and no connector build, so it is worth
// a real control rather than an endpoint documented in an empty state.
export async function scanDatabase(dsn: string, sampleValues: boolean): Promise<DatabaseScanResult> {
  const res = await api.scanDatabase(dsn, sampleValues);
  // New findings land in the shared store, so the surfaces that read it are now stale.
  revalidatePath("/posture");
  revalidatePath("/issues");
  revalidatePath("/dashboard");
  return res;
}
