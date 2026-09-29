"use server";

import { revalidatePath } from "next/cache";
import { api } from "@/lib/api";

// Products — every write here is a scoping decision a named person makes (ADR 0028 G2).
//
// The confirmer is ALWAYS the signed-in person, never an anonymous string: a product's scope ends up
// on the report a customer's reviewer reads ("confirmed by <name>"), and a scope agreed to by nobody
// is the same overclaim as a report signed by nobody. The server refuses an empty confirmer too; this
// is the second lock, not the only one.
async function confirmer(): Promise<string> {
  const me = await api.me();
  const who = (me?.name?.trim() || me?.email?.trim() || "").trim();
  if (!who) throw new Error("You need to be signed in to confirm a product's scope.");
  return who;
}

function ids(formData: FormData, key: string): string[] {
  return formData.getAll(key).map((v) => String(v).trim()).filter(Boolean);
}

function done() {
  revalidatePath("/products");
  revalidatePath("/reports");
}

// Confirm a proposal (or a hand-picked set of unassigned assets) as a product.
export async function confirmProduct(formData: FormData): Promise<void> {
  const name = String(formData.get("name") ?? "").trim();
  const assetIDs = ids(formData, "asset_ids");
  await api.createProduct({ name, asset_ids: assetIDs, confirmed_by: await confirmer(),
    owner: String(formData.get("owner") ?? "").trim() || undefined });
  done();
}

// Add assets to an existing product. The FULL membership is sent and re-confirmed by the person
// clicking: a scope edited by one person and "confirmed" by another is not a confirmation of what
// it now contains.
export async function addToProduct(formData: FormData): Promise<void> {
  const id = String(formData.get("product_id") ?? "");
  // The update REPLACES the membership, so the product's existing members must ride along or they are
  // dropped. A form bound to one product sends them as "current"; the unassigned form offers a choice
  // of products, so it sends every product's members as "current_<id>" and we take the chosen one's.
  const current = [...ids(formData, "current"), ...ids(formData, `current_${id}`)];
  if (current.length === 0) {
    // Refuse rather than risk it: an add that arrives with no existing members would shrink a
    // confirmed product to just the new asset. Every product has at least one member, so this is a
    // broken form, not a real state.
    throw new Error("Could not read this product's current assets — nothing was changed.");
  }
  const next = Array.from(new Set([...current, ...ids(formData, "asset_ids")]));
  await api.updateProduct(id, { asset_ids: next, confirmed_by: await confirmer() });
  done();
}

export async function removeFromProduct(formData: FormData): Promise<void> {
  const id = String(formData.get("product_id") ?? "");
  const drop = String(formData.get("asset_id") ?? "");
  const next = ids(formData, "current").filter((a) => a !== drop);
  await api.updateProduct(id, { asset_ids: next, confirmed_by: await confirmer() });
  done();
}

export async function removeProduct(formData: FormData): Promise<void> {
  await api.deleteProduct(String(formData.get("product_id") ?? ""));
  done();
}

// Out of scope is recorded with who and why — "we decided this is not what customers review" is itself
// part of the scope a reviewer reads. Bringing an asset back needs no reason.
export async function setScope(formData: FormData): Promise<void> {
  const out = String(formData.get("out_of_scope") ?? "") === "1";
  await api.setAssetScope({
    asset_id: String(formData.get("asset_id") ?? ""),
    out_of_scope: out,
    by: await confirmer(),
    reason: String(formData.get("reason") ?? "").trim() || undefined,
  });
  done();
}
