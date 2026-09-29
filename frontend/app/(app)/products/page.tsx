import { Boxes, CheckCircle2, Link2, EyeOff, FileText, AlertTriangle, Plus } from "lucide-react";
import { api } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { CONNECTION_TABS } from "@/lib/tabs";
import type { ConfirmedProduct, ProductAsset, ProductLink } from "@/lib/types";
import { confirmProduct, addToProduct, removeFromProduct, removeProduct, setScope } from "./actions";

export const dynamic = "force-dynamic";

// Products — the scope of the security review your customers run (ADR 0028 G2).
//
// WHAT THIS PAGE MUST NOT DO, and why each field below is rendered rather than summarised:
//
//   1. Never let a proposal look like a decision. A proposal is the platform's inference from links it
//      can prove; a product exists only once a named person confirms it. Confirmed products carry
//      "confirmed by <name> on <date>" because that sentence is what the report hands a reviewer.
//   2. Never hide what a grouping rests on. links_note is the server's own statement of the basis,
//      rendered VERBATIM, and every proposal lists the concrete link behind each join.
//   3. Never present infrastructure as a product of its own. A repository that deploys into an account
//      is shown as "these belong together — which product do they serve?", not as a second product.
//   4. Never let a scope shrink silently. A member that no longer exists is named on the product.
export default async function ProductsPage() {
  const [v, me] = await Promise.all([api.products(), api.me()]);
  const who = me?.name || me?.email || "you";

  return (
    <div className="space-y-6">
      <PageTabs tabs={CONNECTION_TABS} />
      <PageIntro
        icon={Boxes}
        title="Products"
        description="The things your customers buy and review. When a customer's security reviewer asks whether your report covers what they are buying, this is the answer: the assets that make up each product, confirmed by a named person on your side. We suggest groupings from links we can prove; you confirm them."
      />

      {v.deploy_links_unavailable && (
        <div className="card flex items-start gap-2 px-4 py-3 text-sm text-muted">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-high" />
          <span>
            We could not read your cloud and code connections just now, so links from a repository to the
            cloud account it deploys into are missing below. Groupings by domain are unaffected.
          </span>
        </div>
      )}

      {/* ── Confirmed products ─────────────────────────────────────────────────────────── */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-ink">Your products</h2>
        {v.products.length === 0 ? (
          <Empty>
            No product confirmed yet. Until you confirm one, reports cover every connected asset, including
            anything that is not part of what your customers buy.
          </Empty>
        ) : (
          v.products.map((p) => <ProductCard key={p.id} p={p} />)
        )}
      </section>

      {/* ── Proposals ───────────────────────────────────────────────────────────────────── */}
      {v.proposals.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-ink">Suggested products</h2>
          {v.links_note && <p className="text-xs text-muted">{v.links_note}</p>}
          {v.proposals.map((pr, i) => (
            <form key={i} action={confirmProduct} className="card space-y-3 px-5 py-4">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  name="name"
                  defaultValue={pr.name}
                  aria-label="Product name"
                  className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm font-medium text-ink"
                />
                <span className="text-xs text-muted">Untick anything that is not part of this product.</span>
              </div>
              <ul className="space-y-1.5">
                {pr.assets.map((a) => (
                  <li key={a.id} className="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="asset_ids" value={a.id} defaultChecked />
                    <AssetLabel a={a} />
                  </li>
                ))}
              </ul>
              <LinkReasons links={pr.links} />
              <button className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-hover">
                <CheckCircle2 className="h-4 w-4" /> Confirm as a product
              </button>
              <p className="text-[11px] text-faint">Recorded as confirmed by {who}.</p>
            </form>
          ))}
        </section>
      )}

      {/* ── Unassigned ──────────────────────────────────────────────────────────────────── */}
      {v.unassigned.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-ink">Not in a product yet</h2>
          <p className="text-xs text-muted">
            We could not prove which product these belong to, so we have not guessed. Add them where they
            belong, or mark them out of scope.
          </p>
          {v.unassigned.map((g, i) => (
            <div key={i} className="card space-y-3 px-5 py-4">
              {g.assets.length > 1 && (
                <div className="text-xs font-medium text-ink">These belong together. Which product do they serve?</div>
              )}
              <ul className="space-y-1.5">
                {g.assets.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-2 text-sm">
                    <AssetLabel a={a} />
                    <ExcludeForm assetID={a.id} />
                  </li>
                ))}
              </ul>
              <LinkReasons links={g.links} />
              <div className="flex flex-wrap gap-3">
                {v.products.length > 0 && (
                  <form action={addToProduct} className="flex items-center gap-2">
                    {g.assets.map((a) => (
                      <input key={a.id} type="hidden" name="asset_ids" value={a.id} />
                    ))}
                    <select name="product_id" className="rounded-lg border border-border bg-surface px-2 py-1.5 text-sm" aria-label="Product">
                      {v.products.map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                    </select>
                    {/* the current members of every product ride along so the whole scope is re-confirmed */}
                    {v.products.map((p) =>
                      p.assets.map((a) => <input key={p.id + a.id} type="hidden" name={`current_${p.id}`} value={a.id} />),
                    )}
                    <AddButton label={g.assets.length > 1 ? "Add these to product" : "Add to product"} />
                  </form>
                )}
                <form action={confirmProduct} className="flex items-center gap-2">
                  {g.assets.map((a) => (
                    <input key={a.id} type="hidden" name="asset_ids" value={a.id} />
                  ))}
                  <input
                    name="name"
                    required
                    placeholder="New product name"
                    className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
                  />
                  <AddButton label="Create product" />
                </form>
              </div>
            </div>
          ))}
        </section>
      )}

      {/* ── Out of scope ────────────────────────────────────────────────────────────────── */}
      {v.out_of_scope.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-ink">Out of scope</h2>
          <div className="card divide-y divide-border">
            {v.out_of_scope.map((o) => (
              <div key={o.asset.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                <EyeOff className="h-4 w-4 text-muted" />
                <AssetLabel a={o.asset} />
                <span className="text-xs text-muted">
                  excluded by {o.by} on {day(o.at)}
                  {o.reason ? ` · ${o.reason}` : ""}
                </span>
                <form action={setScope} className="ml-auto">
                  <input type="hidden" name="asset_id" value={o.asset.id} />
                  <input type="hidden" name="out_of_scope" value="0" />
                  <button className="text-xs text-accent hover:underline">Bring back into scope</button>
                </form>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function ProductCard({ p }: { p: ConfirmedProduct }) {
  const e = p.exposure;
  const current = p.assets.map((a) => a.id);
  return (
    <div className="card space-y-3 px-5 py-4">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-base font-semibold text-ink">{p.name}</span>
        <span className="text-xs text-muted">
          confirmed by {p.confirmed_by} on {day(p.confirmed_at)}
        </span>
        <div className="ml-auto flex items-center gap-3 text-xs">
          <a href={`/api/vapt?format=html&product=${encodeURIComponent(p.id)}`} target="_blank" rel="noreferrer"
            className="inline-flex items-center gap-1 text-accent hover:underline">
            <FileText className="h-3.5 w-3.5" /> Report for this product
          </a>
          <form action={removeProduct}>
            <input type="hidden" name="product_id" value={p.id} />
            <button className="text-muted hover:text-critical">Remove</button>
          </form>
        </div>
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
        <span className="text-muted">Open issues:</span>
        {e.total === 0 ? (
          <span className="text-muted">none on these assets</span>
        ) : (
          <>
            {e.critical > 0 && <span className="text-critical">{e.critical} critical</span>}
            {e.high > 0 && <span className="text-high">{e.high} high</span>}
            {e.medium > 0 && <span className="text-medium">{e.medium} medium</span>}
            {e.low > 0 && <span className="text-low">{e.low} low</span>}
            {e.info > 0 && <span className="text-muted">{e.info} info</span>}
          </>
        )}
      </div>

      <ul className="space-y-1.5">
        {p.assets.map((a) => (
          <li key={a.id} className="flex flex-wrap items-center gap-2 text-sm">
            <AssetLabel a={a} />
            {a.shared && <span className="rounded-full border border-border px-1.5 text-[10px] text-muted">also in another product</span>}
            <form action={removeFromProduct} className="ml-auto">
              <input type="hidden" name="product_id" value={p.id} />
              <input type="hidden" name="asset_id" value={a.id} />
              {current.map((id) => <input key={id} type="hidden" name="current" value={id} />)}
              <button className="text-xs text-muted hover:text-critical">Remove from product</button>
            </form>
          </li>
        ))}
      </ul>

      {p.missing_asset_ids && p.missing_asset_ids.length > 0 && (
        <p className="flex items-start gap-1.5 text-xs text-high">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          {p.missing_asset_ids.length} asset{p.missing_asset_ids.length === 1 ? " was" : "s were"} confirmed
          as part of this product and no longer exist. The product is smaller than what was confirmed.
          Re-confirm it so the report matches.
        </p>
      )}

      {p.suggestions.length > 0 && (
        <div className="space-y-2 rounded-lg border border-accent/20 bg-accent-soft/20 p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">Linked to this product, not yet in it</div>
          {p.suggestions.map((s) => (
            <form key={s.asset.id} action={addToProduct} className="flex flex-wrap items-center gap-2 text-sm">
              <input type="hidden" name="product_id" value={p.id} />
              <input type="hidden" name="asset_ids" value={s.asset.id} />
              {current.map((id) => <input key={id} type="hidden" name="current" value={id} />)}
              <AssetLabel a={s.asset} />
              <span className="text-xs text-muted">{s.why}</span>
              <AddButton label="Add" />
            </form>
          ))}
        </div>
      )}
    </div>
  );
}

function AssetLabel({ a }: { a: ProductAsset }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted">{kind(a.type)}</span>
      <code className="text-ink">{a.target}</code>
    </span>
  );
}

function LinkReasons({ links }: { links: ProductLink[] }) {
  if (!links || links.length === 0) return null;
  return (
    <ul className="space-y-1">
      {links.map((l, i) => (
        <li key={i} className="flex items-start gap-1.5 text-xs text-muted">
          <Link2 className="mt-0.5 h-3 w-3 shrink-0" />
          <span>{l.why}</span>
        </li>
      ))}
    </ul>
  );
}

function ExcludeForm({ assetID }: { assetID: string }) {
  return (
    <form action={setScope} className="ml-auto flex items-center gap-1.5">
      <input type="hidden" name="asset_id" value={assetID} />
      <input type="hidden" name="out_of_scope" value="1" />
      <input name="reason" placeholder="Why (e.g. marketing site)" className="w-44 rounded-lg border border-border bg-surface px-2 py-1 text-xs" />
      <button className="text-xs text-muted hover:text-ink">Out of scope</button>
    </form>
  );
}

function AddButton({ label }: { label: string }) {
  return (
    <button className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent">
      <Plus className="h-3.5 w-3.5" /> {label}
    </button>
  );
}

function kind(t: string): string {
  switch (t) {
    case "web_application": return "web";
    case "api": return "api";
    case "domain": return "domain";
    case "repository": return "repo";
    case "cloud_account": return "cloud";
    case "container_image": return "image";
    case "ip_address": return "ip";
    default: return t;
  }
}

function day(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "" : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}
