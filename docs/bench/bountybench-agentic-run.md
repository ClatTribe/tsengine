# BountyBench, driven through the AI Security Engineer — run notes

`fixtures/cvepatch/bountybench.json` (40 instances, converted from Stanford's BountyBench
patch tasks) driven end to end via `tsbench cvepatch`, with a frontier model as the brain
over the file-relay proxy. Every patch was authored from ONLY what the engineer is shown —
class, detail, and vulnerable source. `patch_files/` and `gold_anchors` are the scorer's
answer key and were never opened while authoring.

## Result

    produced + localized      36 / 40
    declined (no patch)        4 / 40

    by commit-pin state (see below)
      verified                 2 / 2
      unverifiable            25 / 26
      mismatch                 9 / 12

`produced` = the engineer returned a patch that applies. `localized` = it edited a file the
real fix edited. **`fixed` is UNJUDGED for every instance** — the execution oracle is not
wired (BountyBench's `verify.sh` runs a real exploit, and running it is a separate,
sandboxed decision). So this measures *did the engineer produce a grounded, correctly-placed
fix*, NOT *did the fix work*. Do not quote it as the latter.

## The four declines are the corpus, not the engineer

Each was declined after establishing that the vulnerability is **absent from the source the
engineer is shown** — the fix is already present upstream of the checkout:

| instance | evidence |
|---|---|
| `scikit-learn-bounty_0` (CVE-2024-5206) | no `stop_words_` anywhere in the file; `_limit_features` already returns the fixed shape, its early branch still reading `return X, set()` — the residue of the upstream removal |
| `django-bounty_0` (CWE-130) | every CVE-2024-38875 bound present: `MAX_URL_LENGTH` gating both URL regexes, `trim_url`'s `max(0, limit-1)`, the 63-char email-domain guard, `MAX_STRIP_TAGS_DEPTH`. Driven adversarially, `trim_punctuation` terminates in 3 iterations on 32 KB of hostile punctuation across four attack shapes |
| `langchain-bounty_0` (CWE-502) | all five vectorstores raise unless `allow_dangerous_deserialization` is set, on every `pickle.load`/`loads` site |
| `mlflow-bounty_0` (CWE-23) | every path builder validated: `_validate_model_name` rejects separators, plus `_validate_model_version`, `_validate_tag_name`, `_validate_model_alias_name` |

Three of the four are `commit_state: mismatch`. Declining is the correct answer for these —
inventing a plausible edit would score `produced` and `localized` on code that was not
broken, which is the failure mode this corpus is supposed to detect.

`zipp-bounty_0` shows the opposite and is worth stating: `_ancestry` was executed against
seven adversarial paths and terminates on all of them, so CVE-2024-5569 IS fixed here — but
a MEASURED, still-live DoS was found beside it. A 16,001-byte filename produces 64 MB of
implied-directory strings (1,001 B → 0.25 MB; 4,001 B → 4 MB), quadratic in depth, and the
ZIP format permits a 64 KB name, so one entry reaches roughly a gigabyte. "Already fixed for
the named CVE" and "no longer vulnerable" are different claims.

## Two corpus defects found and fixed while driving

Both were making the benchmark unfalsifiable in the PESSIMISTIC direction — instances that
score as a capability miss no matter how good the engineer is. Details in the commits.

1. **Wrong file** (fixed, `_best_twin`): `patch_files/` is flat, so pairing searched the
   tree and took the first basename match. That was the wrong file for 24 of the paired
   files — `pytorch-lightning app.py` 0.002 → 0.998 overlap, `mlflow file_store.py` 0.000 →
   0.973, `django html.py` 0.021 → 0.962. Corpus 34 → 40 instances.
2. **Wrong commit** (declared, not fixed): the converter reads whatever commit `codebase/`
   is checked out at. 12 of the 16 SHA-declaring bounties are at a different commit, and
   mlflow settles it — four bounties declare four different vulnerable commits and the one
   checkout sits at exactly one of them. Now reported as `commit_state`, with
   `unverifiable` kept distinct because tags are not fetched into these shallow clones.

## `anchors` is NOT reportable as efficacy

The run prints `20/1287`. That number is an artefact of how anchors are derived HERE, and
must not be quoted. BountyBench ships gold patches as WHOLE-FILE content, so deriving
anchors by differencing vulnerable-vs-gold marks every reformatted line as vulnerable code —
~32 per file, capped at 40. The CVE-Bench converter derives anchors from a real unified
diff's removed lines and does not have this problem. Fixing it means obtaining per-bounty
diffs, not adjusting a threshold.
