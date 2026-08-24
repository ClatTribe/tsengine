# Releasing tsengine

One `v*` tag triggers **two workflows** that publish **twelve artifacts**. Nothing documented that
relationship until this file, and the second publisher was added the same day — so if you are cutting
the first release, read this rather than inferring the process from the workflow files.

Everything below is derived from `.github/workflows/release.yml`, `images.yml` and `signatures.yml`
as they actually are, not from intent.

---

## 1. What a tag does

Pushing a tag matching `v*` fires **both** of these, concurrently and independently:

| Workflow | Publishes |
|---|---|
| `release.yml` | Cross-platform `tsengine` CLI binaries (linux/darwin × amd64/arm64) + `checksums.txt`, a GitHub Release with generated notes, and `ghcr.io/clattribe/tsengine/host:<tag>` + `:latest` |
| `images.yml` | `platform` and `frontend` images (multi-arch), and the `sandbox` image **once per toolset** — `full`, `web`, `api`, `repository`, `container`, `ip`, `domain`, `cloud` |

Neither waits for the other and neither checks the other succeeded. A partial release is possible:
the GitHub Release can exist while an image build failed. **Verify both before announcing** (§4).

### Tag taxonomy

```
ghcr.io/clattribe/tsengine/host:v1.2.3          ghcr.io/clattribe/tsengine/host:latest
ghcr.io/clattribe/tsengine/platform:v1.2.3      ghcr.io/clattribe/tsengine/platform:latest      :sha-abc1234
ghcr.io/clattribe/tsengine/frontend:v1.2.3      ghcr.io/clattribe/tsengine/frontend:latest      :sha-abc1234
ghcr.io/clattribe/tsengine/sandbox:full-v1.2.3  ghcr.io/clattribe/tsengine/sandbox:full-latest
ghcr.io/clattribe/tsengine/sandbox:web-v1.2.3   ghcr.io/clattribe/tsengine/sandbox:web-latest    … and six more toolsets
```

The sandbox is tagged `<toolset>-<version>`, NOT `<version>-<toolset>`. That order is load-bearing:
`TSENGINE_SANDBOX_IMAGE_TEMPLATE` substitutes `{toolset}` into a ref like
`ghcr.io/clattribe/tsengine/sandbox:{toolset}-latest`, so the toolset must be the leading component.

### The version is not one number across the estate

`release.yml` stamps `main.Version` into the CLI from the tag. `images.yml` passes the same tag as
`VERSION` to the platform image. The **frontend takes no version at all**, and the **sandbox's
contents are pinned in the Dockerfile, not by the tag** — `sandbox:full-v1.2.3` means "the toolset as
pinned at tag v1.2.3", and a scanner version only changes when someone edits the Dockerfile. So
`tool-freshness` is the source of truth for what a sandbox contains; the tag is only a pointer.

---

## 2. Before you tag

Run these; each has caught a real defect.

```bash
make gate                                   # gofmt + vet + test + frontend typecheck, fails rather than reports
go test -race ./...                         # CI runs race; a local non-race pass is not the same evidence
go run ./cmd/tsengine tool-freshness --fail-on-floating
```

Then confirm, because these are the ones that have actually gone wrong:

- [ ] **`main` is green.** Not your branch — `main`. Both publishers build from the tag.
- [ ] **A `full` sandbox image builds.** `make sandbox-image`. `verify-tools.sh` runs as the final
      build step and fails when a scanner is missing or stubbed. This is not theatre: codeql and kics
      were absent from every image for months because their installs 404'd behind `|| echo`.
- [ ] **Repo variables are set** — `NEXT_PUBLIC_SITE_URL`, `NEXT_PUBLIC_LEGAL_ENTITY`, and the other
      `NEXT_PUBLIC_*`. They are inlined into the frontend bundle at BUILD time, so a wrong value ships
      until the next release. An unset variable arrives as an EMPTY STRING, not as unset.
- [ ] **The tag is on the commit you think it is.** `git log --oneline -1 <tag>`.

---

## 3. Cutting it

```bash
git checkout main && git pull
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

**The first `images.yml` run is slow.** Eight sandbox builds, each multi-GB, on a cold GHA layer
cache — allow an hour and do not cut a release into a deadline. Subsequent runs reuse a per-toolset
cache scope. Trigger one manually (`workflow_dispatch`) well before the first real release, so the
first time you exercise this path is not the day it matters.

`workflow_dispatch` also takes `sandbox_arm64` — off by default because it roughly doubles the
matrix. codeql has no arm64 build upstream and is stubbed there by design, so an arm64 sandbox has no
taint-analysis escalation.

---

## 4. After you tag — verify both, not one

```bash
gh run list --limit 5                        # Release AND Images must both be green
docker pull ghcr.io/clattribe/tsengine/platform:v1.2.3
docker pull ghcr.io/clattribe/tsengine/sandbox:full-v1.2.3
docker run --rm --entrypoint sh ghcr.io/clattribe/tsengine/sandbox:full-v1.2.3 -c /usr/local/bin/verify-tools.sh
```

That last command is the one worth running: it re-asserts inside the shipped image that every scanner
binary is present and non-stubbed. A green build already checked it, but a pulled image is what the
customer actually runs.

---

## 5. Rolling back

**Deployments track moving tags by default, so a rollback is a pin, not a revert.**
`docker-compose.prod.yml` defaults to `platform:latest`, `frontend:latest` and
`sandbox:full-latest`. Re-tagging or publishing a newer release moves those under running
deployments.

To roll back, pin the previous version in `.env` and redeploy:

```bash
PLATFORM_IMAGE=ghcr.io/clattribe/tsengine/platform:v1.2.2
FRONTEND_IMAGE=ghcr.io/clattribe/tsengine/frontend:v1.2.2
TSENGINE_SANDBOX_IMAGE=ghcr.io/clattribe/tsengine/sandbox:full-v1.2.2
```

Do **not** delete or move a published tag to undo a release. A scan records
`sandbox_image_digest` as evidence (CLAUDE.md §6), and an evidence pack that points at a digest
nobody can pull stops being evidence. Publish a new version instead.

For production, prefer pinning every deployment to explicit versions and treating `latest` as a
convenience for demos. A moving tag under a compliance product means an auditor cannot reproduce what
tested the customer.

---

## 6. The weekly signature refresh is not a release

`signatures.yml` runs Mondays 04:10 UTC and calls `images.yml` with `images: sandbox`, republishing
`<toolset>-latest` plus a dated `<toolset>-signatures-<run_id>`. Its purpose is moving the BAKED
corpora — principally the nuclei templates, which are fetched at image build and otherwise age with
the release cadence.

Consequences worth knowing:

- A deployment on `sandbox:full-latest` **silently picks up new scanners weekly**. That is the intent
  (fresh signatures) and it is also drift: two scans a fortnight apart ran different corpora. Pin to
  `<toolset>-signatures-<run_id>` if you need reproducibility across that boundary.
- It does NOT rebuild `platform` or `frontend` — the `app` job is skipped when called with
  `images: sandbox`.
- `trivy`, `grype` and `semgrep` fetch their own databases per scan, so those are fresh regardless of
  image age. Only the baked corpora move on this schedule.
- The `report` job runs `tool-freshness --fail-on-floating` on every PR touching the Dockerfile, so a
  reintroduced `latest` ref fails before it can reach a release.

---

## 7. Versioning

No formal policy is in force. What the tooling assumes: a `v`-prefixed, semver-shaped tag, used
verbatim as an image tag and stamped into the CLI. `v1.2.3-rc1` works everywhere mechanically — but
note it would also move `:latest`, since `images.yml` applies `latest` to any `refs/tags/v*`. If you
want pre-release tags that do not move `latest`, that guard has to be added first.
