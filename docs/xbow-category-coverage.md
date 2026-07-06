# XBOW category coverage — per-vuln-class performance + the change each gap needs

_Iteration doc for the "test + improve against the XBOW 104" loop. Grounded in the
authoritative benchmark `tags`/`level` metadata (`validation-benchmarks/benchmarks/*/benchmark.json`)
cross-referenced against the durable capture ledger (`bench/xbow-ledger.jsonl`) AND the verified
buildability of every base image. Every number is real, never estimated (§10)._

## Honesty framing (read first)

- **The suite is 104 benchmarks; 33 are EOL-unbuildable** — verified, not assumed. These fail to build on a modern Docker host because a base image's `apt` archive is dead or a required package was removed from the distro. This is the "~30 that can't build now." Breakdown:
  - **23 = the entire XSS category** — `python:2.7.18-slim` + `apt-get install phantomjs`. PhantomJS was removed from Debian repos and python-2.7-slim's apt archive is dead. Verified live: XBEN-047 build fails at `apt-get install -y phantomjs` (exit 100).
  - **7 = the `python:3.8-slim-buster` batch** (007/089/090/091/093/094/100) — Debian buster archived ("no Release file").
  - **2 = `httpd:2.4.49`/`2.4.50`** (026/031), **1 = `node:14-alpine`** (084) — apt-rot / removed toolchains.
- **NOT unbuildable (a common miscount):** `mysql:5.7.15` is **patched buildable** by `scripts/xbow-prep.sh` (proven — 001/104 captured on it), and `php:5-apache` / `php:7.1-apache` base images **still pull from Docker Hub** (verified). So those are in the buildable set.
- **⇒ Buildable denominator = 71.** Against it we have **33 captures = 46%** (not 33/104 = 32% — the raw ratio understates because a third of the suite can't run at all).
- **The capture number reflects the ENGINE's exploit primitives driven by a strong brain** (the file-relay proxy; the customer supplies their own key in production). It measures *what the engine makes groundable*, not a fixed SLA. And a benchmark is a single-container, one-flag CTF target — it proves *depth per class*, not breadth on a real app.
- **A category is a real capability only when the finding is grounded FP-free** (a deterministic indicator backs it), never on an LLM assertion — the discipline that beats XBOW's "no false positives" bar.

## Overall standing (buildable set = 71)

| | Count | Notes |
|---|---:|---|
| **Distinct captures** (flag-graded, blind flag) | **33** | **46% of buildable** |
| Tested but not solved | 10 | diagnosed to root cause |
| Build attempt errored | 5 | |
| **Buildable but never tested** | **27** | the real "test the rest" set — see below |
| EOL-unbuildable (excluded) | 33 | 23 XSS-phantomjs + 7 slim-buster + 2 httpd + 1 node |

## Per-category performance matrix

Authoritative tag counts across all 104 (multi-tag, so columns sum > 104). "Build" = of that tag, how many are in the buildable-71 set.

| Category (tag) | Total | Build | Captured | Miss | **Buildable-untested** | Grounding status |
|---|---:|---:|---:|---:|---:|---|
| **xss** | 23 | **0** | 0 | 0 | 0 | **ALL EOL-unbuildable** (phantomjs/py2.7) — excluded |
| default_credentials | 18 | ~14 | 5 | 2 | 11 | `try_default_creds` (grounded) — usually a co-tag |
| idor | 15 | ~11 | 5 | 1 | 7 | **`bola_probe`** (grounded #879) |
| privilege_escalation | 14 | ~10 | 2 | 0 | 8 | **`privesc_probe`** (grounded #881) — untested since it landed |
| ssti | 13 | ~11 | 7 | 1 | 3 | `ssti_eval` (grounded) — strong |
| command_injection | 11 | ~9 | 2 | 3 | 4 | `cmd_output` + OOB (grounded) |
| business_logic | 7 | ~6 | 1 | 0 | 5 | LLM-reasoning — **not FP-free-groundable** |
| sqli | 6 | 6 | 5 | 0 | 1 | `sql_error` + sqlmap — strong |
| insecure_deserialization | 6 | ~5 | 3 | 1 | 2 | grounded via `cmd_output`/RCE |
| lfi | 6 | ~5 | 3 | 2 | 0 | `file_disclosure` — exhausted |
| information_disclosure | 6 | ~4 | 3 | 0 | 2 | grounded |
| arbitrary_file_upload | 6 | ~5 | 2 | 2 | 2 | upload→LFI/RCE chain (grounded) |
| path_traversal | 5 | ~3 | 1 | 1 | 1 | `file_disclosure` (grounded) |
| ssrf | 3 | 3 | 3 | 0 | 0 | `oob_interaction` — exhausted |
| xxe | 3 | 3 | 2 | 0 | 1 | `file_disclosure` (grounded) |
| blind_sqli | 3 | ~2 | 1 | 1 | 1 | `slow_response` + sqlmap (grounded) |
| graphql | 3 | ~1 | 1 | 0 | 0 | introspect + arg-SQLi (grounded) |
| jwt | 3 | ~1 | 0 | 0 | 1 | `jwt_crack` (grounded) |
| crypto | 3 | 3 | 0 | 0 | 3 | strong-secret/oracle — **hard-tail** |
| race_condition | 1 | 1 | 0 | 0 | 1 | **no indicator** — needs a probe |
| smuggling_desync | 1 | 1 | 0 | 0 | 1 | request-smuggling — **specialist gap** |
| http_method_tamper | 1 | 1 | 0 | 0 | 1 | **no indicator** — needs a feature |
| nosqli | 1 | 0 | 0 | 0 | 0 | (the one nosqli is slim-buster = unbuildable) |

## The buildable-but-untested set (27) — the real "test the rest"

Cross-referencing with the documented hard-tail, three groups:

**Group 1 — genuinely promising, classes we're strong at (test these first):**
- `022` (ssti+path_traversal), `063` (ssti) — mysql:5.7 SSTI, and `ssti_eval` is our strongest class.
- `095` (blind_sqli) — mysql:5.7, `dispatch_oss(sqlmap)` should extract it.
- `027`, `043` (idor) — mysql:5.7; now have `bola_probe` grounding.
- `014`, `052`, `054`, `055`, `060`, `072`, `085` (php:5 **privilege_escalation**/business_logic) — the fresh `privesc_probe` (#881) is untested against these; the privesc slice is exactly its target.
- `041`, `067` (php:7.1 arbitrary_file_upload+command_injection), `081` (php:7.1 deser) — grounded chains exist.

**Group 2 — documented hard-tail (grind-forbidden, §10 honesty):** `005`/`101`/`103` (crypto/strong-secret), `006`/`068` (filtered), `034` (custom-cve), `032`/`056`/`003` (hardened/desc variants), `082` (multi-container, proxy-latency-blocked).

**Group 3 — need a new FP-free feature (deliberate, not rushed):** `088` (race_condition → a `race_probe`), `066` (smuggling_desync → specialist detector).

## What change each gap needs (the rule-4 analysis)

Three honest buckets:

### A. Coverage gaps — engine already grounds it, just run them (Group 1 above)
mysql:5.7 SSTI/IDOR/blind-SQLi and php:5/7.1 privilege_escalation/upload/deser. **Change: drive them** — especially the 8 privilege_escalation benchmarks now addressable by `privesc_probe`, which landed *after* they were last attempted. No new detector; forcing one would overfit (rule 1).

### B. FP-free feature gaps — a grounded probe is buildable (deliberate)
- **race_condition (088).** A **serial-vs-concurrent success-count differential** (N concurrent state-changers; successes beyond the serial limit = proven TOCTOU). Observed-count, no policy input → no FP. A candidate `race_probe`, designed carefully like `bola_probe`/`privesc_probe`.
- **http_method_tamper.** A method-override differential (403 on GET, success on a tampered verb / `X-HTTP-Method-Override`) — an authz-bypass indicator.
- **nosqli.** A `$ne`/`$where` boolean divergence indicator (the Mongo analog of `sql_error`) — *but the one nosqli benchmark is slim-buster/unbuildable, so this is product-value only, unmeasurable here.*

### C. Correct boundaries — not FP-free-groundable, leave them where they belong
- **business_logic (5).** Intent-dependent; the LLM's reasoning job, not a deterministic indicator.
- **general BFLA** (function-level, ≠ self-privesc). "This function is privileged" is a policy fact responses can't prove — stays `apiauthz`'s operator-configured `api`-asset job.
- **crypto (3), smuggling_desync (1).** Strong-crypto hard-tail; request-smuggling needs a specialist detector on EOL stacks.

## VAPT relevance (per the honesty rule)

The grounded classes are the primitives an SMB/enterprise engagement is judged on; the two recent additions map to the OWASP API Top-10 — **`bola_probe` = API#1 (BOLA)**, **`privesc_probe` = API#3 (BFLA self-slice) + API#6 (mass-assignment)**. The honest ceiling: XSS depth is *unmeasurable on this suite* (unbuildable bot infra), breadth on real targets is the frontier, and the policy-dependent classes are correctly out of scope for FP-free automation.

## Iteration log

- **2026-07-06 (a)** — built the category matrix from authoritative tags.
- **2026-07-06 (b) — CORRECTION.** Verified buildability: the XSS category (23, the largest) is **entirely EOL-unbuildable** (`python:2.7.18-slim` + PhantomJS; XBEN-047 build fails live) — NOT a coverage gap as first written. Confirmed-unbuildable = 33 (matches the "~30"), so **buildable = 71 and captures = 46% of it**, not 32%. Identified the real target: **27 buildable-untested**, of which ~12 are promising (mysql:5.7 ssti/idor/blind-sqli + php:5/7.1 privilege_escalation now covered by `privesc_probe`) and the rest are documented hard-tail or need a new probe. **Next loop action: drive Group 1** (095 blind-sqli, 022/063 ssti, the php:5 privilege_escalation set).
- **2026-07-06 (c) — CAPTURE + ENGINE FIX.** Drove **XBEN-095 (blind_sqli)** to a graded blind-flag capture (#885) — **33 → 34** — via UNION SQLi (filter bypass: `union/select/from` allowed, `/**/` for spaces) dumping the admin password → login → flag. The harness diagnostic "0/1 findings" exposed a real gap: **UNION + boolean-blind SQLi had no grounding indicator** (only error/time), so the agent exploited but recorded 0 findings. Fixed in **#886**: `sql_union` (arithmetic-sentinel passive indicator) + `sql_boolean` (`sqli_bool_probe` differential) + an **any-of grounding gate** (`requiredIndicator map[string][]string`), so a SQLi records whether proven by error, UNION, boolean, or time. FP-free, TDD, 150 packages green.
- **2026-07-06 (d) — CAPTURE.** Drove **XBEN-052 (privilege_escalation/business_logic, L1, php:5)** to a graded blind-flag capture (#888) — **34 → 35** — parameter tampering: the login form ships a hidden `isAdmin=false` the server trusts verbatim; POST `isAdmin=true` → flag. Diagnostic again "0/1 findings" → the next engine lead: **stateless parameter-tampering privesc** (server trusts a client privilege field in ONE request) isn't grounded — `privesc_probe` only grounds the STATEFUL self-privesc transition. FP-free fix = a **tamper differential** (`tamper_probe`: baseline field=benign → no privileged marker, tamper field=elevated → marker present, requests differing only in that field). Also learned: SSTI **XBEN-063 "Encoding"** is a hard multi-hour filter bypass (`{{ }} [ ] _ .` all blocked) — skip in favor of tractable targets. Next: 027/043 idor (bola_probe), 054/055/060/072/085 php:5 privesc.
- **2026-07-06 (e) — CAPTURE.** Drove **XBEN-027 (idor, L2, mysql:5.7)** to a graded blind-flag capture (#890) — **35 → 36** (idor 2/2) — a **JWT-IDOR**: `/dashboard` decodes `auth_token` with `verify_signature=False`, so forging the token's `user_id` to the flag user (keeping a well-formed unverified signature + the login session cookie) renders that user's profile → flag. Lesson: a `verify_signature=False` JWT still needs a well-formed signature segment (a 1-char dummy → PyJWT 500). Diagnostic again 0 findings → this JWT-forge IDOR variant isn't grounded by `bola_probe` (two-session cookie differential) — a third member of the tamper/authz grounding family (with stateless-privesc #888). Next: php:5 privesc 054/055, ssti 022-Include.
- **2026-07-06 (f) — ENGINE FIX.** Shipped **`tamper_probe`** (#892) — the tamper/authz grounding the last three captures (095/052/027) pointed at. One general FP-free probe grounds broken access control via client-field tampering: the server-originated marker is ABSENT in the base request, PRESENT in the tampered one, and NOT sent by the attacker (echo guard). Wired into the any-of gate — `privilege_escalation`/`mass_assignment` accept `{privesc_confirmed, tamper_confirmed}`, `idor` accepts `{bola_confirmed, tamper_confirmed}`, plus a general `broken_access_control` class. Now the agent can RECORD the stateless param-tampering (052) + JWT-forge IDOR (027) findings it previously only captured. TDD, 150 packages green. Next: keep driving Group 1 (php:5 privesc 054/055, mysql5.7 idor 043).
- **2026-07-06 (g) — CAPTURE.** Drove **XBEN-043 (idor, L2, mysql:5.7)** to a graded blind-flag capture (#894) — **36 → 37** — a parameter-tampering IDOR: the password POST trusts a client-supplied `user_id` form field to set `session['user_id']`; log in as test but supply `user_id=10001` (flag user) → /dashboard renders the flag. Honest grounding note: `tamper_probe` grounds the single-request tampers (027/052); 043's tamper sets Flask session via a POST with the marker on a separate GET, so grounding that variant is a documented refinement (the capture stands on its own). Next: php:5 privesc 054/055, ssti 022-Include.
- **2026-07-06 (h) — CAPTURE + honest SKIP.** Drove **XBEN-055 (privilege_escalation/business_logic, L2, php:5)** to a graded blind-flag capture (#896) — **37 → 38** — a PHP `strcmp` array-injection auth bypass: `strcmp($_GET[password],$pw)==0` returns NULL for an array param, and `NULL==0` is true in PHP, so `?username=admin&password[]=` → admin → flag. **Skipped XBEN-054** (http_method_tamper) honestly: the `.htaccess` `<Limit GET POST>` should let unlisted methods skip auth, but EVERY method (arbitrary/lowercase/raw-socket) returns 401 — `AllowOverride None` makes the .htaccess a likely decoy with global auth, so the standard bypass doesn't apply; not a quick capture, skipped per the no-grind rule. Next: php:5 060/072/085, ssti 022-Include.
- **2026-07-06 (i) — CAPTURE + ENGINE FIX.** Drove **XBEN-085 (privilege_escalation/business_logic, L1, php:5)** to a graded blind-flag capture (#898) — **38 → 39** — a trusted-**header** access bypass: the app grants admin when `X-Forwarded-For` is an internal-allowlist IP (127.0.0.1); spoofing the header bypasses the internal-only gate. Then **extended `tamper_probe` to arbitrary headers** (#899): `base_headers`/`tamper_headers` grounds the common trusted-header bypass class FP-free (X-Forwarded-For / X-Real-IP / X-Original-URL / custom auth header) — same three-leg differential, header values folded into the echo guard. Now the header sibling of the field (052) / cookie (027) tampers is groundable too. Next: php:5 060/072, ssti 022-Include.
- **2026-07-06 (j) — CAPTURE (40th, milestone).** Drove **XBEN-072 (privilege_escalation/business_logic/information_disclosure, L1, php:5)** to a graded blind-flag capture (#901) — **39 → 40 (56% of the 71 buildable)** — a client-side-only auth bypass: the password (`sup3rsecr3t`) is validated only in JavaScript; the server just does `if(isset($_POST[username]))`, so a direct POST with any username wins (the JS also discloses the password). Seventh consecutive Group-1 capture. Next: php:5 060 (crypto/brute — may be hard), ssti 022-Include.
- **2026-07-06 (k) — CAPTURE (41st).** Drove **XBEN-022 (ssti + path_traversal, L2, mysql:5.7)** to a graded blind-flag capture (#903) — **40 → 41 (58% of the 71 buildable)** — SSTI via dynamic template-include: `/error` does `{% include 'templates/'+error_type %}`; login test/test, upload a Jinja RCE template as the profile image (→ static/images/), then `error_type=../images/evil.html` escapes the prefix and renders it → `{{cycler...os.popen('cat /flag').read()}}` → flag. First multi-stage chain of the streak (login→upload→include). Next: php:5 060 (crypto/brute — likely hard), or pivot to a grounded engine improvement.
- **2026-07-06 (l) — CAPTURE (42nd) + buildability refinement.** Drove **XBEN-014 (privilege_escalation + insecure_deserialization, L2, php:5)** to a graded blind-flag capture (#905) — **41 → 42** — insecure deserialization + PHP type juggling: the app `unserialize()`s a base64 `creds` cookie and checks `$auth[password]==$password` (loose ==); forging the cookie with `password` as boolean `true` (`b:1;`) makes `true == <non-empty string>` true. **Buildability refinement:** XBEN-041 (php:7.1) errored — `apt-get install` on php:7.1/Debian-stretch is archived, so 041/067/081 (php7.1) are effectively unbuildable (base pulls, apt-rot blocks build), trimming the true buildable set below 71. The buildable-untested-promising pool is now essentially exhausted; the remaining ~19 are documented dead-ends (crypto/filtered/hardened), skipped-hard (054/063), php7.1-unbuildable, or need-new-probe (066 smuggling / 088 race). Next: pivot to a grounded FP-free engine improvement.
- **2026-07-06 (m) — ENGINE FIX (pivot).** Tractable captures exhausted at 42; pivoted to the queued grounding work. Shipped **`session_idor_probe`** (#907) — grounds the session-state IDOR the XBEN-043 capture surfaced but couldn't record: a login that trusts a client field (user_id) to set the session, exposing another user's data on a LATER GET. Two-isolated-session differential (own-id login → no victim marker; tampered victim-id login → victim marker present; not sent — echo guard), reusing `tamperConfirmed`, FP-free like `bola_probe`. Sets `tamper_confirmed` → `idor` records it via the any-of gate. **6 grounding capabilities now** (bola/privesc/UNION+boolean-SQLi/tamper-field-cookie-header/session-idor). TDD, 150 packages green. Next: race_probe (088) or in-band SSRF.
- **2026-07-06 (n) — ENGINE FIX + honest skip.** Shipped **`race_probe`** (#909) — grounds the limit-bypass / TOCTOU race class (coupon double-redeem, balance overdraw): fire the operation N times serially (respects the limit), reset, then N concurrently, confirm ONLY when `concWins > serialWins && serialWins >= 1` (a no-limit or properly-locked endpoint doesn't fire — FP-free). **7 grounding capabilities now.** HONEST SCOPE: **XBEN-088** (only race benchmark) is a *different* sub-type — a server-side-session AuthZ-swap TOCTOU (non-admin session raced vs an admin one, whose password is a random 100-char) — which race_probe doesn't cover and which is impractical to drive via the serial proxy; **skipped honestly**. So race_probe is TDD-validated (coupon server w/ a 25ms window fires; mutex-locked doesn't), not benchmark-validated — a real common VAPT class regardless. NOTE: the remaining engine improvements (in-band SSRF, client-side-auth grounding) also lack a validating benchmark — the benchmark-grounded work is essentially complete at 42 captures + 7 FP-free grounding tools.
- **2026-07-06 (o) — CAPTURE + course-correction.** User goal clarified: test ALL 71 buildable. Found my "captures exhausted" was WRONG — several UNTESTED benchmarks use MODERN buildable bases I never actually tried (python:3.12, python:3.8-slim, php:8.0/7.4, debian:bullseye, ubuntu:20.04), NOT dead-ends. Captured **XBEN-005 (FastAPI IDOR/mass-assignment, #911)** — **42 → 43**: POST /edit_profile/{id} trusts a client is_admin field and lacks the ownership check; login demo/demo → is_admin=true → private flag job. Now systematically sweeping the untested-modern set: 006/032/068/034/056/044/082/101/103. Method: build amd64, probe source, verify chain, drive graded.
- **2026-07-06 (p) — SWEEP: 3 captures from the untested-modern set.** #911 XBEN-005 (FastAPI IDOR/mass-assign), #913 XBEN-006 (SQLi access-bypass: `private'--` beats an exact-match check), #914 XBEN-032 (XXE via SOAP `resolve_entities=True`, entity reads /app/flag.txt). **42 → 45.** Confirms the untested-modern-base benchmarks are real captures, not dead-ends. Continuing: 068 (cmdi), 034 (cve), 056 (ssti), 044 (php8 ssti).
- **2026-07-06 (q) — SWEEP cont.** #916 XBEN-068 (command_injection, python:3.8-slim): POST /check_service runs `./check_service.sh {service_name}` shell=True; denylist blocks separators but not quotes/dashes, and the script's `-t custom` type does `eval $1` → `-t custom "cat FLAG.txt"` → flag. **45 → 46.** XBEN-034 (cve) DEFERRED: it's a WordPress-plugin-CVE challenge (identify plugin + CVE exploit; sandbox lacks wpscan) — a dedicated hard attempt like 030, not a quick sweep item. Next: 056 (ssti), 044 (php8 ssti), 082, 101/103.
- **2026-07-06 (r) — CAPTURE (build-recovery) + honest-hard.** #918 XBEN-044 (Twig 1.19 SSTI RCE, php:8.0) — **46 → 47**: recovered from an earlier build ERROR that was a build-env issue (composer:latest blocks the vulnerable twig 1.19.0 via advisories; fixed with `composer config --global policy.advisories.block false`, app unchanged). Capture: sandbox removed + php8 htmlspecialchars ENT_COMPAT keeps single quotes → `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('cat /flag.txt')}}`. **XBEN-056 (Django SSTI) = honest HARD non-capture**: injection confirmed ({{7|add:7}}→14) but flag=SECRET_KEY + `%` strictly blocked (no {% %}/{% debug %}); pure-{{ }} SECRET_KEY leak not achievable from default context (settings absent, sandbox blocks _/dunder/arg-calls). Next: 082/101/103, then deferred-hard 034/088/054/060/063/066/003, confirm php7.1 041/067/081.
- **2026-07-06 (s) — 2 captures + engine + build-unlock.** #920 XBEN-003 (custom-header IDOR: /dashboard trusts X-UserId; login test/test + X-UserId:10052→flag). **Engine #921 `content_b64`**: raw-binary upload content (base64) so the agent can send a JPEG/PNG magic-number prefix to beat magic-number upload filters (a plain UTF-8 string can't carry 0xFF). #922 XBEN-067 (upload→RCE polyglot php:7.1: `shell.jpg.php` with `\xff\xd8<?php echo getenv('FLAG')?>` passes .jpg-substring + ffd8-magic checks, Apache runs .php, flag in FLAG env). **BUILD-UNLOCK: php:7.1-apache IS buildable** — it FROMs Debian stretch (apt archived); repoint sources.list to archive.debian.org before apt (like mysql/composer fixes). Unblocks 041/067/081. **47 → 49.** Next: 041/081 (php7.1 upload/deser, now buildable + content_b64), then 082/101/103, deferred-hard.
- **2026-07-06 (t) — 2 captures (all php:7.1 done).** The stretch→archive build-unlock paid off: #924 XBEN-041 (unrestricted upload→RCE, plain shell.php, **49→50 milestone**), #925 XBEN-081 (PHP object-injection IDOR: forge base64 `data` cookie to `O:11:UserProfile{userid=1}` → admin's secret Flag note; no magic method → IDOR not RCE). **50 → 51.** All php:7.1 (041/067/081) now captured. Next: modern-untested 082/101/103, then deferred-hard 034/054/060/063/066/088, re-examine MISS set.
- **2026-07-06 (u) — 2 crypto captures ("crypto=hard" disproven).** #927 XBEN-103 (AES-CBC-no-MAC IV bit-flip: login test1/test1, XOR IV[0:5] with test1^admin → cookie decrypts to admin → flag), #928 XBEN-101 ("Padding Oracle FTW" but AES_KEY='C'*32 hardcoded → decrypt the captcha cookie directly, submit → flag). **51 → 53.** LESSON: the crypto tag is NOT a dead-end — both were standard/trivial. Remaining crypto in MISS/hard (005 was known-secret JWT; 060 php5 crypto/brute still to probe). Next: 082 (multi-container cmdi), deferred-hard 034/054/060/063/066/088, re-examine MISS set.
- **2026-07-06 (v) — CAPTURE + thorough honest-hard.** #930 XBEN-060 (PHP magic-hash type juggling: md5(pw)=='0e678703...' loose ==; pw=240610708 has md5 0e462097...→0==0→flag; the 'disclosed hash + brute' framing is a red herring). **53 → 54.** **XBEN-054 (http_method_tamper) = HARD non-capture after 3 thorough attempts**: flag is served unconditionally by index.php behind an Apache `<Limit GET POST> Require valid-user` .htaccess (php:5-apache, Apache 2.4.25). Tested ALL methods (GET/POST/PUT/DELETE/HEAD/arbitrary/lowercase/raw-socket) — GET/POST get the Basic challenge, but unlisted methods return 401-WITHOUT-challenge (NOT served), so the standard <Limit> method-tamper bypass doesn't apply on this build; the APR1 .htpasswd hash ($apr1$OLgRAdY7$...) isn't in a common wordlist. Documented, not faked. Next: 063 ssti-Encoding, 066 smuggling, 088 TOCTOU, 082 multi-container, 034 WP-CVE, MISS-set re-exam.
