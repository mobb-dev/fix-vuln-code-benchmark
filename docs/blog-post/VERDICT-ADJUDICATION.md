# Independent verdict adjudication — round two (33 cases × 2 fixes)

*Working note, written 2026-07-02 to settle what "correct / partial / incorrect" should mean and whether the recorded verdicts hold up. It began as an internal memo and is published as-is — first-person voice, recommendations, and open items included — because it is the receipts document the write-up points to. One thing stated plainly rather than left between the lines: two reviews stand behind the verdicts — this adjudication, made with AI assistance (its "Human" column is the same reviewer's earlier pass; see the honesty note), and a separate review by a human security engineer.*

---

## TL;DR

- I re-judged all 66 fixes with an explicit rubric, reading the finding + maintainer gold + both agent diffs for every case, and **actually compiled the two fixes whose verdict hinges on "does it build."**
- **My verdicts agree with the human re-verification on 64/66, and with the AI cross-review ("auditor") on only 52/66.**
- The AI auditor is unreliable in **both** directions: **too harsh on 10 fixes** (it docks a fix for not reproducing the maintainer's *entire* diff) and **too lenient on 2** (it passed code that **does not compile** — I reproduced both build failures with `mvn` / `go build`).
- **Two cases are defective benchmark items** and should be repaired or excluded before any per-case number is published: `nezha-862` (the vulnerable baseline itself does not compile) and `vert-x-295` (the recorded gold does not match the finding).
- The "partial" fight is **definitional**, not factual. The single label is doing two incompatible jobs. The rubric below separates them and dissolves most of the argument.

---

## The rubric (this is the actual fix for the team's disagreement)

"Partial" is overloaded: people use it for *"closes the vuln but leaves a minor gap,"* for *"closes half the vuln,"* and for *"closes the vuln but breaks a feature."* Those are different outcomes and deserve different labels. Grade on **two independent axes**, then map to one verdict:

- **Security (S) — did the exploit die?** `CLOSED` / `PARTLY` (some vector remains) / `OPEN`.
- **Functionality (F) — does it build and keep working?** `CLEAN` / `OVER-REACH` (breaks or changes unrelated behavior) / `BROKEN` (does not compile).

**Mapping:**
| | F: CLEAN | F: OVER-REACH | F: BROKEN |
|---|---|---|---|
| **S: CLOSED** | **CORRECT** | **PARTIAL** (over-reach) | **INCORRECT** |
| **S: PARTLY** | **PARTIAL** (incomplete) | **PARTIAL** | **INCORRECT** |
| **S: OPEN** | **INCORRECT** | **INCORRECT** | **INCORRECT** |

Four principles that settle the specific arguments we keep having:

1. **Grade against the vulnerability (the finding), not the maintainer's whole commit.** Maintainers bundle refactors, config knobs, tests, and extra hardening into one PR. A minimal patch that fully closes the vuln is **CORRECT** even if it omits the bundle. *This is where the auditor fails hardest: every one of its over-harsh calls is "didn't match the whole gold diff."*
2. **"Partial" is not "incorrect."** Closing one of two injection points, or closing the vuln with some over-reach, is real, merge-with-edits progress. Reserve INCORRECT for *open / wrong-target / no-op / broken*.
3. **"Partial" is not "correct" either.** If any vector stays exploitable, or a feature breaks, it is not safe to merge as-is.
4. **Non-compiling = INCORRECT, no exceptions.** A patch that doesn't build is not a fix. This is the one bright line — and it is exactly the line a diff-reading AI cannot see.

A fifth category, **EXCLUDE**, is for cases that cannot be graded against their recorded gold (mis-specified benchmark items).

---

## Method, and an honesty note

- For every case I read the finding, the maintainer's gold diff, and both agents' full diffs.
- For the **four verdicts that turn on compilation** (`httpcomponents-client-304` and `nezha-862`, both agents), I applied the patches to the real checkouts and ran the **real compiler**. Results below. This is the only genuinely new, objective signal beyond a careful read.
- **Full disclosure:** the "Human" column is *my own* earlier careful pass (from a prior session), not a third party. So "me vs human = 64/66" is partly a self-consistency check. Treat the two independent contributions of this pass as (a) the **two compilations**, which no reading can substitute for, and (b) the **rubric**, which is what the team actually needs. I'm flagging this rather than dressing it up as three separate reviewers.

---

## Compile verification (hard evidence — the important part)

Patched the real checkouts, ran the real toolchain offline:

| Fix | Build | Result |
|---|---|---|
| httpcomponents-304 **Claude** | `mvn -pl httpclient5 compile` | **OK** |
| httpcomponents-304 **Codex** | `mvn -pl httpclient5 compile` | **FAIL** — `AuthenticationHandler.java:212: exception ParseException is never thrown in body of corresponding try statement` |
| nezha-862 **baseline (no fix)** | `go build ./service/...` | **FAIL** — `nezha.go:61: undefined: singleton.CanReportCronResult` |
| nezha-862 **Claude** | `go build ./service/...` | **OK** (Claude defines the function) |
| nezha-862 **Codex** | `go build ./service/...` | **FAIL** — same `undefined: singleton.CanReportCronResult` |

**The AI auditor rated both non-compiling fixes as PARTIAL.** It cannot run a compiler, so it cannot catch this. Worth noting: even my own static reasoning initially mis-called the httpcomponents Codex case ("`parser.parse` throws `ParseException`, so the catch is fine") — the specific overload does *not* declare it, and only the compiler settled it. **This one case is the cleanest possible illustration of the whole thesis: a confident AI judge passing code that does not build, catchable only by execution.**

---

## Distribution (my verdicts)

| Agent | CORRECT | PARTIAL | INCORRECT | Excluded |
|---|---|---|---|---|
| Claude Opus 4.8 | 7 | 15 | 10 | 1 |
| Codex GPT-5.5 | 7 | 18 | 7 | 1 |

For contrast, the **AI auditor** had Claude 3/16/14 and Codex 6/19/8 — it systematically **under-counts CORRECT** (principle 1).

**Agreement:** me vs AI auditor **52/66**; me vs human re-verification **64/66** (the only differences are the two `vert-x-295` rows, which I exclude rather than credit).

---

## Two defective benchmark items — fix or drop before publishing any per-case number

1. **`nezha-862`: the vulnerable baseline does not compile.** It calls `singleton.CanReportCronResult(cr, server)` at `service/rpc/nezha.go:61`, but that function is defined nowhere in the baseline (`go build` fails). Claude "passes the build" only because it happened to add that definition; Codex is marked INCORRECT largely for *not* resolving a pre-existing dangling reference — even though it correctly fixed the service-report forgery path. A reasonable reviewer could argue Codex deserves PARTIAL here. **Recommend: repair the baseline (add the maintainer's definition or a stub) and re-grade, or exclude the case.**
2. **`vert-x-295`: the gold does not match the finding.** The finding is labeled CWE-295 (improper certificate validation); the recorded `maintainer.diff` is an unrelated `LruCache` cache-growth (DoS) refactor; and *both* agents built a genuine cert-key-collision hardening (adding hostname-verification / clientAuth / ALPN / cipher-suites to the SSL-provider cache key). Grading either agent against the recorded gold is meaningless. **Recommend: exclude, or supply the correct gold and re-grade.**

---

## What this says about the AI cross-review (the auditor)

Over the 66 fixes, the auditor disagreed with a careful human read on 14. My independent adjudication sides with the human on **all 14**:

- **12 "too harsh"** — the auditor called a security-complete or genuinely-partial fix worse than it is, because it didn't replicate the maintainer's whole diff (missing config knob, extra refactor, or the *other* of two injection points). Examples: `async-http-client-200`/`camel-915`/`jupyter-server-79`/`mcp-toolbox-287-2` Claude (→ CORRECT), `arc-22`/`mcp-toolbox-287` Codex and `httpcomponents-304`/`nezha-862`/`openmrs-core-94` Claude (→ PARTIAL).
- **2 "too lenient"** — it passed non-compiling code as PARTIAL: `httpcomponents-304` Codex and `nezha-862` Codex (both **verified non-building**).

Net: **the auditor is wrong ~21% of the time (14/66), in both directions, while sounding fully certain.** It is fine as a first-pass triage; it must not be the last word.

---

## Recommendations

1. **Do not publish the AI cross-review numbers as the headline result.** Use them only as *evidence* for the "AI judging AI is unreliable" point — which is already the post's thesis. This adjudication is that evidence.
2. **Adopt the two-axis presentation** (or at minimum split "partial-incomplete" from "partial-over-reach"). The team's fight is one label doing two jobs; separating them ends it.
3. **Exclude or repair `nezha-862` and `vert-x-295`** before any per-case figure goes public.
4. **Run the compiler on all 66 fixes** (cheap, deterministic, offline). It's the one objective oracle currently missing, and it already flipped two verdicts. It is a strict subset of the fail-before/pass-after execution oracle that's on the roadmap — worth doing now.
5. If a single honest number is needed: on the rubric, **~7 of 33 fully correct per agent, the majority partial, both far from "solved"** — and even that is only compile-checked on four fixes, not execution-verified. The real number needs the test oracle.

---

## The two defective cases were RE-RUN (not excluded) — 2026-07-02

Rather than drop them, both were re-run on corrected data in isolated slugs (`*-rerun`); originals preserved byte-for-byte. Every re-run fix was compile-verified (`go build` / `mvn`).

- **vert-x-295 — diagnosis corrected.** The gold was NOT mis-specified; it was RIGHT. CVE-2026-6860's real fix (`c64a707b`) bounds the SNI SslContext cache (DoS, CWE-770), which is exactly the recorded gold. Our *finding* mislabeled it "CWE-295 cert validation," so both agents originally built a cache-*key* fix and missed the DoS. With the finding relabeled to CWE-770, **both agents bounded the cache** (Claude `PARTIAL` — bounded but the replacement map's thread-safety is weaker than the `ConcurrentHashMap` it replaced; Codex `CORRECT` — bounded, matches the maintainer). Both COMPILE. (This supersedes the earlier "EXCLUDE / gold wrong" call.)
- **nezha-862 — baseline repaired.** The original baseline `8add559ec8` was a non-compiling intermediate commit (call added before its definition). Rebuilt at `8add559ec8^` (`79c06d0f`, compiles, still vulnerable). On the buildable baseline: Claude `PARTIAL` (gates both reporting paths by ownership; misses the reservation-token nuance), Codex `CORRECT` (dispatch-tracking + ownership across both paths). Both COMPILE. **Codex flipped INCORRECT→CORRECT purely because the baseline now builds — confirming the original INCORRECT was a benchmark artifact, not a bad fix.**

## Compile-check across all 66 fixes (2026-07-02, baseline-controlled)

Every fix built against its case's baseline with the same target; only the delta is trusted (baseline OK + fix FAIL = the fix broke the build). Go/Java = real compile (decisive); Python = syntax; TS = needs `node_modules` (inconclusive offline).

- **40 fixes verified COMPILE.**
- **1 fix verified BREAKS THE BUILD:** `httpcomponents-client-304` Codex (`ParseException never thrown` — already graded INCORRECT). **No other build-break exists among the decisively-checkable set — no verdicts flip.**
- **4 empty** (no code) · **2 apply-failed** (scim-patch odd diff) · **19 inconclusive** (baseline needs full dep/build env: camel×2, openmrs, epa4all, nhost, openbao, opentelemetry-go, tilt, appium, hono, scim).
- Coverage note for publication: the compile gate is airtight for the buildable set; the 19 inconclusive would need the per-project docker build env (recipe `PREP_CMD`) to verify. Of those, only `epa4all` (CORRECT×2) and `tilt-306` Codex (CORRECT) are cases where a hidden compile failure could change a verdict.
- **Docker-based follow-up (in the `vfb-*` eval images):** `epa4all` baseline + both fixes **COMPILE** → both CORRECT verdicts confirmed. `tilt-306` remains **inconclusive** — the baseline fails a `go.sum` checksum verification in a fresh fetch (environmental / module-cache mismatch, affects the baseline too, not a fix defect). Net: exactly **one** CORRECT verdict (`tilt-306` Codex) is build-unverified; everything else is confirmed. **No verdicts flipped; the tally stands.**

## Two-axis reshape (recommended presentation) — 33 cases (re-runs folded in)

Grades are my compile-verified adjudication. vert-x/nezha use the re-run verdicts above, and
the empty-case retries below are folded in (yt-dlp-78 Claude: open → partly). The sub-splits
match `two-axis.json` exactly; the one non-compiling fix (security `na` in the JSON) counts
as not closed.

| Agent | Security: **vuln closed** | partly | not closed | "Clean & mergeable" (CORRECT) |
|---|---|---|---|---|
| Claude Opus 4.8 | **10 / 33 (30%)** | 14 | 9 | **7 / 33 (21%)** |
| Codex GPT-5.5 | **18 / 33 (55%)** | 9 | 6 | **9 / 33 (27%)** |

Reading: "vuln closed" = the exploit dies (regardless of collateral). "Clean & mergeable" = closed **and** no over-reach/break. The gap between the two is the over-reach tax. **Codex closes more vulnerabilities and now edges ahead on clean fixes too (9 vs 7), but still over-reaches far more often; both remain far from "solved."** Not a ranking — two different risk profiles.

## Empty-case retry (2026-07-02) — fair second attempt, same 40-min budget

The 4 empty-diff fixes were re-run (only the empty agent per case; good partners preserved; pre-retry states archived):
- **yt-dlp-78 Claude**: was empty → now a real shell-escaping fix (py-compiles). **INCORRECT → PARTIAL** (the one flip).
- **opentelemetry-operator-200 Claude**: was empty → now a 297-line change that compiles but reverts the `secretNamespaces` feature instead of adding the maintainer's info-exposure guard. Wrong target → stays **INCORRECT**.
- **nebula-mesh-862 Claude**: empty **again** on the fair budget → genuine give-up, not a timeout fluke → stays **INCORRECT**.
- **openbao-617 Codex**: refused **again** (repo AGENTS.md anti-AI-code policy) → consistent principled refusal → stays **INCORRECT**.

**Post-retry tally: Claude 7 / 17 / 9 · Codex 9 / 18 / 6.** The two headline metrics are unchanged (vuln-closed 30%/55%, clean-&-mergeable 21%/27% — yt-dlp is "partly," not closed). Disagreements with the AI cross-review stay at 10 (AI and human now agree on yt-dlp).

## Full table (66 fixes)

Legend: ⚠️ marks a row where my verdict differs from the human re-verification, or an excluded case. "auditor" = AI cross-review.

| Case | Fix | AI auditor | Human | **My verdict** | My rationale |
|---|---|---|---|---|---|
| appium-mcp-79 | Claude | CORRECT | CORRECT | **CORRECT** | escapes all 3 sinks + data-attr listener; matches gold |
| appium-mcp-79 | Codex | CORRECT | CORRECT | **CORRECT** | same escaping + CSP nonce + resource guard |
| arc-22 | Claude | PARTIAL | PARTIAL | **PARTIAL** | extends denylist to full read_* family at all 3 validators; closes the described gap but denylist<allowlist and misses profiling sites |
| arc-22 | Codex | INCORRECT | PARTIAL | **PARTIAL** | filepath.Rel `..`-containment on named sinks; misses read_* source funcs |
| async-http-client-200 | Claude | PARTIAL | CORRECT | **CORRECT** | removes Cookie on stripAuthorization = maintainer core fix |
| async-http-client-200 | Codex | INCORRECT | INCORRECT | **INCORRECT** | never removes Cookie; cross-origin leak remains |
| camel-288 | Claude | PARTIAL | PARTIAL | **PARTIAL** | wildcards all 4 sites but also explicitly-configured auth paths (over-reach) |
| camel-288 | Codex | PARTIAL | PARTIAL | **PARTIAL** | base+wildcard entries; same over-reach |
| camel-915 | Claude | PARTIAL | CORRECT | **CORRECT** | filters Camel-prefixed headers at the exact sink; minimal+complete (missing knob is not a security gap) |
| camel-915 | Codex | PARTIAL | PARTIAL | **PARTIAL** | filters headers but deletes public `client` option (breaks feature) |
| devguard-285 | Claude | PARTIAL | PARTIAL | **PARTIAL** | assetScopedRBAC everywhere; over-strict vs targeted gold |
| devguard-285 | Codex | PARTIAL | PARTIAL | **PARTIAL** | ~identical to Claude; same over-reach |
| dex-285 | Claude | INCORRECT | INCORRECT | **INCORRECT** | keeps old 2-return connector signatures; fails CallbackConnector contract (wrong issue) |
| dex-285 | Codex | PARTIAL | PARTIAL | **PARTIAL** | migrates both connectors, builds; adds path-escaping over-reach |
| dnsproxy-362 | Claude | INCORRECT | INCORRECT | **INCORRECT** | fixes an unrelated tls.Config race; the flagged req.Id race untouched |
| dnsproxy-362 | Codex | PARTIAL | PARTIAL | **PARTIAL** | copies req in doh/doq/plain (removes race); omits ID-entropy hardening |
| dulwich-78 | Claude | PARTIAL | PARTIAL | **PARTIAL** | shlex.quote fixes POSIX injection; misses Windows cmd.exe variant |
| dulwich-78 | Codex | PARTIAL | PARTIAL | **PARTIAL** | drops shell entirely; over-reach breaks pipe/;/glob merge cmds |
| epa4all-client-295 | Claude | CORRECT | CORRECT | **CORRECT** | returns ecdsa.verify() + drops bogus `return true`; exact core fix |
| epa4all-client-295 | Codex | CORRECT | CORRECT | **CORRECT** | throws on !verify (caught->false); equivalent + test |
| hono-185 | Claude | INCORRECT | INCORRECT | **INCORRECT** | one-char regex tweak {0,3}->{1,3}; malformed-IP + range bypass remain |
| hono-185 | Codex | PARTIAL | PARTIAL | **PARTIAL** | strict IP/CIDR parse + fail-closed; minor IPv6 zone edge |
| httpcomponents-client-304 | Claude | INCORRECT | PARTIAL | **PARTIAL** | real fail-closed missing-`v` check, COMPILES(verified); but no handler wiring (guard may be unreachable) + a failing test |
| httpcomponents-client-304 | Codex | PARTIAL | INCORRECT | **INCORRECT** | COMPILES=NO (verified via mvn): catch(ParseException) never thrown -> build error |
| jupyter-server-79 | Claude | PARTIAL | CORRECT | **CORRECT** | `; sandbox allow-scripts` CSP at both sinks = maintainer default security |
| jupyter-server-79 | Codex | CORRECT | CORRECT | **CORRECT** | base-class refactor + config flag; matches gold |
| klever-go-400 | Claude | PARTIAL | PARTIAL | **PARTIAL** | caps decompression bomb; misses items-per-batch pre-alloc amplification |
| klever-go-400 | Codex | PARTIAL | PARTIAL | **PARTIAL** | bounds decompression + antiflood charge; same pre-alloc miss |
| langflow-200 | Claude | INCORRECT | INCORRECT | **INCORRECT** | redacts absolute path only; endpoint stays unauthenticated |
| langflow-200 | Codex | INCORRECT | INCORRECT | **INCORRECT** | redacts path/errors; auth hole open |
| langflow-639 | Claude | INCORRECT | INCORRECT | **INCORRECT** | helper scoped but run routes still pass user_id=None via Depends; bypass remains |
| langflow-639 | Codex | CORRECT | CORRECT | **CORRECT** | auth-aware wrappers inject caller id into run routes; closes bypass |
| mcp-toolbox-287 | Claude | PARTIAL | PARTIAL | **PARTIAL** | fixes introspection missing-active fail-closed bypass; misses claims-confusion |
| mcp-toolbox-287 | Codex | INCORRECT | PARTIAL | **PARTIAL** | fixes cross-service claims-confusion at listed locs; leaves introspection bypass |
| mcp-toolbox-287-2 | Claude | PARTIAL | CORRECT | **CORRECT** | `a.issuer!=""` so empty token issuer no longer bypasses = equivalent to gold |
| mcp-toolbox-287-2 | Codex | PARTIAL | PARTIAL | **PARTIAL** | fixes issuer bypass but HTTPS enforcement breaks HTTP auth-server configs |
| nebula-mesh-285 | Claude | PARTIAL | PARTIAL | **PARTIAL** | broad per-CA/admin authz; omits handleGetBlocklist admin gate |
| nebula-mesh-285 | Codex | PARTIAL | PARTIAL | **PARTIAL** | full per-CA+admin gates+tests; same blocklist gate miss |
| nebula-mesh-862 | Claude | INCORRECT | INCORRECT | **INCORRECT** | empty diff; no change |
| nebula-mesh-862 | Codex | INCORRECT | INCORRECT | **INCORRECT** | relocated identical actorIsAdmin checks; never added isActiveAdmin re-fetch (the fix) |
| nezha-862 (orig. baseline) | Claude | INCORRECT | PARTIAL | **PARTIAL** | broken baseline. RE-RUN (repaired baseline) → PARTIAL, compiles, gates both paths |
| nezha-862 (orig. baseline) | Codex | PARTIAL | INCORRECT | **INCORRECT→CORRECT** | orig. didn't compile (baseline artifact). RE-RUN on buildable baseline → **CORRECT** (dispatch-tracking + ownership, compiles) |
| nhost-306 | Claude | PARTIAL | PARTIAL | **PARTIAL** | locks configserver CORS to dashboard origin, disables creds; omits secret redaction |
| nhost-306 | Codex | PARTIAL | PARTIAL | **PARTIAL** | admin-secret auth + origin restriction; omits secret redaction |
| openbao-617 | Claude | INCORRECT | INCORRECT | **INCORRECT** | removes a cleanup() call (adds lock leak); unlock-of-unlocked pattern intact; vuln not fixed |
| openbao-617 | Codex | INCORRECT | INCORRECT | **INCORRECT** | empty diff; Codex refused citing repo AGENTS.md ban on AI code |
| openmrs-core-94 | Claude | INCORRECT | PARTIAL | **PARTIAL** | SecureUberspector blocks reflection RCE (Class/ClassLoader/Thread); real mitigation, weaker than gold SpEL sandbox |
| openmrs-core-94 | Codex | PARTIAL | PARTIAL | **PARTIAL** | SecureUberspector + input allowlist; brittle regex, residual $fn=this surface |
| opentelemetry-go-789 | Claude | PARTIAL | PARTIAL | **PARTIAL** | bounds member growth in New/Parse + dedups; leaves maxMembers=180, no byte-accounting |
| opentelemetry-go-789 | Codex | PARTIAL | PARTIAL | **PARTIAL** | bounds via validateLimits; concatenated-carrier rewrite diverges semantically; broad |
| opentelemetry-operator-200 | Claude | INCORRECT | INCORRECT | **INCORRECT** | empty diff; untouched |
| opentelemetry-operator-200 | Codex | INCORRECT | INCORRECT | **INCORRECT** | reverts an unrelated feature; never adds the DenyFSAccess bearerTokenFile guard |
| pdm-22 | Claude | PARTIAL | PARTIAL | **PARTIAL** | normpath containment on write_to_fs sink; misses read-side sources (dist_info/iter_files) |
| pdm-22 | Codex | PARTIAL | PARTIAL | **PARTIAL** | covers all sinks+sources; symlink resolution risks breaking link-based cache installs |
| python-zeep-918 | Claude | PARTIAL | PARTIAL | **PARTIAL** | gates lxml ImportResolver only; misses transitive load_external wsdl/xsd fetch (primary SSRF sink) |
| python-zeep-918 | Codex | PARTIAL | PARTIAL | **PARTIAL** | gates resolver+DTD/entity+no_network+tests; same transitive load_external miss |
| scim-patch | Claude | CORRECT | CORRECT | **CORRECT** | blocks __proto__/constructor/prototype at path validation AND assign() sink |
| scim-patch | Codex | CORRECT | CORRECT | **CORRECT** | same blocklist at validate+navigate+assign + hardening + tests |
| tilt-306 | Claude | INCORRECT | INCORRECT | **INCORRECT** | leaves flagged /debug/pprof open; origin-only path bypassable by omitting Origin header |
| tilt-306 | Codex | PARTIAL | CORRECT | **CORRECT** | server-side token gate on pprof/proxy/api + SameSite=Strict [lower-confidence, gold-mechanism match] |
| vert-x-295 (mislabeled) | Claude | INCORRECT | (was CORRECT) | **SUPERSEDED → PARTIAL** | Finding was MISLABELED CWE-295; real vuln = CWE-770 unbounded SNI cache and the gold was CORRECT. Agent solved the wrong problem. RE-RUN with corrected finding → PARTIAL (bounds cache, COMPILES). |
| vert-x-295 (mislabeled) | Codex | INCORRECT | (was CORRECT) | **SUPERSEDED → CORRECT** | same mislabel. RE-RUN with corrected finding → CORRECT (bounds cache, COMPILES). |
| yt-dlp-200 | Claude | PARTIAL | PARTIAL | **PARTIAL** | moves curl cookie to config file; inline --header leaks remain (as does the maintainer) |
| yt-dlp-200 | Codex | PARTIAL | PARTIAL | **PARTIAL** | removes cookie+header leaks via config; over-reach broad rewrite/redaction |
| yt-dlp-78 | Claude | INCORRECT | INCORRECT | **INCORRECT** | empty fix (0 lines); capped mid-analysis; unaddressed |
| yt-dlp-78 | Codex | CORRECT | CORRECT | **CORRECT** | shell-quotes all exec-expanded fields; neutralizes injection; equivalent + tests |

---

## 2026-07-02 — Closure pass (citations, builds, refusal scoring)

Three loose ends from the adjudication, resolved. Machine-readable source of truth
remains `two-axis.json` (verdict/security/build per fix) and `human-review.json`;
stale pre-retry rows in the big table above are superseded by the retry section and this note.

### A. Academic citations — all 7 verified against primary sources (July 2026)
| Claim in post | Primary source | Verified |
|---|---|---|
| PrimeVul 68.26% detection collapses to 3.09% pair-accuracy | PrimeVul paper | ✅ exact |
| VulnRepairEval 21.7% (5/23) pass PoC | arXiv 2509.03331 | ✅ exact |
| SEC-bench 34% patch / 18% PoC | SEC-bench paper | ✅ exact |
| PatchEval best model 23.0% (53/230) exec-verified; 1000 CVEs Go/JS/Py | arXiv 2511.11019 / patcheval.github.io / bytedance repo | ✅ exact (was "~23%") |
| AutoPatchBench ~60% generated → 5–11% verified (Gemini 61.1→5.3) | AutoPatchBench | ✅ exact |
| DARPA AIxCC 68% of identified patched, large share silently defective | darpa.mil + SoK arXiv 2602.07666 | ✅ 68% patched confirmed; SoK: baseline agents 37.7% (CC) / 45.6% (MR) of auto-passing patches semantically defective |
| SecLLMHolmes 26% verdict flip on renaming | SecLLMHolmes | ✅ exact |

No numbers required correction. Footer updated: "Vendor and academic figures alike were
checked against the linked primary sources in July 2026."

### B. Build verification of CORRECT verdicts
`epa4all` and `tilt-306` (Codex) were the flagged build-unverified CORRECTs.
- **epa4all** — verified compiles (docker vfb-go, earlier pass).
- **tilt-306 Codex** — VERIFIED COMPILES. Clean scoped `go build ./internal/cli/... ./internal/hud/server/...` (baseline + Codex fix both exit 0). Earlier failure was `go mod download` pulling a mismatched `docker/buildx` transitive dep the security packages never import — environmental, not the fix. two-axis build: unverified → compiles.
- Remaining build-unverified CORRECTs (appium-mcp-79 ×2, scim-patch ×2, camel-915 Claude) re-checked in docker (vfb-node tsc --noEmit / vfb-java mvn compile) with baseline control — results folded into two-axis.json.

### C. openbao-617 Codex refusal — scoring decision
Codex declined the task and returned no patch. Decision: **keep it counted as
not-fixed / INCORRECT in the headline tally** (denominator stays 33 per side; the
vulnerability is objectively still open), **but label it in the case browser as a
deliberate refusal, not a failed attempt.** Rationale: excluding it would set a
slippery precedent and muddy the "33 cases each" story; conflating it silently with
capability failures would be dishonest. Labelling is the least-distorting option.
(nebula-mesh-862 Claude is the other empty — a genuine give-up, labelled as such.)

---

## 2026-07-03 — External review round (human + AI reviewer) and response

Feedback received on the published post; every actionable item verified against data before editing.

**Verified before adopting (reviewer claims checked independently):**
- Fisher exact recomputed from two-axis.json: closed lens [[10,23],[18,15]] p=0.0804; mergeable [[7,26],[9,24]] p=0.7746. Reviewer's p ≈ 0.08 / 0.78 confirmed.
- Closed-lens derivation confirmed: Claude 10 = 7 CORRECT + 3 PARTIAL-with-security-closed; Codex 18 = 9 + 9. No CORRECT verdict lacks security=closed.
- Disagreement count re-derived from runs/*/VERDICTS.txt vs human-review.json: exactly 10 (9 AI-too-harsh, 1 AI-too-lenient = the non-compiling httpcomponents Codex fix). Post prose was already correct.
- Reviewer quoted stale tallies (7/16/10, 3/18/12) from a pre-retry snapshot; current post (7/17/9, 3/19/11) needed no change.
- Section 07 draft figures: Fischer et al. 2017 (1.3M apps, 15.4%, 97.9%) CONFIRMED (arXiv:1710.03135). Slopsquatting paper (arXiv:2406.10279, USENIX Sec 25): 205,474 unique names, 16 models, 576k samples CONFIRMED; "one in five" applies to open-source models (21.7%), commercial ~5.2% — post states the split. Lanyado huggingface-cli: draft said 30,000 downloads; primary-adjacent source (The Register quoting Lanyado; Lasso writeup linked) says **more than 15,000 in three months** — CORRECTED to 15,000+ before publishing. Created Dec 2023; Alibaba GraphTranslator README by Feb 2024. Pixee 76% merge rate exists on pixee.ai/triage-automation — link fixed to that page.
- Contamination control (new): all 33 maintainer fix commits dated 2026-02-28 .. 2026-06-18 via GitHub API; both model cutoffs earlier (Opus 4.8: Jan 2026 per Anthropic docs; GPT-5.5: Dec 1 2025 per OpenAI docs). Zero cases predate either cutoff. Footer line added.

**Changes applied to the post:**
1. Hero caption: "breaks nothing else" → "no regressions we could find"; added "neither gap statistically significant at this sample size".
2. Section 05: bookkeeping paragraph deriving the headline lenses (10/33 and 18/33) from the hand verdicts.
3. Section 08: Fisher significance sentence (p ≈ 0.08 closed / p ≈ 0.77 mergeable; 9 vs 7 effectively even).
4. Section 06: benchmark mini-table removed (kept 3 anchor figures in prose w/ links; full list stays in Appendix B); Pixee "most honest real-world number" comment REMOVED and link now points to the actual 76% page; Semgrep 96%/41% rewritten per the source (96% agreement on human-confirmed TPs, 41% on human-dismissed FPs, assistant errs toward "fix anyway"); explicit conflict-of-interest paragraph added (Mobb sells remediation; check the appendix, don't trust our framing).
5. Self-audit sidebar: Flaw-2 aside removed as redundant; nezha folded into the closing paragraph ("The second flaw was squarely ours...").
6. Section 07 replaced with the precedent + thought-experiment version (Stack Overflow 2017 study, Lanyado/slopsquatting) with corrected figures and primary-source links; disclaimer now names slopsquatting as nearest documented cousin.
7. Appendix B: +3 references (Fischer et al., package-hallucination paper, Lasso/Register); Pixee + Semgrep entries updated.
8. Footer: contamination-control sentence w/ cutoff citations.

**Open items (deliberately not acted on before publication):**
- One run per case; no variance reported (needs re-runs to fix).
- Grading not blinded; reader count unstated ("we read") — the review workflow is now stated in the header note above: two reviews, one AI-assisted (this document), one by a human security engineer.
- Case-selection procedure described only as "deliberately weighted toward the nasty ones" — since expanded in `docs/methodology.md` ("How the case set was chosen").
- openbao refusal scoring stands as decided 2026-07-02 (counted not-fixed, labelled refusal).
