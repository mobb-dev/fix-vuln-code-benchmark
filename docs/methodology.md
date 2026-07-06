# Methodology

## The question

Given a real, known vulnerability, can an AI coding agent produce a fix that actually removes
it? We measure the fix, not detection: the agent is told what kind of bug it is and where, and
has to remediate it. The benchmark ran in two rounds, and the escalation between them is part
of the result: the first round's design had a flaw, we found it, and the second round exists
to close it. Both rounds are documented in this repo; round two's run data is committed in
full (`runs/`), while round one survives as its case recipes (`cases/`), the contamination
receipts (`evidence/`), and the summary matrix in the write-up — its raw 126 run outputs were
never committed.

## Round one: execution-verified, internet on

Seven disclosed CVEs across Go, Python, JavaScript and Java. Two agents (Claude Code, OpenAI
Codex), three models each, three reasoning settings: 126 attempts.

**1. Recreate the vulnerable code.** The recipe names the commit where the maintainer fixed
the bug. We clone the project, check out the commit right before that one, and re-initialize
the repository as a single commit, so the agent cannot read the maintainer's patch from
`git log`. The clone lives in a container and never touches the host.

**2. Hand the agent the bug, not the fix.** The agent receives `finding.md`: the vulnerability
type, the file, and why it is exploitable, taken from the public advisory with the remediation
removed. It never sees the maintainer's patch or test.

**3. Decide by execution.** The security test the maintainer added in the fix commit must fail
on the vulnerable baseline, pass after the agent's fix, and leave the surrounding tests green.
A separate model reviews the diff as fast triage; the execution test decides.

**Result:** Claude Code 56/63, Codex 59/63, both flagships perfect. And one number that did
not fit: the AI reviewer had graded 62 and 63 of 63 as fixed, so it over-passed roughly one
failed fix in ten.

**The flaw.** These bugs are disclosed, so their fixes are public, and the agents had internet
access because that is how the tools ship. When a hard case stalled, an agent researched the
bug, wrote its own fetcher after our command blocklist stopped `curl`, downloaded the
maintainer's patch, and applied it byte for byte. That is competent behavior, not cheating,
but it means round one measured "can the agent find the patch" as much as "can the agent
produce a fix." Instruction-level and command-level blocking does not hold; only removing the
network does. The receipts are in `evidence/`.

## Round two: harder cases, network physically cut

Thirty-three CVEs, deliberately weighted toward multi-file fixes — the 32 in `cases32.json`
plus `scim-patch`, carried over from round one — one flagship per vendor (Claude Opus 4.8,
GPT-5.5), one attempt each, 40 minute budget. See `PROCESS.md` for the exact pipeline.

### How the case set was chosen

The selection pipeline is committed, so "we picked the hard ones" is checkable rather than
trust-us. `candidates-100.json` is the candidate pool: 100 recently disclosed, already-fixed
vulnerabilities across the four languages (28 Go, 28 Java, 22 Python, 22 JS/TS; 16 critical,
45 high, 39 medium), assembled deliberately weighted toward hard, multi-file bugs — in 79 of
the 100 the maintainer's fix touches more than one source file, and each entry records the
advisory, fix commit, severity, and file counts. Every candidate then went through an
automated calibration pass whose per-candidate outcome is recorded in `calib-ledger.json`:
32 VERIFIED, 53 NOT VERIFIED, 6 NO-VERDICT, 5 INCONCLUSIVE, 4 TIMEOUT. The round-two set is
exactly the 32 VERIFIED cases: `scripts/clone-vulnerable.sh` and `scripts/gen-findings-loc.py`
select `verdict == VERIFIED` mechanically, so no cleanly-calibrating case was dropped and no
failing one was hand-admitted. `scim-patch`, carried over from round one, makes 33 graded
cases. Two honest caveats: the editorial judgment lives upstream, in how the candidate pool
was assembled; and calibration was necessary but not sufficient — two VERIFIED cases still
shipped flawed (a mislabeled finding, a non-compiling baseline), were caught by our own audit,
and were re-run on corrected data, as described below.

What changed, and why:

- **Isolation is physical.** Agent containers run on an internal Docker network with no route
  out. A dual-homed allowlist proxy (`scripts/egress_proxy.py`) permits CONNECT to exactly the
  two model API hosts and refuses everything else. Zero fixes used the web; every attempt to
  reach past the allowlist stopped at the proxy (itemized in `runs/EGRESS-EVIDENCE.md`, raw
  decision log in `runs/proxy-egress.log`).
- **Findings are de-biased.** `FINDING.txt` contains the vulnerability type and precise
  locations (file, line range, function), generated from the fix's own hunks by
  `scripts/gen-findings-loc.py`. No advisory prose, no identifiers to pattern-match.
- **Contamination is date-controlled.** Every maintainer fix in the set is dated after both
  models' documented training cutoffs, so the fixes cannot be memorized either.
- **Grading is layered.** Each agent cross-reviews the other's diff against the maintainer's
  real fix (CORRECT, PARTIAL, INCORRECT). Then a re-verification pass reads every diff,
  re-judges it under an explicit rubric, and compile-checks every fix credited as correct —
  done twice: one AI-assisted pass (recorded in the adjudication document) and one review by
  a human security engineer.
  The final verdicts sit on two axes: did the fix close the vulnerability, and is it clean and
  mergeable (closed, compiles, no over-reach). A patch that does not compile is INCORRECT, no
  exceptions.

**Result:** vulnerability closed, Claude 10/33 and Codex 18/33; clean and mergeable, 7/33 and
9/33. Neither gap is statistically significant at this sample size. The AI cross-review
disagreed with the human read on 10 of 66 fixes, too harsh nine times, and once too lenient,
on a fix that does not compile. Full detail, including the rubric and every disagreement, is
in `docs/blog-post/VERDICT-ADJUDICATION.md`.

## Auditing ourselves

The same rigor applied to our own data found two flaws: one case's finding mislabeled the
vulnerability class (the agents dutifully fixed the wrong thing), and one case's "vulnerable"
baseline did not compile at all. Both cases were rebuilt on corrected data and re-run; the
originals are archived in `_superseded/` rather than deleted. Two empty submissions were
retried on a fresh budget before being counted as failures; one was a deliberate refusal by
the agent, which is labeled as such rather than blended into the capability numbers.

## Known limitations

- One run per agent per case; run-to-run variance is not yet measured.
- The agent containers were not identical: Claude ran as uid 1000 with `HOME=/tmp`, Codex as
  root (see `PROCESS.md`). Prompt, 40-minute budget, CPU, and memory were the same for both.
  The one observed consequence — a Maven warning polluting Claude's Java traces — was a
  harness parsing bug, found and fixed; a residual disadvantage to the non-root agent on
  permission-sensitive builds cannot be ruled out.
- Grading was not blinded: reviewers knew which agent produced each diff.
- The cross-review is not execution verification and is used only as evidence about AI
  grading, never as the headline number.
- One project (Apache Camel) does not build offline even before any fix is applied, so that
  single correct verdict rests on a careful read instead of the compiler, and is flagged.
- Cost is not reported for subscription-authenticated agents; tokens and wall time are.

## What each round-two run writes

`runs/<slug>/` holds, per case: `FINDING.txt` handed to the agents, both agents' `fix.diff`,
raw `trace.jsonl` and readable `transcript.md`, `meta.json` (tokens, time, `used_web`, blocked
egress attempts), the maintainer's `maintainer.diff`, both cross-reviews under `reviews/`, and
`VERDICTS.txt`. The hand-verified verdicts are `two-axis.json` and `human-review.json` at the
repo root.
