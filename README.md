# vuln-fix-bench

Can an AI coding agent fix a real, already-disclosed security vulnerability? This benchmark
measures that question the hard way: real CVEs, real projects, the agents cut off from the
internet, and every verdict of the offline round backed by artifacts you can read in this
repo.

It was built by the research team at [Mobb](https://mobb.ai). Full disclosure, stated the same
way we state it in the write-up: Mobb sells automated vulnerability remediation, and a study
that concludes "automated fixes need real verification and a human in the loop" is not a
conclusion we lose money on. That is exactly why every round-two diff, review, verdict, and
piece of sandbox evidence is committed here verbatim. Check our read; do not take it on
trust.

**Status: ongoing research.** The 33-case round is complete and written up. The next phases,
in order: scale the case set toward hundreds so the numbers stop being anecdotes; bring the
execution oracle (the project's own test must fail before the fix and pass after) to the hard
set; and a supervised round with the internet deliberately on, recording and auditing every
source the agents consult. Issues and case contributions are welcome.

## What we found

Two rounds, escalating rigor.

**Round one: 7 disclosed CVEs, 6 models, 3 reasoning settings, 126 attempts.** Graded by each
project's own security test (it must fail on the vulnerable code and pass after the fix).
Claude Code landed 56 of 63, Codex 59 of 63, and both flagships (Claude Opus 4.8, GPT-5.5)
were a perfect 21 for 21. It looked solved. Then we noticed the agents had internet access and
the fixes are public, and we caught an agent writing its own fetcher to download the
maintainer's patch when our command blocklist stopped `curl`. Round one's raw run outputs are
not committed here; what survives in this repo are its case recipes (`cases/`), the
contamination receipts (`evidence/`), and the per-model matrix in the write-up. Round two is
committed in full.

**Round two: 33 harder, multi-file CVEs, flagships only, network physically cut.** The agents
run on an isolated Docker network whose only route out is an allowlist proxy for the two model
APIs. Findings are stripped of advisory text so nothing can be pattern-matched. Each agent's
fix is compared against the maintainer's real fix, cross-reviewed by the other agent, then
re-verified by hand with the compiler. The verdicts, on two axes:

| | Vulnerability closed | Clean and mergeable (closed + builds + no over-reach) |
|---|---|---|
| Claude Opus 4.8 | 10 / 33 | 7 / 33 |
| Codex GPT-5.5 | 18 / 33 | 9 / 33 |

At 33 cases neither gap between the vendors is statistically significant. The finding is not a
winner; it is that producing a plausible patch is close to solved and producing a correct one,
offline, on hard bugs, is not. Along the way the AI judge we used for grading disagreed with a
careful human read on 10 of 66 fixes, in both directions at once, including passing a fix that
does not compile.

The complete adjudication, rubric, and every correction we made to our own benchmark is in
[docs/blog-post/VERDICT-ADJUDICATION.md](docs/blog-post/VERDICT-ADJUDICATION.md).

## How round two works

For one case (see [PROCESS.md](PROCESS.md) for the full step-by-step):

1. **Vulnerable baseline.** The project is cloned at the commit right before the maintainer's
   fix and its git history is flattened to a single commit, so the fix cannot be read from
   `git log`. `FINDING.txt` states the vulnerability type and the exact locations, nothing else.
2. **Two agents fix it independently**, each in a sandboxed per-language container
   (`vfb-go`, `vfb-python`, `vfb-node`, `vfb-java`) on the isolated network. 40 minute budget.
3. **The maintainer's real fix** is extracted from the fix commit as the gold standard.
4. **Cross-review.** Each agent grades the other's diff against the gold standard:
   CORRECT, PARTIAL, or INCORRECT, with reasoning.
5. **Human re-verification.** We read every diff ourselves, compile-check every fix we credit
   as correct, and publish the two-axis verdicts (`two-axis.json`, `human-review.json`).

## Run it yourself

You need Docker and agent credentials (a Claude subscription token, and optionally a ChatGPT
login for Codex).

```bash
# 1. Credentials: put a Claude token in .env (never committed), and log Codex in once
claude setup-token          # then: cp .env.example .env and paste the token
codex login                 # only if running the Codex side

# 2. Build the per-language agent images
bash scripts/build-images.sh

# 3. Materialize the vulnerable checkouts (about 2.7 GB, not stored in git)
bash scripts/clone-vulnerable.sh

# 4. Run one case end to end (both agents fix, gold diff, cross-review)
python3 scripts/run_fix.py tilt-306

# 5. Or run the whole set, a few cases at a time
CASES="tilt-306 pdm-22" PARALLEL_CASES=2 python3 scripts/run_all.py
python3 scripts/run_all.py            # everything in cases32.json

# 6. Inspect
python3 scripts/status.py             # ground-truth status board from runs/
python3 scripts/build_report.py       # self-contained HTML report of all runs
```

`scripts/rereview.py <case...>` re-runs only the cross-review stage over existing fixes.

The claude-code lane is backend-swappable: the same Claude Code CLI can drive MiniMax's
M-series instead of Claude, through MiniMax's Anthropic-compatible endpoint. Put a
`MINIMAX_API_KEY` in `.env` and run:

```bash
CLAUDE_BACKEND=minimax python3 scripts/run_fix.py tilt-306   # model: MiniMax-M3 by default
```

The egress allowlist follows the backend (`api.minimax.io` replaces `api.anthropic.com`),
and results land in `runs/<case>/claude-code__MiniMax-M3/`, so backends never overwrite
each other. `CLAUDE_MODEL` still overrides the model either way. In minimax mode the
pipeline runs only the MiniMax fix (the published Codex fixes are reused as the review
counterpart, not re-run), and review/verdict files are model-qualified
(`VERDICTS__MiniMax-M3.txt`, `claude-code__MiniMax-M3-fix__by-codex.md`), so published
artifacts are never touched. `FIX_LANES=claude,codex` overrides the lane selection.

## What is in this repo

| Path | What it is |
|---|---|
| `cases/<slug>/recipe` | Per-case source of truth: repo URL, fix commit, language, CWE |
| `cases32.json` | The 32 cases selected for round two; the 33rd graded case, `scim-patch`, carries over from round one (all 33 have 2026 fix dates) |
| `runs/<slug>/` | The actual benchmark data: both agents' diffs, traces, transcripts, the maintainer's gold diff, both cross-reviews, verdicts |
| `two-axis.json`, `human-review.json` | The hand-verified per-fix verdicts behind the headline numbers |
| `evidence/` | Receipts from the contamination discovery (the agent that fetched the fix) |
| `_superseded/` | Archived runs from the two cases we re-ran after finding flaws in our own data (a mislabeled finding, a broken baseline), kept for transparency |
| `prompt-template.txt`, `review-prompt-template.txt` | The exact prompts the agents and reviewers receive |
| `scripts/` | The pipeline: `run_fix.py` (one case), `run_all.py` (sweep), `egress_proxy.py` (the allowlist proxy), `status.py`, `build_report.py`, `rereview.py`, image and checkout builders |
| `docker/` | The four per-language agent images |
| `docs/methodology.md` | The methodology across both rounds, including what round one got wrong |
| `PROCESS.md` | The round-two pipeline, step by step |
| `docs/blog-post/` | Sources of the public write-up, plus the full verdict adjudication |
| `candidates-100.json`, `calib-ledger.json` | Case selection: the 100-candidate pool and the calibration verdicts whose 32 VERIFIED entries are the round-two set (see `docs/methodology.md`) |

The vulnerable checkouts (`checkouts/`) are not stored in git; `scripts/clone-vulnerable.sh`
rebuilds them from the upstream repositories at pinned commits.

## The sandbox, verified

Round two's isolation is physical, not polite. Containers run on an internal Docker network
with no route out; a dual-homed proxy allows CONNECT to exactly two hosts (the Claude and
OpenAI APIs) and refuses everything else. Across the whole exercise — the 66 final runs plus
the archived pre-retry runs — no fix used the web. The proxy's raw decision log is committed
(`runs/proxy-egress.log`: 8,228 refused outbound connections, only the two model API hosts
ever allowed), and `runs/EGRESS-EVIDENCE.md` itemizes the 39 network-reaching commands the
agents tried during the original sweep; each run's `meta.json` records its own attempts. All
33 maintainer fixes are dated after both models' documented training cutoffs (verified via
the GitHub API; see the adjudication), so the models cannot have memorized these fixes
either.

## Known limitations

Documented rather than hidden: each agent got one attempt per case (no variance measurement
yet); the AI cross-review is kept only as evidence of AI-judging-AI unreliability, never as
the headline; the two agent containers were not identical (Claude ran as a non-root user with
`HOME=/tmp`, Codex as root — an asymmetry documented in `PROCESS.md`, with prompt, budget,
CPU, and memory the same for both); one project (Apache Camel) does not compile offline even
before a fix is applied, so that single correct verdict rests on a careful read instead of
the compiler. The full list, with the two flaws we found in our own benchmark and how we
corrected them, is in the adjudication document.

## License

MIT for everything authored in this repository (scripts, docs, prompts, data files). The
`runs/`, `evidence/`, and `_superseded/` directories contain diffs and excerpts of the studied
open-source projects, which remain under their own upstream licenses; each case links its
upstream repository in `cases/<slug>/recipe` and `cases32.json`.
