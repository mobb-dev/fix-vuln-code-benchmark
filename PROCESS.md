# Vuln-fix benchmark — the full pipeline, step by step (validated manually on appium-mcp-79 + scim-patch)

## Inputs per case `<slug>` (already prepared)
- `checkouts/<slug>/`        the project at the VULNERABLE commit (parent of the fix), git flattened.
- `checkouts/<slug>/FINDING.txt`   the finding: vulnerability TYPE + WHERE (file/function/line). No advisory
  text, no fix, no GHSA id/URL (those bias the agent / let it look the fix up).

## Stage 1 — FIX (Claude and Codex, in parallel, one container each)
1. **Clean workspace, history wiped, .gitignore kept.** Copy `checkouts/<slug>/` to a throwaway dir, then
   flatten its git: `rm -rf .git && git init && git add -A && git commit -m baseline` (generic message).
   Result: vulnerable files + the project's `.gitignore` + a `.git` with ONE baseline commit.
   - WHY: the `.gitignore` makes the diff robust (next), but the *original* clone's `.git` contains the fix
     commit (the fix is a descendant of the vulnerable parent) — the agent could `git show` it. Flattening
     leaves no history, no remote, no fix to read.
2. **Run the agent in a sandboxed container** (`vfb-<language>`):
   - mount the workspace at `/work`, working dir `/work`; no host access beyond it.
   - Claude: `--user 1000:1000 -e HOME=/tmp`, token via `--env-file .env` (never on disk).
   - Codex: runs as root, `~/.codex/auth.json` mounted read-only at `/seed` and copied in.
   - The claude-code lane is backend-swappable: `CLAUDE_BACKEND=minimax` points the same CLI at
     MiniMax's Anthropic-compatible endpoint (`api.minimax.io`, default model `MiniMax-M3`,
     key `MINIMAX_API_KEY`). The proxy allowlist follows the backend, the Claude token is not
     passed into MiniMax containers (and vice versa), and output goes to its own
     `runs/<slug>/claude-code__<model>/` directory. A swapped backend runs only its own fix
     lane (the published Codex fixes are reused as review counterparts) and writes
     model-qualified review/verdict filenames, so published artifacts are never overwritten.
   - **Web blocked**: Claude `--disallowedTools WebFetch,WebSearch,Bash(curl *|wget *|nc *|gh *|git push *|git remote *|git fetch *)`; Codex `-c tools.web_search=false`. The model-API connection still works.
   - Prompt = `prompt-template.txt` ("read FINDING.txt → remediate; local edits only; don't commit/push/PR").
3. **Capture the diff — robustly, using the project's own `.gitignore`** (NOT a hardcoded exclude list,
   which overfits). After the agent edits (it may run install/build/test → generated files):
   `git -C <workspace> add -A` (honors the project's `.gitignore`, e.g. node_modules/dist/lib/coverage) with a
   tiny universal backstop (`node_modules`, `__pycache__`, `*.pyc`) for repos with an incomplete ignore file,
   then `git diff --cached HEAD -- . ':!FINDING.txt'` → `fix.diff`. Generated artifacts excluded automatically.
4. **Bundle** into `runs/<slug>/<agent>__<model>/`: `prompt.txt`, `finding.txt`, `fix.diff`, `trace.jsonl`
   (raw), `transcript.md` (readable loop via render-transcript.py), `meta.json` (model, cost/tokens,
   `used_web`, tool count). Audit `used_web` == false.

## Stage 2 — MAINTAINER DIFF (the gold standard)
From the fix commit (`gh api /repos/<repo>/commits/<FIX>`), keep the SOURCE-file patches (exclude tests),
write `runs/<slug>/maintainer.diff`.

## Stage 3 — CROSS-REVIEW (each agent judges the OTHER's fix)
- Codex reviews Claude's fix; Claude reviews Codex's fix.
- Reviewer prompt (`review-prompt-template.txt`) = methodology + the finding + the maintainer's gold fix +
  the agent's fix. Runs in a sandboxed, web-blocked container; the diffs are in the prompt (no code mount).
- Output, captured to `runs/<slug>/reviews/<fixer>-fix__by-<reviewer>.md` (+ trace):
  `METHODOLOGY: … EVIDENCE: … REASONING: … VERDICT: CORRECT | PARTIAL | INCORRECT`.
  CORRECT = fully removes the vuln + preserves behavior; PARTIAL = misses a variant or over-reaches;
  INCORRECT = not fixed / breaks it.
- `runs/<slug>/VERDICTS.txt` summarizes both verdicts.

## Final per-case record: `runs/<slug>/`
both agent fix-bundles · `maintainer.diff` · `reviews/` (2 reviews + traces) · `VERDICTS.txt`
→ self-documenting: exact prompt → full reasoning/tools → diff → gold fix → independent verdict + why.

## Learnings baked in (from the manual runs)
- **Diff via the project's `.gitignore`, not a hardcoded exclude list** — the list overfit one example; the
  `.gitignore` generalizes (each project declares its own generated dirs). Validated: identical clean result.
- **Flatten, don't delete, git** — keep a single-commit `.git` (history wiped) so the `.gitignore`-diff works
  AND there's no fix to read. Original `.git` would leak the fix.
- **Agents build/test** → create node_modules/lib/.nyc_output; the `.gitignore` diff drops them.
- **Codex residual gap**: its `web_search` is off but it can still shell-`curl`; the `used_web`/trace audit
  catches it — reject any run that reached the web.
- **Capture the prompt + the full reasoning** (transcript), not just the diff — that's the audit trail.
- **Parse traces tolerantly** — the `vfb-java` image's Maven entrypoint prints `Can not write to /root/.m2/...`
  to **stdout** as line 1 (Claude runs as uid 1000, `/root` unwritable), which is not JSON. A strict
  `json.loads` per line crashed → empty meta + lost verdicts on every Java case. The loader now skips
  non-JSON lines. (This bug is why the pipeline moved from bash-with-inline-python-heredocs to Python.)

## Automated (Python — `scripts/run_fix.py`, `scripts/run_all.py`)
- `python3 scripts/run_fix.py <case>` — runs all three stages for one case (fixes in parallel → maintainer
  diff → cross-review in parallel) with every learning above baked in. Output: `runs/<case>/`.
- `[CASES="a b c"] python3 scripts/run_all.py` — sweeps `run_fix.py` over a case set ONE AT A TIME (default:
  every prepared `checkouts/*/`), then prints all `VERDICTS.txt`. Within a case the two agents run in
  parallel (one container each); cases never overlap, to bound Docker load on the shared daemon.
- Docker calls are built as argv lists (no shell quoting); traces are parsed with a tolerant loader that
  skips non-JSON lines — see the Maven-warning learning below.
- Validated end-to-end on appium-mcp-79 + scim-patch + the Go/Python/Java pilot (full bundle, `used_web=false`).

## Known limitation
The cross-review verdict is one signal, not ground truth: observed it pass a 5×-oversized (177-line vs the
maintainer's 35) Codex fix as CORRECT on appium-mcp-79, where manual judgment flagged over-reach. The bundle
keeps the gold diff + full reasoning so any case can be re-judged. For a correctness number, prefer execution
verification (fail-before / pass-after the maintainer's regression test) over the agent verdict.
