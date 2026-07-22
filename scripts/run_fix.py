#!/usr/bin/env python3
"""Full benchmark pipeline for ONE case (see PROCESS.md).

  Stage 1  FIX     Claude + Codex each remediate the vulnerable checkout
                   (sandboxed container, web-blocked, the two agents in parallel).
  Stage 2  GOLD    capture the maintainer's official fix diff (source files only).
  Stage 3  REVIEW  Codex judges Claude's fix and Claude judges Codex's fix
                   (verdict + evidence + reasoning), in parallel.

Output: runs/<case>/  — both fix bundles, maintainer.diff, reviews/, VERDICTS.txt.
Usage:  run_fix.py <case-slug>

Overridable via env: CLAUDE_BACKEND (anthropic | minimax), CLAUDE_MODEL, CODEX_MODEL, EFFORT.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The claude-code lane is backend-swappable: the same Claude Code CLI can drive Anthropic's
# Claude (default) or a MiniMax M-series model through MiniMax's Anthropic-compatible
# endpoint (https://platform.minimax.io/docs/token-plan/claude-code). Each backend writes
# to its own runs/<case>/claude-code__<model>/ directory, so results never overwrite.
CLAUDE_BACKEND = os.environ.get("CLAUDE_BACKEND", "anthropic")
_CLAUDE_DEFAULT_MODEL = {"anthropic": "claude-opus-4-8", "minimax": "MiniMax-M3"}
if CLAUDE_BACKEND not in _CLAUDE_DEFAULT_MODEL:
    sys.exit(f"unknown CLAUDE_BACKEND={CLAUDE_BACKEND!r} (expected: anthropic | minimax)")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", _CLAUDE_DEFAULT_MODEL[CLAUDE_BACKEND])
MINIMAX_BASE_URL = os.environ.get("MINIMAX_BASE_URL", "https://api.minimax.io/anthropic")
CODEX_MODEL = os.environ.get("CODEX_MODEL", "gpt-5.5")
EFFORT = os.environ.get("EFFORT", "medium")

# Which fix lanes stage 1 runs. Classic runs do both; a swapped claude backend defaults to
# only its own lane, so the published codex fixes are reused as the review counterpart
# instead of being re-run (and overwritten).
_DEFAULT_LANES = "claude,codex" if CLAUDE_BACKEND == "anthropic" else "claude"
FIX_LANES = [l.strip() for l in os.environ.get("FIX_LANES", _DEFAULT_LANES).split(",") if l.strip()]


def lane_tag(agent: str, model: str) -> str:
    """Filename tag for review/verdict artifacts. The classic pairs keep the published
    names; any other model is qualified so new artifacts can never overwrite them."""
    classic = {"claude-code": "claude-opus-4-8", "codex": "gpt-5.5"}
    return agent if classic.get(agent) == model else f"{agent}__{model}"


_NONCLASSIC = [m for a, m in (("claude-code", CLAUDE_MODEL), ("codex", CODEX_MODEL))
               if lane_tag(a, m) != a]
VERDICTS_NAME = "VERDICTS.txt" if not _NONCLASSIC else f"VERDICTS__{'__'.join(_NONCLASSIC)}.txt"

# ── Sandbox isolation ─────────────────────────────────────────────────────────
# The agent containers sit on an --internal docker network (no route out, no external DNS)
# whose ONLY reachable peer is an allowlist CONNECT proxy that permits the model hosts and
# nothing else. So `git clone github.com` / `curl raw.githubusercontent` / `python urllib`
# have nowhere to go — a denylist of shell commands can't be evaded because there's no route.
NET = "vfb-internal"
PROXY = "vfb-proxy"
# The allowlist follows the active backend: exactly the model hosts in use, nothing more.
_MODEL_HOST = {"anthropic": r"api\.anthropic\.com", "minimax": r"api\.minimax\.io"}
ALLOW_HOSTS = os.environ.get("ALLOW_HOSTS", rf"{_MODEL_HOST[CLAUDE_BACKEND]},chatgpt\.com")
SANDBOX = ["--network", NET,
           "-e", f"HTTPS_PROXY=http://{PROXY}:8888", "-e", f"HTTP_PROXY=http://{PROXY}:8888",
           "-e", f"https_proxy=http://{PROXY}:8888", "-e", f"http_proxy=http://{PROXY}:8888"]
# Audit backstop: flag any executed command that reaches for the network. Prevention should make
# these fail (no route), but recording attempts surfaces a fail-open proxy or a missed model host.
EGRESS_RE = re.compile(r"urllib|urlopen|requests\.|httpx|http\.client|\bfetch\(|\bcurl\b|\bwget\b|"
                       r"raw\.githubusercontent|git\s+clone|git\s+fetch|git\s+remote|\bnc\b|"
                       r"Invoke-WebRequest|axios|/dev/tcp")

# Web is blocked so the agent can never fetch the advisory/fix or phone out; the model API still works.
# (Claude denies the fetch tools + shell escape hatches; Codex gets tools.web_search=false at call time.)
CLAUDE_FIX_DENY = ("WebFetch,WebSearch,Bash(curl *),Bash(wget *),Bash(nc *),Bash(gh *),"
                   "Bash(git push *),Bash(git remote *),Bash(git fetch *)")
CLAUDE_REVIEW_DENY = "WebFetch,WebSearch,Bash(curl *),Bash(wget *)"

# Codex needs its auth copied into place before it runs; the prompt is passed via env to avoid shell quoting.
CODEX_FIX_SCRIPT = (
    'mkdir -p /root/.codex && cp /seed/auth.json /root/.codex/auth.json 2>/dev/null; '
    'codex exec --json -m "$CODEX_MODEL" -c model_reasoning_effort="$EFF" '
    '-c tools.web_search=false --dangerously-bypass-approvals-and-sandbox "$CODEX_PROMPT" </dev/null'
)
CODEX_REVIEW_SCRIPT = (
    'mkdir -p /root/.codex && cp /seed/auth.json /root/.codex/auth.json 2>/dev/null; '
    'codex exec --json -m "$RM" -c model_reasoning_effort=medium '
    '-c tools.web_search=false --dangerously-bypass-approvals-and-sandbox "$REVIEW_PROMPT" </dev/null'
)


# ── helpers ──────────────────────────────────────────────────────────────────
def load_events(path: Path) -> list[dict]:
    """Parse a stream-json / --json trace, skipping any non-JSON line.

    The vfb-java image's Maven entrypoint prints 'Can not write to /root/.m2/...'
    to stdout as the first line (Claude runs as uid 1000, /root is unwritable); a
    strict json.loads(line) crashes on it. Skipping non-JSON lines keeps us robust
    to any such warning that leaks onto the trace stream.
    """
    events = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def env_file_value(key: str) -> str:
    """Read one KEY=VALUE line from .env (docker --env-file syntax, no quotes)."""
    envf = ROOT / ".env"
    if envf.exists():
        for line in envf.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return ""


def claude_lane_env() -> list[str]:
    """Docker env args for the claude-code lane, per backend.

    anthropic (default): the Claude subscription token via --env-file, as always.
    minimax: the same CLI pointed at MiniMax's Anthropic-compatible endpoint. Explicit
    vars INSTEAD of --env-file so the real Anthropic token never enters the container
    (MiniMax's docs require the conflicting Anthropic vars to be absent). The key's
    value travels through a bare `-e NAME` — docker reads it from this process's
    environment — so it stays out of the container's argv and `docker inspect` args.
    """
    if CLAUDE_BACKEND == "anthropic":
        return ["--env-file", str(ROOT / ".env")]
    key = os.environ.get("MINIMAX_API_KEY") or env_file_value("MINIMAX_API_KEY")
    if not key:
        sys.exit("CLAUDE_BACKEND=minimax needs MINIMAX_API_KEY (env var or a .env line)")
    os.environ["ANTHROPIC_AUTH_TOKEN"] = key
    env = ["-e", f"ANTHROPIC_BASE_URL={MINIMAX_BASE_URL}", "-e", "ANTHROPIC_AUTH_TOKEN",
           "-e", f"ANTHROPIC_SMALL_FAST_MODEL={CLAUDE_MODEL}"]
    if "[1m]" in CLAUDE_MODEL:
        env += ["-e", "CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000"]
    return env


def read_recipe(case: str) -> dict:
    out = {}
    for line in (ROOT / "cases" / case / "recipe").read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v.strip().strip('"')
    return out


def git(work: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(work), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def flatten_workspace(src: Path) -> Path:
    """Copy the vulnerable checkout to a throwaway dir and flatten git to a single
    baseline commit — keeps the project's .gitignore (so the diff drops generated
    files) but leaves no fix history for the agent to read."""
    work = Path(tempfile.mkdtemp(prefix="vfb-"))
    subprocess.run(["cp", "-a", f"{src}/.", str(work)], check=True)
    shutil.rmtree(work / ".git", ignore_errors=True)
    git(work, "init", "-q")
    git(work, "config", "user.email", "b@b")
    git(work, "config", "user.name", "b")
    git(work, "add", "-A")
    git(work, "commit", "-qm", "baseline")
    # universal backstop for repos whose .gitignore misses these
    with (work / ".git" / "info" / "exclude").open("a") as f:
        f.write("node_modules/\n__pycache__/\n*.pyc\n")
    subprocess.run(["chmod", "-R", "a+rwX", str(work)], check=True)
    return work


def capture_diff(work: Path, out: Path) -> int:
    """Diff via the project's own .gitignore so generated/dependency artifacts drop
    out automatically (not a hardcoded exclude list). Returns changed-line count."""
    git(work, "add", "-A")
    diff = subprocess.run(
        ["git", "-C", str(work), "diff", "--cached", "HEAD", "--", ".", ":!FINDING.txt"],
        capture_output=True, text=True).stdout
    out.write_text(diff)
    return sum(1 for ln in diff.splitlines() if ln[:1] in "+-" and not ln[:3] in ("+++", "---"))


def docker_run(args: list[str], stdout: Path | None = None, stderr: Path | None = None,
               name: str | None = None, timeout: int | None = None) -> None:
    """Run a container. If `name` + `timeout` are given, a hung agent (e.g. stuck in API
    rate-limit backoff) is killed after `timeout`s instead of stalling the whole sweep."""
    out_f = open(stdout, "wb") if stdout else subprocess.DEVNULL
    err_f = open(stderr, "wb") if stderr else subprocess.DEVNULL
    full = [DOCKER, "run", "--rm", *(["--name", name] if name else []), *args]
    try:
        subprocess.run(full, stdout=out_f, stderr=err_f, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        if name:
            subprocess.run([DOCKER, "kill", name], capture_output=True)
        if stderr:
            with open(stderr, "ab") as f:
                f.write(f"\n[run_fix] killed: exceeded {timeout}s timeout\n".encode())
    finally:
        for f in (out_f, err_f):
            if hasattr(f, "close"):
                f.close()


DOCKER = "docker"
COMMON = ["-w", "/work", "--memory", "4g", "--cpus", "2", "--pids-limit", "1024"]
AGENT_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT", "2400"))  # 40 min cap per agent (Claude thinks long on hard cases)


def ensure_sandbox() -> None:
    """Create the internal (no-egress) network and start the allowlist proxy if not already up.
    Idempotent — safe to call before every case. A dead proxy fails runs closed (no leak).
    If a running proxy's allowlist differs from ALLOW_HOSTS (e.g. CLAUDE_BACKEND switched
    between runs), it is recreated — a stale allowlist would fail the new backend closed."""
    if subprocess.run(["docker", "network", "inspect", NET], capture_output=True).returncode:
        subprocess.run(["docker", "network", "create", "--internal", NET], check=True, stdout=subprocess.DEVNULL)
    running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", PROXY],
                             capture_output=True, text=True).stdout.strip()
    if running == "true":
        env_lines = subprocess.run(
            ["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", PROXY],
            capture_output=True, text=True).stdout.splitlines()
        current = next((ln.split("=", 1)[1] for ln in env_lines if ln.startswith("ALLOW_HOSTS=")), None)
        if current != ALLOW_HOSTS:
            print(f"[sandbox] proxy allowlist changed ({current!r} -> {ALLOW_HOSTS!r}), recreating {PROXY}", flush=True)
            running = "false"
    if running != "true":
        subprocess.run(["docker", "rm", "-f", PROXY], capture_output=True)
        subprocess.run(["docker", "run", "-d", "--name", PROXY, "--network", NET,
                        "-v", f"{ROOT}/scripts:/s:ro", "-e", f"ALLOW_HOSTS={ALLOW_HOSTS}",
                        "vfb-python", "python3", "/s/egress_proxy.py"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "connect", "bridge", PROXY], check=True)  # proxy alone gets internet
        time.sleep(2)
        print(f"[sandbox] {NET} + {PROXY} up (allow: {ALLOW_HOSTS})", flush=True)


def parse_meta(events: list[dict], agent: str, model: str) -> dict:
    """Audit record from the trace. `used_web` = a named web tool fired; `egress_attempts` =
    shell commands that reached for the network (these should FAIL — no route — under the sandbox)."""
    web, tools, turns, cost, usage = False, 0, None, None, None
    egress = []
    for e in events:
        t = e.get("type")
        if t == "assistant":
            for b in e.get("message", {}).get("content", []):
                if b.get("type") == "tool_use":
                    tools += 1
                    if b.get("name") in ("WebFetch", "WebSearch"):
                        web = True
                    if b.get("name") == "Bash" and EGRESS_RE.search(b.get("input", {}).get("command", "") or ""):
                        egress.append((b.get("input", {}).get("command", ""))[:200])
        elif t == "result":
            turns, cost = e.get("num_turns"), e.get("total_cost_usd")
        elif t == "item.completed" and e.get("item", {}).get("type") == "command_execution":
            tools += 1
            cmd = e["item"].get("command", "") or ""
            if EGRESS_RE.search(cmd):
                egress.append(cmd[:200])
        elif t == "turn.completed":
            usage = e.get("usage")
    return {"agent": agent, "model": model, "tool_calls": tools, "turns": turns,
            "cost_usd": cost, "usage": usage, "used_web": web, "egress_attempts": egress}


def render_transcript(trace: Path) -> str:
    r = subprocess.run(["python3", str(ROOT / "scripts" / "render-transcript.py"), str(trace)],
                       capture_output=True, text=True)
    return r.stdout


def verdict_of(md: str) -> str:
    for line in md.splitlines():
        if "VERDICT:" in line:
            return line.strip()
    return ""


# ── Stage 1: fix ─────────────────────────────────────────────────────────────
def fix_one(case: str, image: str, agent: str, model: str, prompt: str) -> dict:
    rd = ROOT / "runs" / case / f"{agent}__{model}"
    rd.mkdir(parents=True, exist_ok=True)
    work = flatten_workspace(ROOT / "checkouts" / case)
    try:
        mount = ["-v", f"{work}:/work"]
        if agent == "claude-code":
            docker_run(
                [*mount, *COMMON, *SANDBOX, "--user", "1000:1000", "-e", "HOME=/tmp",
                 *claude_lane_env(), image,
                 "claude", "-p", prompt, "--model", model, "--dangerously-skip-permissions",
                 "--output-format", "stream-json", "--verbose", "--disallowedTools", CLAUDE_FIX_DENY],
                rd / "trace.jsonl", rd / "stderr.log",
                name=f"vfb-fix-{case}-{agent}", timeout=AGENT_TIMEOUT)
        else:  # codex
            docker_run(
                [*mount, *COMMON, *SANDBOX, "-v", f"{Path.home()}/.codex:/seed:ro", "-e", "HOME=/root",
                 "-e", f"CODEX_MODEL={model}", "-e", f"EFF={EFFORT}", "-e", f"CODEX_PROMPT={prompt}",
                 image, "bash", "-lc", CODEX_FIX_SCRIPT],
                rd / "trace.jsonl", rd / "stderr.log",
                name=f"vfb-fix-{case}-{agent}", timeout=AGENT_TIMEOUT)

        changed = capture_diff(work, rd / "fix.diff")
        (rd / "prompt.txt").write_text(prompt)
        shutil.copy(ROOT / "checkouts" / case / "FINDING.txt", rd / "finding.txt")
        events = load_events(rd / "trace.jsonl")
        (rd / "transcript.md").write_text(render_transcript(rd / "trace.jsonl"))
        meta = parse_meta(events, agent, model)
        (rd / "meta.json").write_text(json.dumps(meta, indent=2))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ea = len(meta["egress_attempts"])
    note = f", ⚠ {ea} egress attempt(s) blocked" if ea else ""
    print(f"[{case}] {agent}__{model}: {changed} diff lines, used_web={meta['used_web']}{note}", flush=True)
    return meta


# ── Stage 2: maintainer gold diff ────────────────────────────────────────────
def gen_maintainer(case: str, recipe: dict) -> None:
    """Capture the maintainer's official fix as the gold standard — source files only
    (drop tests/dist/lib). Filtering is done in Python (robust; no jq-escaping pitfalls,
    and `.patch` may be absent for binary/oversized files)."""
    gold = ROOT / "runs" / case / "maintainer.diff"
    if gold.exists() and gold.stat().st_size:
        print(f"[{case}] maintainer.diff exists — reused", flush=True)
        return
    repo = recipe["REPO_URL"].replace("https://github.com/", "").replace(".git", "")
    r = subprocess.run(["gh", "api", f"/repos/{repo}/commits/{recipe['FIX_COMMIT']}"],
                       capture_output=True, text=True)
    files = json.loads(r.stdout).get("files", []) if r.returncode == 0 else []
    src = re.compile(r"\.(go|py|java|ts|js|jsx|tsx|mjs|cjs)$")
    skip = re.compile(r"test|spec|/dist/|/lib/")
    parts = [f"--- a/{f['filename']}\n+++ b/{f['filename']}\n{f['patch']}"
             for f in files
             if src.search(f["filename"]) and not skip.search(f["filename"]) and f.get("patch")]
    diff = "\n".join(parts)
    gold.write_text(diff)
    n = sum(1 for ln in diff.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---"))
    print(f"[{case}] maintainer.diff: {n} lines ({len(parts)} source files)", flush=True)


# ── Stage 3: cross-review ────────────────────────────────────────────────────
def review_one(case: str, image: str, fixer: str, fmodel: str, reviewer: str, rmodel: str) -> str:
    out = ROOT / "runs" / case / "reviews" / f"{lane_tag(fixer, fmodel)}-fix__by-{lane_tag(reviewer, rmodel)}"
    out.parent.mkdir(parents=True, exist_ok=True)
    prompt = "\n".join([
        (ROOT / "review-prompt-template.txt").read_text(),
        "\n===== 1. THE VULNERABILITY =====",
        (ROOT / "checkouts" / case / "FINDING.txt").read_text(),
        "===== 2. MAINTAINER OFFICIAL FIX (gold standard) =====",
        (ROOT / "runs" / case / "maintainer.diff").read_text(),
        "===== 3. THE AGENT FIX TO JUDGE =====",
        (ROOT / "runs" / case / f"{fixer}__{fmodel}" / "fix.diff").read_text(),
    ])
    out.with_suffix(".prompt.txt").write_text(prompt)
    trace, err = out.with_suffix(".trace.jsonl"), out.with_suffix(".err.log")

    if reviewer == "claude-code":
        docker_run(
            [*SANDBOX, "--user", "1000:1000", "-e", "HOME=/tmp", "--memory", "2g", "--cpus", "2",
             *claude_lane_env(), image,
             "claude", "-p", prompt, "--model", rmodel, "--dangerously-skip-permissions",
             "--output-format", "stream-json", "--verbose", "--disallowedTools", CLAUDE_REVIEW_DENY],
            trace, err, name=f"vfb-rev-{case}-{fixer}-by-{reviewer}", timeout=AGENT_TIMEOUT)
        texts = [e.get("result", "") for e in load_events(trace) if e.get("type") == "result"]
    else:  # codex
        docker_run(
            [*SANDBOX, "-v", f"{Path.home()}/.codex:/seed:ro", "-e", "HOME=/root", "--memory", "2g", "--cpus", "2",
             "-e", f"RM={rmodel}", "-e", f"REVIEW_PROMPT={prompt}", image, "bash", "-lc", CODEX_REVIEW_SCRIPT],
            trace, err, name=f"vfb-rev-{case}-{fixer}-by-{reviewer}", timeout=AGENT_TIMEOUT)
        texts = [e["item"]["text"] for e in load_events(trace)
                 if e.get("type") == "item.completed" and e.get("item", {}).get("type") == "agent_message"]

    md = texts[-1] if texts else ""
    out.with_suffix(".md").write_text(md)
    v = verdict_of(md)
    print(f"[{case}] {fixer}-fix reviewed by {reviewer}: {v or '(no verdict)'}", flush=True)
    return v


# ── orchestration ────────────────────────────────────────────────────────────
def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: run_fix.py <case-slug>")
    case = sys.argv[1]
    src = ROOT / "checkouts" / case
    if not (src / "FINDING.txt").exists():
        sys.exit(f"missing checkout or FINDING.txt for {case}")
    recipe = read_recipe(case)
    image = f"vfb-{recipe['LANGUAGE']}"
    (ROOT / "runs" / case / "reviews").mkdir(parents=True, exist_ok=True)
    prompt = (ROOT / "prompt-template.txt").read_text()

    ensure_sandbox()  # internal network + allowlist proxy must be up before any agent runs
    print(f"=== [{case}] Stage 1: fixes ({' + '.join(FIX_LANES)}) ===", flush=True)
    lane_jobs = {"claude": ("claude-code", CLAUDE_MODEL), "codex": ("codex", CODEX_MODEL)}
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(fix_one, case, image, *lane_jobs[l], prompt)
                for l in FIX_LANES if l in lane_jobs]
    for f in futs:
        f.result()  # surface any unexpected exception

    print(f"=== [{case}] Stage 2: maintainer diff ===", flush=True)
    gen_maintainer(case, recipe)

    # Reviews pair whatever fixes are on disk: a lane that did not run this sweep (e.g.
    # codex under CLAUDE_BACKEND=minimax) is judged from its existing published fix.
    print(f"=== [{case}] Stage 3: cross-review ===", flush=True)

    def have_fix(agent: str, model: str) -> bool:
        return (ROOT / "runs" / case / f"{agent}__{model}" / "fix.diff").exists()

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_claude_by_codex = (ex.submit(review_one, case, image, "claude-code", CLAUDE_MODEL, "codex", CODEX_MODEL)
                             if have_fix("claude-code", CLAUDE_MODEL) else None)
        f_codex_by_claude = (ex.submit(review_one, case, image, "codex", CODEX_MODEL, "claude-code", CLAUDE_MODEL)
                             if have_fix("codex", CODEX_MODEL) else None)
        v_claude_by_codex = f_claude_by_codex.result() if f_claude_by_codex else "(no fix on disk)"
        v_codex_by_claude = f_codex_by_claude.result() if f_codex_by_claude else "(no fix on disk)"

    ctag, xtag = lane_tag("claude-code", CLAUDE_MODEL), lane_tag("codex", CODEX_MODEL)
    verdicts = (f"case: {case}\n"
                f"{ctag} fix, reviewed by {xtag}: {v_claude_by_codex or '(no verdict)'}\n"
                f"{xtag} fix, reviewed by {ctag}: {v_codex_by_claude or '(no verdict)'}\n")
    (ROOT / "runs" / case / VERDICTS_NAME).write_text(verdicts)
    print(verdicts, flush=True)
    print(f"=== [{case}] done -> {ROOT / 'runs' / case} ===", flush=True)


if __name__ == "__main__":
    main()
