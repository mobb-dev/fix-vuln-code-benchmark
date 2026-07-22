#!/usr/bin/env python3
"""Read-only status board for the benchmark. Scans runs/<case>/ and reports the ground truth
from the run artifacts (not memory): each agent's diff size, wall time, clean-vs-killed,
used_web, blocked egress attempts; the gold-standard size; and the cross-review verdicts.

Usage: status.py            (all cases)
       status.py a b c      (only these cases)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
sys.path.insert(0, str(ROOT / "scripts"))
from run_fix import CLAUDE_MODEL, CODEX_MODEL  # noqa: E402  (dirs follow the active backend env)


def result_minutes(trace: Path):
    if not trace.exists():
        return None
    for line in trace.read_text(errors="replace").splitlines():
        line = line.strip()
        if line[:1] != "{":
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "result" and e.get("duration_ms"):
            return e["duration_ms"] / 60000
    return None


def agent_stat(d: Path):
    if not d.exists():
        return None
    meta = json.loads((d / "meta.json").read_text()) if (d / "meta.json").exists() else {}
    diff = (d / "fix.diff").read_text() if (d / "fix.diff").exists() else ""
    lines = sum(1 for ln in diff.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---"))
    killed = (d / "stderr.log").exists() and "killed: exceeded" in (d / "stderr.log").read_text(errors="replace")
    return {"lines": lines, "web": meta.get("used_web"), "egress": len(meta.get("egress_attempts", [])),
            "killed": killed, "min": result_minutes(d / "trace.jsonl")}


def diff_lines(p: Path):
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text().splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---"))


def fmt(s):
    if not s:
        return "—"
    t = f"{s['min']:.0f}m" if s["min"] else "?"
    flags = " ".join(filter(None, [
        "KILLED" if s["killed"] else "",
        "⚠WEB" if s["web"] else "",
        f"e{s['egress']}" if s["egress"] else "",
    ]))
    return f"{s['lines']}L {t} {flags}".strip()


def main():
    want = sys.argv[1:]
    cases = sorted(p.name for p in RUNS.iterdir() if p.is_dir()) if RUNS.exists() else []
    if want:
        cases = [c for c in cases if c in want]
    print(f"lanes: claude-code__{CLAUDE_MODEL} · codex__{CODEX_MODEL}")
    print(f"{'CASE':26} {'CLAUDE':20} {'CODEX':20} {'GOLD':>5}  VERDICTS (Claude-by-Codex / Codex-by-Claude)")
    print("-" * 100)
    clean = killed = web = egress = 0
    for c in cases:
        cl = agent_stat(RUNS / c / f"claude-code__{CLAUDE_MODEL}")
        cx = agent_stat(RUNS / c / f"codex__{CODEX_MODEL}")
        gold = diff_lines(RUNS / c / "maintainer.diff")
        vfile = RUNS / c / "VERDICTS.txt"
        verds = " / ".join(re.findall(r"VERDICT: (\w+)", vfile.read_text())) if vfile.exists() else "(running…)"
        print(f"{c:26} {fmt(cl):20} {fmt(cx):20} {gold:>5}  {verds}")
        for s in (cl, cx):
            if not s:
                continue
            killed += s["killed"]
            clean += not s["killed"]
            web += bool(s["web"])
            egress += s["egress"]
    print("-" * 100)
    print(f"{len(cases)} cases | {clean} agent-runs clean | {killed} killed | {web} used_web | {egress} egress attempts blocked")


if __name__ == "__main__":
    main()
