#!/usr/bin/env python3
"""Run the full pipeline (run_fix.py) over a set of cases, several at a time.

Each case runs both agents in parallel (one container each). Cases run concurrently up to
PARALLEL_CASES (default 3) to cut wall-clock — Claude can think for many minutes on a hard
case, so strict one-at-a-time would take all day. Real memory use per agent is modest (~0.5 GB);
the --memory 4g is only a cap. Lower PARALLEL_CASES if the machine (which shares its Docker
daemon with other stacks) feels loaded.

Usage:  [CASES="slug slug ..."] [PARALLEL_CASES=2] run_all.py
        (default: every prepared checkout — checkouts/*/ that has a FINDING.txt)
"""
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from run_fix import ensure_sandbox  # noqa: E402

PARALLEL = int(os.environ.get("PARALLEL_CASES", "3"))


def run_case(c: str) -> tuple[str, int]:
    rc = subprocess.run(["caffeinate", "-i", "python3", str(ROOT / "scripts" / "run_fix.py"), c]).returncode
    return c, rc


def main() -> None:
    env_cases = os.environ.get("CASES", "").split()
    all_cases = env_cases or sorted(p.name for p in (ROOT / "checkouts").iterdir() if p.is_dir())
    cases = [c for c in all_cases if (ROOT / "checkouts" / c / "FINDING.txt").exists()]
    skipped = [c for c in all_cases if c not in cases]
    if skipped:
        print(f"skipping (not prepared): {', '.join(skipped)}")
    print(f"pipeline over {len(cases)} case(s), {PARALLEL} at a time", flush=True)

    ensure_sandbox()  # bring up the network + proxy ONCE so concurrent cases don't race to create it

    failed = []
    with ThreadPoolExecutor(max_workers=PARALLEL) as ex:
        futs = {ex.submit(run_case, c): c for c in cases}
        for f in as_completed(futs):
            c, rc = f.result()
            print(f"{'✓ done' if rc == 0 else '! FAILED'}: {c}", flush=True)
            if rc:
                failed.append(c)

    print("=" * 36, "verdicts", "=" * 36)
    for v in sorted((ROOT / "runs").glob("*/VERDICTS.txt")):
        print(f"--- {v.parent.name} ---")
        print(v.read_text())
    if failed:
        print(f"FAILED cases: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
