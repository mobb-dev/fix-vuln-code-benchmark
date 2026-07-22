#!/usr/bin/env python3
"""Re-run ONLY the cross-reviews (Stage 3) for the given cases — does NOT re-run the fixes.

Feeds each reviewer the agent's fix.diff already on disk and OVERRIDES the existing review
outputs + verdicts FOR THE ACTIVE LANE PAIR ONLY (its old review files are cleared first, so
there are no duplicates; other backends' reviews — e.g. a MiniMax sweep's model-qualified
files — are left untouched). Use when a review's integrity is in question.

Usage: rereview.py <case> [<case> ...]
"""
import glob
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_fix import (ROOT, ensure_sandbox, gen_maintainer, review_one, read_recipe,  # noqa: E402
                     CLAUDE_MODEL, CODEX_MODEL, VERDICTS_NAME, lane_tag)


def main():
    cases = sys.argv[1:]
    if not cases:
        sys.exit("usage: rereview.py <case> ...")
    ensure_sandbox()
    for case in cases:
        recipe = read_recipe(case)
        image = f"vfb-{recipe['LANGUAGE']}"
        md = f"{ROOT}/runs/{case}/maintainer.diff"
        if not os.path.exists(md) or os.path.getsize(md) == 0:
            gen_maintainer(case, recipe)  # reviewer needs the gold standard
        before = ""
        vf = f"{ROOT}/runs/{case}/{VERDICTS_NAME}"
        if os.path.exists(vf):
            before = open(vf).read()
        # clear ONLY this lane pair's review artifacts so we override without touching
        # other backends' reviews
        ctag, xtag = lane_tag("claude-code", CLAUDE_MODEL), lane_tag("codex", CODEX_MODEL)
        for stem in (f"{ctag}-fix__by-{xtag}", f"{xtag}-fix__by-{ctag}"):
            for f in glob.glob(f"{ROOT}/runs/{case}/reviews/{stem}.*"):
                os.remove(f)
        print(f"=== re-reviewing {case} (fixes untouched) ===", flush=True)
        with ThreadPoolExecutor(max_workers=2) as ex:
            f1 = ex.submit(review_one, case, image, "claude-code", CLAUDE_MODEL, "codex", CODEX_MODEL)
            f2 = ex.submit(review_one, case, image, "codex", CODEX_MODEL, "claude-code", CLAUDE_MODEL)
            v_claude_by_codex, v_codex_by_claude = f1.result(), f2.result()
        open(vf, "w").write(
            f"case: {case}\n"
            f"{ctag} fix, reviewed by {xtag}: {v_claude_by_codex or '(no verdict)'}\n"
            f"{xtag} fix, reviewed by {ctag}: {v_codex_by_claude or '(no verdict)'}\n")
        print(f"  before: {before.strip().splitlines()[-2:] if before else 'n/a'}")
        print(f"  after : {v_claude_by_codex or '(no verdict)'} / {v_codex_by_claude or '(no verdict)'}", flush=True)


if __name__ == "__main__":
    main()
