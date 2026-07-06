#!/usr/bin/env python3
"""Inject generated sections into blog-post/post.html:

1. V1 full results matrix (7 CVEs x 6 models x 3 reasoning efforts, real-test verdicts)
   between <!--V1MATRIX:BEGIN--> / <!--V1MATRIX:END-->.
2. The round-two case browser (all 33 cases: complete maintainer/Claude/Codex diffs,
   both cross-reviews, human verdicts) between <!--CASEBROWSER:BEGIN--> / <!--CASEBROWSER:END-->.
   On first run it bootstraps the markers by replacing the old hand-made featured block.

Re-runnable: content between markers is replaced wholesale each time.
All injected text is HTML-escaped and long-dash-sanitized (house style: no em/en dashes).
"""
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # repo root (this script lives in docs/blog-post/)
POST = os.path.join(HERE, "post.html")
A = 'target="_blank" rel="noopener noreferrer"'
CL_DIR = "claude-code__claude-opus-4-8"
CX_DIR = "codex__gpt-5.5"


def dash(s):
    """House style: no em/en dashes anywhere, including quoted material."""
    s = s.replace(" — ", ", ").replace("—", ", ")
    s = s.replace(" – ", ", ").replace("–", "-")
    return s


def esc(s):
    return dash(html.escape(s, quote=False))


# ----------------------------------------------------------------------------
# 1. The v1 matrix (authoritative data recovered from the published v1 report)
# ----------------------------------------------------------------------------
V1_CASES = [
    ("go-attestation", "google/go-attestation", "CWE-20 input validation"),
    ("filebrowser", "filebrowser/filebrowser", "CWE-863 broken authorization"),
    ("gogs", "gogs/gogs", "CWE-345 data authenticity"),
    ("devbridge-autocomplete", "devbridge/jQuery-Autocomplete", "CWE-79 cross-site scripting"),
    ("scim-patch", "thomaspoignant/scim-patch", "CWE-1321 prototype pollution"),
    ("marimo", "marimo-team/marimo", "CWE-79 cross-site scripting"),
    ("xwiki-commons", "xwiki/xwiki-commons", "CWE-23 path traversal"),
]
V1_MODELS = [
    ("Claude Opus 4.8", "opus", "$8.66 total", "91s avg", "273K tok avg"),
    ("Claude Sonnet 4.6", "sonnet", "$4.70 total", "84s avg", "262K tok avg"),
    ("Claude Haiku 4.5", "haiku", "$2.34 total", "68s avg", "400K tok avg"),
    ("GPT-5.5", "g55", "cost n/a", "171s avg", "639K tok avg"),
    ("GPT-5.4", "g54", "cost n/a", "132s avg", "471K tok avg"),
    ("GPT-5.4-mini", "g54m", "cost n/a", "172s avg", "597K tok avg"),
]
EFFORTS = ["lo", "md", "hi"]
V1_FAILS = {
    ("go-attestation", "sonnet", "lo"), ("go-attestation", "sonnet", "md"),
    ("go-attestation", "haiku", "hi"),
    ("scim-patch", "sonnet", "lo"),
    ("scim-patch", "haiku", "lo"), ("scim-patch", "haiku", "md"), ("scim-patch", "haiku", "hi"),
    ("go-attestation", "g54", "lo"),
    ("go-attestation", "g54m", "lo"), ("go-attestation", "g54m", "hi"),
    ("scim-patch", "g54m", "hi"),
}


def check_v1():
    per_model = {k: 0 for _, k, *_ in V1_MODELS}
    for c, m, e in V1_FAILS:
        assert any(c == s for s, _, _ in V1_CASES), c
        assert e in EFFORTS, e
        per_model[m] += 1
    expect = {"opus": 0, "sonnet": 3, "haiku": 4, "g55": 0, "g54": 1, "g54m": 3}
    assert per_model == expect, per_model
    claude_pass = 63 - (per_model["opus"] + per_model["sonnet"] + per_model["haiku"])
    codex_pass = 63 - (per_model["g55"] + per_model["g54"] + per_model["g54m"])
    assert claude_pass == 56 and codex_pass == 59, (claude_pass, codex_pass)


def gen_matrix():
    check_v1()
    out = ['<div class="mxwrap"><table class="mx">']
    # header
    out.append("<thead><tr><th rowspan=\"2\" style=\"text-align:left\">Vulnerability</th>")
    for name, _key, *_ in V1_MODELS:
        out.append(f'<th colspan="3" class="vgrp">{esc(name)}</th>')
    out.append("</tr><tr>")
    for i, _m in enumerate(V1_MODELS):
        for j, e in enumerate(EFFORTS):
            cls = ' class="vgrp"' if j == 0 else ""
            out.append(f"<th{cls}>{e}</th>")
    out.append("</tr></thead><tbody>")
    # body
    for slug, repo, cwe in V1_CASES:
        out.append(
            f'<tr><td class="rowh"><a href="https://github.com/{repo}" {A}>{esc(repo)}</a>'
            f'<span class="cw">{esc(cwe)}</span></td>'
        )
        for _name, key, *_ in V1_MODELS:
            for j, e in enumerate(EFFORTS):
                fail = (slug, key, e) in V1_FAILS
                cls = "ko" if fail else "ok"
                if j == 0:
                    cls += " vgrp"
                out.append(f'<td class="{cls}">{"✗" if fail else "✓"}</td>')
        out.append("</tr>")
    out.append("</tbody><tfoot><tr><td class=\"rowh\">per model</td>")
    for _name, key, cost, secs, toks in V1_MODELS:
        fails = sum(1 for c in V1_FAILS if c[1] == key)
        out.append(f'<td colspan="3" class="vgrp">{21 - fails}/21 · {esc(cost)} · {esc(secs)} · {esc(toks)}</td>')
    out.append("</tr></tfoot></table></div>")
    out.append(
        '<p class="mxnote">✓ = the project\'s own security test flips from red (vulnerable) to green (fixed)'
        " and the rest of the suite stays green. lo / md / hi = reasoning effort."
        " Totals: Claude Code 56/63 ($15.70, 85 min); Codex 59/63 (165 min)."
        " Both flagships 21/21; every miss sits with a smaller model on the same two bugs.</p>"
    )
    return "\n".join(out)


# ----------------------------------------------------------------------------
# 2. The round-two case browser
# ----------------------------------------------------------------------------
PILL = {"CORRECT": "ok", "PARTIAL": "part", "INCORRECT": "bad"}

CNOTES = {
    "async-http-client-200": (
        "All three edited the same method. The maintainer and Claude removed the "
        "<code>Cookie</code> header, which is the actual leak. Codex did not."
    ),
    "vert-x-295": (
        "Re-run with a corrected finding. The real CVE-2026-6860 is an unbounded SNI SslContext cache "
        "(a memory-exhaustion DoS, CWE-770), which is exactly what the maintainer fixed. Our original "
        "finding mislabeled it as certificate validation, which sent both agents to the wrong fix. With "
        "the label corrected, both agents bound the cache; both compile."
    ),
    "nezha-862": (
        "Re-run on a repaired baseline. The original benchmark baseline was a non-compiling intermediate "
        "commit (it called an authorization function the fix commit defined). Rebuilt one commit earlier so "
        "it compiles and is still vulnerable; both agents then gate the reporting paths, and both compile."
    ),
}
OPEN_CASE = "async-http-client-200"

# Cases where the agent returned no patch. A refusal (declined the task) is a
# different failure mode than a give-up (tried, did not converge) — both count as
# not-fixed, but we say which so the empty "code" tab is not mistaken for a bug.
EMPTY_REASON = {
    ("openbao-617", "codex"): (
        "Codex declined this task and returned no patch. This is a deliberate refusal, "
        "not a failed attempt. We still count it as not-fixed (the vulnerability stays open), "
        "but it is a refusal, not an inability."
    ),
    ("nebula-mesh-862", "claude"): (
        "Claude returned no patch. On a fair re-run it still did not converge on a fix, "
        "so we count it as not-fixed. The review below grades that empty submission."
    ),
}


def empty_msg(slug, agent, label):
    return EMPTY_REASON.get((slug, agent),
                            f"{label} produced no code for this case. See the Human tab for why.")

TWOAXIS = json.load(open(os.path.join(ROOT, "two-axis.json")))
SEC_MAP = {"closed": ("ok", "vuln closed"), "partly": ("part", "vuln partly"),
           "open": ("bad", "vuln open"), "na": ("part", "vuln n/a")}
BLD_MAP = {"compiles": ("ok", "builds"), "broken": ("bad", "won't build"),
           "unverified": ("part", "build unverified"), "none": ("part", "no code")}


def axstrip(slug):
    ta = TWOAXIS.get(slug, {})
    parts = []
    for agent, name in (("claude", "Claude"), ("codex", "Codex")):
        a = ta.get(agent, {})
        sc, sl = SEC_MAP.get(a.get("security", "na"), ("part", "?"))
        bc, bl = BLD_MAP.get(a.get("build", "unverified"), ("part", "?"))
        parts.append(f'<span class="axlab">{name}</span> '
                     f'<span class="vd {sc}">{sl}</span> <span class="vd {bc}">{bl}</span>')
    return '<div class="axstrip">' + '<span class="axsep">·</span>'.join(parts) + '</div>'


def classify_diff(text):
    out = []
    for line in text.split("\n"):
        e = esc(line.rstrip("\r"))
        if line.startswith(("diff ", "index ", "+++", "---", "@@", "new file", "deleted file",
                            "similarity", "rename ", "old mode", "new mode", "Binary files")):
            out.append(f'<span class="hunk">{e}</span>')
        elif line.startswith("+"):
            out.append(f'<span class="add">{e}</span>')
        elif line.startswith("-"):
            out.append(f'<span class="del">{e}</span>')
        else:
            out.append(f'<span class="ctx">{e}</span>')
    return "\n".join(out)


def diff_counts(text):
    add = sum(1 for l in text.split("\n") if l.startswith("+") and not l.startswith("+++"))
    dele = sum(1 for l in text.split("\n") if l.startswith("-") and not l.startswith("---"))
    return add, dele


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_verdicts(path):
    cl = cx = "?"
    for line in read(path).splitlines():
        m = re.search(r"VERDICT:\s*([A-Z]+)", line)
        if not m:
            continue
        if line.startswith("Claude fix"):
            cl = m.group(1)
        elif line.startswith("Codex fix"):
            cx = m.group(1)
    return cl, cx


def pill(verdict, label):
    cls = PILL.get(verdict, "part")
    return f'<span class="vd {cls}">{esc(label)}: {esc(verdict.lower())}</span>'


def diff_panel(key, active, meta_html, diff_text, empty_note):
    act = " active" if active else ""
    if diff_text.strip():
        body = f'<pre class="diff"><code>{classify_diff(diff_text)}</code></pre>'
    else:
        body = f'<div class="rev">{esc(empty_note)}</div>'
    return (f'<div data-panel="{key}" class="{act.strip()}">'
            f'<div class="meta">{meta_html}</div>{body}</div>')


def tab_group(buttons, panels):
    bar = "".join(
        f'<button data-tab="{k}"{" class=\"active\"" if i == 0 else ""} type="button">{esc(lbl)}</button>'
        for i, (k, lbl) in enumerate(buttons)
    )
    return f'<div class="tabs" data-tabs><div class="tabbar">{bar}</div>{"".join(panels)}</div>'


def gen_case(c, human):
    slug = c["slug"]
    base = os.path.join(ROOT, "runs", slug)
    gold = read(os.path.join(base, "maintainer.diff"))
    cl = read(os.path.join(base, CL_DIR, "fix.diff"))
    cx = read(os.path.join(base, CX_DIR, "fix.diff"))
    rev_cl = read(os.path.join(base, "reviews", "claude-code-fix__by-codex.md"))
    rev_cx = read(os.path.join(base, "reviews", "codex-fix__by-claude-code.md"))
    aud_cl, aud_cx = parse_verdicts(os.path.join(base, "VERDICTS.txt"))
    hv = human[slug]
    h_cl, h_cx = hv["claude"]["v"], hv["codex"]["v"]

    repo = c["repo"]
    ga, gd = diff_counts(gold)
    ca, cd = diff_counts(cl)
    xa, xd = diff_counts(cx)

    # summary row
    is_open = " open" if slug == OPEN_CASE else ""
    summ = (
        f'<summary><span class="arrow">▶</span>'
        f'<span class="crepo">{esc(slug)}</span>'
        f'<span class="ccwe">{esc(repo)} · {esc(c["cwe"])} {esc(c.get("cwe_name") or "")}</span>'
        f'<span class="spacer"></span>'
        f'{pill(h_cl, "Claude")} {pill(h_cx, "Codex")}</summary>'
    )

    # links row
    links = [f'<a href="https://github.com/{repo}" {A}>github.com/{esc(repo)}</a>']
    if c.get("advisory_url"):
        links.append(f'<a href="{html.escape(c["advisory_url"])}" {A}>{esc(c.get("cve") or "advisory")}</a>')
    if c.get("fix_sha"):
        links.append(f'<a href="https://github.com/{repo}/commit/{c["fix_sha"]}" {A}>maintainer fix commit</a>')
    if not c.get("advisory_url"):
        links.append("<span>carried over from round one</span>")
    linkrow = f'<div class="reflinks" style="margin:0 0 6px">{" ".join(links)}</div>'

    note = f'<p class="cnote">{CNOTES[slug]}</p>' if slug in CNOTES else ""

    code_tabs = tab_group(
        [("m", "Maintainer"), ("c", "Claude"), ("x", "Codex")],
        [
            diff_panel("m", True,
                       f'the shipped fix · <b>+{ga} / -{gd}</b> lines <span class="vd gold">gold standard</span>',
                       gold, ""),
            diff_panel("c", False,
                       f'Claude Opus 4.8 · <b>+{ca} / -{cd}</b> lines {pill(aud_cl, "auditor")} {pill(h_cl, "human")}',
                       cl, empty_msg(slug, "claude", "Claude")),
            diff_panel("x", False,
                       f'Codex GPT-5.5 · <b>+{xa} / -{xd}</b> lines {pill(aud_cx, "auditor")} {pill(h_cx, "human")}',
                       cx, empty_msg(slug, "codex", "Codex")),
        ],
    )

    human_txt = (
        f"Claude's fix: {h_cl}. {hv['claude'].get('note') or ''}\n\n"
        f"Codex's fix: {h_cx}. {hv['codex'].get('note') or ''}"
    )
    cl_empty = "  · grading an empty submission" if not (cl and cl.strip()) else ""
    cx_empty = "  · grading an empty submission" if not (cx and cx.strip()) else ""
    review_tabs = tab_group(
        [("rc", "Codex reviews Claude"), ("rx", "Claude reviews Codex"), ("rh", "Human re-verification")],
        [
            f'<div data-panel="rc" class="active"><div class="meta">Codex GPT-5.5 grading Claude\'s fix against the gold standard{cl_empty} {pill(aud_cl, "verdict")}</div><div class="rev">{esc(rev_cl)}</div></div>',
            f'<div data-panel="rx"><div class="meta">Claude Opus 4.8 grading Codex\'s fix against the gold standard{cx_empty} {pill(aud_cx, "verdict")}</div><div class="rev">{esc(rev_cx)}</div></div>',
            f'<div data-panel="rh"><div class="meta">Our own read of both diffs {pill(h_cl, "Claude")} {pill(h_cx, "Codex")}</div><div class="rev">{esc(human_txt)}</div></div>',
        ],
    )

    return (
        f'<details class="case"{is_open}>{summ}<div class="cbody">'
        f"{linkrow}{axstrip(slug)}{note}"
        f'<div class="grouplab">The code</div>{code_tabs}'
        f'<div class="grouplab">The reviews</div>{review_tabs}'
        f"</div></details>"
    )


def gen_browser():
    cases = json.load(open(os.path.join(ROOT, "cases32.json")))
    cases.append({
        "slug": "scim-patch", "lang": "node", "cwe": "CWE-1321",
        "cwe_name": "Prototype Pollution", "repo": "thomaspoignant/scim-patch",
        "fix_sha": None, "advisory_url": None, "cve": None,
    })
    human = json.load(open(os.path.join(ROOT, "human-review.json")))
    # open case first, then alphabetical
    cases.sort(key=lambda c: (c["slug"] != OPEN_CASE, c["slug"]))
    blocks = [gen_case(c, human) for c in cases]
    legend = ('<div class="vlegend">summary pills show our human re-verification verdict per fix · '
              'inside each case, "auditor" = the AI cross-review, "human" = our read</div>')
    return f'{legend}<div class="cases">{"".join(blocks)}</div>'


# ----------------------------------------------------------------------------
# injection
# ----------------------------------------------------------------------------
def inject(s, name, payload):
    b, e = f"<!--{name}:BEGIN-->", f"<!--{name}:END-->"
    assert b in s and e in s, f"markers for {name} missing"
    pre, rest = s.split(b, 1)
    _, post = rest.split(e, 1)
    return f"{pre}{b}\n{payload}\n    {e}{post}"


def main():
    s = read(POST)

    # bootstrap: replace the old hand-made featured block with lead-in + markers
    if "<!--CASEBROWSER:BEGIN-->" not in s:
        m = re.search(r'\n    <div class="tabsc">.*?<p class="tcap">.*?</p>\s*\n    </div>\n', s, re.S)
        assert m, "featured block not found for bootstrap"
        lead = (
            "\n    <p>And because claims like these deserve receipts, here is the entire round: "
            "every vulnerability, the maintainer's real fix, both agents' attempts in full, and the "
            "reviews that judged them. One case is opened for you; the other thirty-two are a click away.</p>\n"
            "    <!--CASEBROWSER:BEGIN-->\n    <!--CASEBROWSER:END-->\n"
        )
        s = s[: m.start()] + lead + s[m.end():]

    s = inject(s, "V1MATRIX", gen_matrix())
    s = inject(s, "CASEBROWSER", gen_browser())

    for ch, nm in (("—", "em dash"), ("–", "en dash")):
        n = s.count(ch)
        assert n == 0, f"{n} {nm}(s) leaked into output"

    with open(POST, "w", encoding="utf-8") as f:
        f.write(s)
    print(f"post.html written: {len(s):,} chars ({len(s)/1024/1024:.2f} MB)")
    print("cases:", s.count('<details class="case"'), "| tab groups:", s.count("data-tabs"))


if __name__ == "__main__":
    sys.exit(main())
