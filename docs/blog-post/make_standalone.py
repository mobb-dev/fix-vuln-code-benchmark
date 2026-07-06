#!/usr/bin/env python3
"""Wrap post.html (the artifact source) into a complete standalone HTML page.

post.html is written to be wrapped by the claude.ai artifact publisher: it starts
at <title> and relies on the publisher for the doctype/head/body skeleton and a
minimal reset. This script produces blog-post/plausible-not-fixed.html: the SAME
content, byte for byte, inside a proper HTML5 skeleton whose reset replicates the
artifact wrapper exactly (fetched from the published page 2026-07-06), so the
standalone renders identically. The claude.ai frame-runtime script is deliberately
NOT replicated (platform plumbing, not rendering).

Re-run after any change to post.html:  python3 make_standalone.py
"""
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "post.html"
OUT = HERE / "plausible-not-fixed.html"

content = SRC.read_text(encoding="utf-8")

m = re.match(r"<title>(.*?)</title>\n?", content)
if not m:
    raise SystemExit("post.html no longer starts with <title> — adjust this script")
title = m.group(1)
body = content[m.end():]

DESCRIPTION = (
    "A field report on what it actually takes to measure whether an AI can fix a "
    "vulnerability, and why almost every number you've seen is more flattering than it should be."
)

# Reset copied verbatim from the artifact publisher's wrapper so rendering matches.
RESET = (
    ":root{color-scheme:light}"
    "body{margin:0;padding:0;font:14px -apple-system,BlinkMacSystemFont,sans-serif;"
    "background:#faf9f5;color:#141413}"
    "img{max-width:100%}"
)

FAVICON = (
    "data:image/svg+xml,"
    "<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22>"
    "<text y=%22.9em%22 font-size=%2290%22>&#128737;&#65039;</text></svg>"
)

page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<meta name="description" content="{DESCRIPTION}">
<link rel="icon" href="{FAVICON}">
<style>{RESET}</style>
</head>
<body>
{body}
</body>
</html>
"""

OUT.write_text(page, encoding="utf-8")

# sanity: the region between <body>\n and \n</body> must be byte-identical to post.html minus its title line
written = OUT.read_text(encoding="utf-8")
inner = written.split("<body>\n", 1)[1].rsplit("\n</body>", 1)[0]
assert inner == body, "content drifted while wrapping"
print(f"written {OUT.name}: {OUT.stat().st_size:,} bytes (source {SRC.stat().st_size:,})")
print(f"title: {title}")
print("content region byte-identical to post.html: OK")
