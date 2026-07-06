#!/usr/bin/env python3
"""Write FINDING.txt per project with vulnerability TYPE and precise LOCATIONS: file + line range +
enclosing function for every source place the vulnerability is present. Locations are read from the
maintainer fix's diff hunks (the authoritative 'where'); only locations are recorded - never the changed code."""
import json, os, subprocess, re
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cands = {c["fix_sha"]: c for c in json.load(open(ROOT + "/candidates-100.json"))}
led = json.load(open(ROOT + "/calib-ledger.json"))
slugs = [s for s, d in led.items() if d["verdict"] == "VERIFIED"]
def recipe(c): return dict(l.strip().split("=", 1) for l in open(f"{ROOT}/cases/{c}/recipe") if "=" in l and not l.startswith("#"))
def gh(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    try: return json.loads(r.stdout) if r.returncode == 0 else {}
    except Exception: return {}
def is_src(eco, f):
    fl = f.lower()
    if eco == "go":    return f.endswith(".go") and not fl.endswith("_test.go")
    if eco == "pip":   return f.endswith(".py") and "test" not in fl
    if eco == "maven": return f.endswith(".java") and "/src/main/" in f
    if eco == "npm":   return (f.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")) and not f.endswith(".d.ts")
                               and ".test." not in fl and ".spec." not in fl and "/test" not in fl and "/dist/" not in f)
    return False
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@(.*)")
# Canonical CWE names — fallback when a recipe's CWE_NAME is missing or left as the bare id.
CWE_NAMES = {
    "CWE-22": "Path Traversal", "CWE-78": "OS Command Injection", "CWE-79": "Cross-site Scripting",
    "CWE-94": "Code Injection", "CWE-185": "Incorrect Regular Expression", "CWE-200": "Information Exposure",
    "CWE-285": "Improper Authorization", "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path or Channel",
    "CWE-295": "Improper Certificate Validation", "CWE-304": "Missing Critical Step in Authentication",
    "CWE-306": "Missing Authentication for Critical Function", "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption", "CWE-617": "Reachable Assertion",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-789": "Memory Allocation with Excessive Size Value", "CWE-862": "Missing Authorization",
    "CWE-915": "Improperly Controlled Modification of Object Attributes",
    "CWE-918": "Server-Side Request Forgery", "CWE-1321": "Prototype Pollution",
}

for slug in slugs:
    r = recipe(slug); fix = r["FIX_COMMIT"]; c = cands.get(fix, {}); eco = c.get("ecosystem", "")
    repo = r["REPO_URL"].replace("https://github.com/", "").replace(".git", "")
    cwe = r["CWE_ID"]; name = r.get("CWE_NAME", "").strip('"')
    if not name or name == cwe: name = CWE_NAMES.get(cwe, "")   # fall back to canonical name
    type_line = f"{name} ({cwe})" if name else cwe              # avoid the redundant "CWE-x (CWE-x)"
    commit = gh(f"/repos/{repo}/commits/{fix}")
    locs = {}
    for f in commit.get("files", []):
        if not is_src(eco, f["filename"]): continue
        hs = []
        for ln in f.get("patch", "").split("\n"):
            m = HUNK.match(ln)
            if m:
                a = int(m.group(1)); length = int(m.group(2) or 1); ctx = m.group(3).strip()
                if a == 0: continue   # @@ -0,0 +... @@ = file added by the fix; not present in the vulnerable code
                rng = str(a) if length <= 1 else f"{a}-{a + length - 1}"
                hs.append((rng, ctx))
        if hs: locs[f["filename"]] = hs
        elif "patch" not in f: locs[f["filename"]] = [("(file too large for line detail)", "")]
    txt = f"Project: {repo}\nVulnerability type: {type_line}\n\nWhere the vulnerability is (file -> vulnerable line ranges, with enclosing function):\n"
    if not locs:
        txt += f"  {r['VULN_FILE']}  (precise lines unavailable)\n"
    for fn, hs in locs.items():
        txt += f"\n  {fn}\n"
        for rng, ctx in hs:
            txt += f"    - lines {rng}" + (f"   in: {ctx}" if ctx else "") + "\n"
    open(f"{ROOT}/checkouts/{slug}/FINDING.txt", "w").write(txt)
    print(f"{slug:26} {cwe:9} {len(locs)} file(s), {sum(len(h) for h in locs.values())} location(s)")
print(f"\nwrote {len(slugs)} FINDING.txt with precise locations")
