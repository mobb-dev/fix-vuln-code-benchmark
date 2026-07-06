#!/usr/bin/env bash
# Clone each calibrated case's project at the VULNERABLE version (parent of the fix commit), then flatten
# git history to a single commit so the fix is not discoverable. Working tree = the vulnerable code.
# Output: <repo>/checkouts/<slug>/
set -uo pipefail
B=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="$B/checkouts"; mkdir -p "$OUT"
SLUGS=$(python3 -c "import json;l=json.load(open('$B/calib-ledger.json'));print(' '.join(s for s,d in l.items() if d['verdict']=='VERIFIED'))")
ok=0; fail=0
for slug in $SLUGS; do
  src=$(grep '^REPO_URL=' "$B/cases/$slug/recipe" | cut -d= -f2-)
  fix=$(grep '^FIX_COMMIT=' "$B/cases/$slug/recipe" | cut -d= -f2-)
  dst="$OUT/$slug"
  [ -d "$dst" ] && { echo "skip $slug (exists)"; continue; }
  echo ">>> $slug  ($src @ ${fix:0:10}^)"
  if ! git clone -q --filter=blob:none --no-checkout "$src" "$dst" 2>/dev/null; then
    echo "   CLONE FAILED"; fail=$((fail+1)); rm -rf "$dst"; continue
  fi
  (
    cd "$dst" || exit 1
    parent=$(git rev-parse "${fix}^" 2>/dev/null)
    if [ -z "$parent" ]; then git fetch -q --filter=blob:none origin "$fix" 2>/dev/null || true; parent=$(git rev-parse "${fix}^" 2>/dev/null); fi
    [ -z "$parent" ] && { echo "   CANNOT RESOLVE PARENT"; exit 2; }
    git -c advice.detachedHead=false checkout -q "$parent" 2>/dev/null || { echo "   CHECKOUT FAILED"; exit 3; }
    rm -rf .git && git init -q && git add -A && git -c user.email=bench@local -c user.name=bench commit -q -m "vulnerable baseline ($slug @ ${parent:0:10})"
    echo "   ok: ${parent:0:10}  ($(git ls-files | wc -l | tr -d ' ') files)"
  )
  case $? in 0) ok=$((ok+1));; *) fail=$((fail+1)); rm -rf "$dst";; esac
done
echo "=== cloned $ok, failed $fail into $OUT ==="
du -sh "$OUT" 2>/dev/null
