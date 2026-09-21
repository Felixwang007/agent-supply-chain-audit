#!/usr/bin/env bash
# audit.sh — 30-second pre-install audit for a Python/npm repo you are about to run.
#
# Usage:
#   bash audit.sh <git-url-or-local-path>
#
# It does NOT install or execute anything from the target. It clones (if a URL)
# into a temp dir, greps for the patterns that matter, prints a verdict, and
# deletes the clone. Read the "hits" yourself — a hit is a question, not proof.
set -uo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "usage: bash audit.sh <git-url-or-local-path>" >&2
  exit 2
fi

CLEANUP=""
if [ -d "$TARGET" ]; then
  DIR="$TARGET"
else
  DIR="$(mktemp -d 2>/dev/null || mktemp -d -t audit)"
  CLEANUP="$DIR"
  git clone --depth 1 -q "$TARGET" "$DIR/repo" 2>/dev/null || { echo "clone failed"; exit 1; }
  DIR="$DIR/repo"
fi

SCORE=0
hit() { printf '  [!] %s\n' "$1"; SCORE=$((SCORE + 1)); }

echo "== audited tree: $DIR"
echo "== files: $(find "$DIR" -type f -not -path '*/.git/*' | wc -l)"

echo
echo "== 1. hardcoded network endpoints =="
# A literal IPv4 address in source is a red flag; domain names in a CLI tool are usually fine.
grep -rnE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?' \
  --include='*.py' --include='*.js' --include='*.mjs' --include='*.ts' --include='*.sh' \
  "$DIR" 2>/dev/null | grep -v '/test' | head -20 || echo "  (none)"
grep -rnE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' -r "$DIR" 2>/dev/null | head -5 | grep -q . && hit "hardcoded IP endpoint(s) found"

echo
echo "== 2. download-then-execute chain =="
grep -rnE '(urllib\.request|urlopen|requests\.get|httpx\.|fetch\()' \
  --include='*.py' --include='*.js' --include='*.mjs' "$DIR" 2>/dev/null | grep -v '/test' | head -20 || echo "  (none)"
grep -rnE 'exec\(|eval\(|compile\(|__import__\(|importlib\.import_module|pickle\.loads|marshal\.loads|b64decode|fromhex' \
  --include='*.py' --include='*.js' --include='*.mjs' "$DIR" 2>/dev/null | grep -v '/test' | head -25 || echo "  (none)"
if grep -rqE 'exec\(compile|exec\(zlib|exec\([a-z_]+\.decompress|__import__\(' --include='*.py' "$DIR" 2>/dev/null; then
  hit "dynamic execution of non-literal code"
fi

echo
echo "== 3. import-time side effects (the part nobody reads) =="
for f in cli.py main.py app.py __main__.py tokentab/__init__.py "$(basename "${DIR}")/__init__.py"; do
  [ -f "$DIR/$f" ] || continue
  if grep -nE '^[A-Za-z_][A-Za-z0-9_.]*\.[a-z_]+\(|^[a-z_]+\(' "$DIR/$f" 2>/dev/null | grep -vE '^#' | head -5 | grep -q .; then
    echo "  --- $f (top-level calls):"
    grep -nE '^[A-Za-z_][A-Za-z0-9_.]*\.[a-z_]+\(|^[a-z_]+\(' "$DIR/$f" | head -5 | sed 's/^/      /'
    hit "$f calls functions at import time — check each one"
  fi
done

echo
echo "== 4. obfuscation smell (big int arrays + xor lambdas) =="
if grep -rqE 'lambda [a-z],[a-z]: ?bytes\(|bytes\(v ?\^ ?k' --include='*.py' "$DIR" 2>/dev/null; then
  hit "xor-decode lambda present (string/array obfuscation)"
fi
BIG=$(grep -rlE '\[[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+, ?[0-9]+' --include='*.py' "$DIR" 2>/dev/null | wc -l)
[ "$BIG" -gt 0 ] && hit "$BIG python file(s) contain large int-array literals"

echo
echo "== 5. declared vs real distribution =="
PKG=$(grep -m1 -E '^name ?=' "$DIR/pyproject.toml" 2>/dev/null | sed -E 's/.*"(.*)".*/\1/;s/.*= ?//;s/ //g')
[ -n "${PKG:-}" ] && printf '  package name: %s\n' "$PKG"
if [ -f "$DIR/package.json" ]; then
  node -e 'const p=require(process.argv[1]);console.log("  pkg:",p.name,"| install hooks:",JSON.stringify({preinstall:p.scripts&&p.scripts.preinstall,postinstall:p.scripts&&p.scripts.postinstall,prepare:p.scripts&&p.scripts.prepare}))' "$PWD/$DIR/package.json" 2>/dev/null || true
fi

echo
echo "== verdict =="
if [ "$SCORE" -eq 0 ]; then
  echo "  no automatic red flags — still read the entry point and the install hooks before running."
else
  echo "  $SCORE automatic red flag(s). Do not run it until each hit is explained by the author's intent."
fi
echo "  This script only greps. It cannot see runtime behaviour, fetched stage-2 code, or memory-only payloads."

[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"
exit 0
