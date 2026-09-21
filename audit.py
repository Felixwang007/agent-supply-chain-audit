#!/usr/bin/env python3
"""audit.py — cross-platform pre-install audit (no installation, no execution of the target).

    python audit.py <git-url-or-local-path>

Same checks as audit.sh but written for Windows/macOS/Linux where bash pipelines
are awkward. Prints a verdict and a list of hits to read by hand.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

NET_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")
# bare IPv4 without scheme, e.g. "HOST": "172.233.51.81" — version strings like 1.2.3.4 are rare in source
BARE_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")


def valid_ipv4(token: str) -> bool:
    """Reject 414.336.75.75-style false positives (each octet must be <= 255)."""
    host = token.split(":")[0]
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
EXEC_RE = re.compile(
    r"\b(exec|eval|compile|__import__|importlib\.import_module|pickle\.loads|"
    r"marshal\.loads|b64decode|fromhex|Function)\s*\("
)
FETCH_RE = re.compile(r"\b(urllib\.request|urlopen|requests\.get|httpx\.|fetch\(|http\.get)\b")
XOR_RE = re.compile(r"bytes\(v ?\^ ?k|lambda [A-Za-z_], ?[A-Za-z_]: ?bytes\(")
ARRAY_RE = re.compile(r"\[\s*\d{1,3}(?:,\s*\d{1,3}){11,}\s*\]")
IMPORTTIME_RE = re.compile(r"^[A-Za-z_][\w.]*\.[a-z_]+\(")
# dynamic dispatch hidden behind decoded names: getattr(mod, <decoded>)(...), __import__(<decoded>)
DYNDISPATCH_RE = re.compile(r"getattr\(|__import__\((?![^)]*[\"'])" )

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "test", "tests"}


def iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in {".py", ".js", ".mjs", ".ts", ".sh", ".ps1"} or p.name == "package.json":
            yield p


def resolve(target: str) -> tuple[Path, str | None]:
    p = Path(target)
    if p.is_dir():
        return p, None
    tmp = Path(tempfile.mkdtemp(prefix="audit-"))
    subprocess.run(["git", "clone", "--depth", "1", "-q", target, str(tmp / "repo")], check=True)
    return tmp / "repo", str(tmp)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    try:
        root, tmp = resolve(sys.argv[1])
    except subprocess.CalledProcessError:
        print("clone failed")
        return 1

    hits: list[str] = []
    print(f"== audited tree: {root}")
    files = list(iter_files(root))
    print(f"== source files scanned: {len(files)}\n")

    sections = {
        "1. hardcoded IP endpoints": [],
        "2. fetch -> dynamic execution": [],
        "3. obfuscation smell": [],
    }

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = f.relative_to(root)
        for i, line in enumerate(text.splitlines(), 1):
            if NET_RE.search(line) and "127.0.0.1" not in line and "0.0.0.0" not in line:
                sections["1. hardcoded IP endpoints"].append(f"{rel}:{i}: {line.strip()[:110]}")
            bare = BARE_IP_RE.search(line)
            if (bare and valid_ipv4(bare.group(0)) and "127.0.0.1" not in line
                    and "0.0.0.0" not in line and not line.lstrip().startswith("#")):
                sections["1. hardcoded IP endpoints"].append(
                    f"{rel}:{i} (bare IP {bare.group(0)}): {line.strip()[:110]}"
                )
            if (FETCH_RE.search(line) and EXEC_RE.search(line)) or (
                EXEC_RE.search(line) and ("decompress" in line or "compile" in line)
            ):
                sections["2. fetch -> dynamic execution"].append(f"{rel}:{i}: {line.strip()[:110]}")
            if XOR_RE.search(line) or len(ARRAY_RE.findall(line)) >= 1:
                sections["3. obfuscation smell"].append(f"{rel}:{i}: {line.strip()[:110]}")
            if DYNDISPATCH_RE.search(line):
                sections["3. obfuscation smell"].append(f"{rel}:{i} (dynamic dispatch): {line.strip()[:110]}")

        if f.name in {"cli.py", "main.py", "app.py", "__main__.py", "__init__.py"}:
            for i, line in enumerate(text.splitlines(), 1):
                if IMPORTTIME_RE.match(line) and not line.startswith(("if", "def", "class")):
                    hits.append(f"{rel}:{i} runs at import time -> {line.strip()[:90]}")

    for title, rows in sections.items():
        print(f"== {title} ==")
        if not rows:
            print("  (none)\n")
            continue
        for r in rows[:20]:
            print("  ", r)
        if len(rows) > 20:
            print(f"   ... +{len(rows) - 20} more")
        hits.append(f"{title}: {len(rows)} line(s)")
        print()

    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {})
            hooks = {k: v for k, v in scripts.items() if k in {"preinstall", "install", "postinstall", "prepare"}}
            print("== npm install hooks ==")
            print("  ", hooks or "(none)")
            if hooks:
                hits.append("npm install-time hooks present")
            print()
        except (OSError, json.JSONDecodeError):
            pass

    print("== verdict ==")
    if not hits:
        print("  no automatic red flags — still read the entry point and install hooks before running.")
    else:
        for h in hits:
            print(f"  [!] {h}")
        print("  Read every hit before running. A hit is a question, not proof.")
    print("  A static grep cannot see runtime behaviour, fetched stage-2 code, or memory-only payloads.")

    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
