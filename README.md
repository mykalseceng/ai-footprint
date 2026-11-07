# ai-footprint

Audits what Claude Code, Codex CLI, OpenCode, pi and T3 Code leave on your Mac and what that exposes:
stored credentials and who can read them, sessions and logs, secrets in history, instruction
files, MCP servers and hooks that run automatically, and where each tool connects. Each run
writes a single-file HTML dashboard.

## Usage

```sh
uv run ai-footprint --list                 # supported tools, which are installed, where
uv run ai-footprint                        # audit installed tools (asks which in a terminal)
uv run ai-footprint all                    # audit every installed tool without asking
uv run ai-footprint codex opencode         # audit only these
uv run ai-footprint all --json run.json    # also write the data the dashboard shows
uv run ai-footprint all --html report.html # also write the static report (no scripts)
uv run ai-footprint all --doctor           # each check: review, clear or not checked
uv run ai-footprint --validate             # verify probes, fix commands, tool claims, CLI options
uv run ai-footprint t3code --profile       # documented features here, and what the profile misses
uv run ai-footprint claude --live          # opt-in network checks
uv run ai-footprint all --capture          # record where each tool connects when started (sudo)
uv run ai-footprint all --network ai-footprint-capture.json   # show that capture again later
```

Tool names are `claude`, `codex`, `opencode`, `pi` and `t3code`. `--doctor` and `--validate` exit 1
when a check fails.

`--capture` shows which hosts each tool reaches on its own. It runs `sudo tcpdump` on all
interfaces, starts each tool idle with no prompt for 60 seconds, and names every host its
processes reached from the TLS server name, HTTP Host header or DNS answer in the capture.

## Harnesses

Each tool is a package under `src/ai_footprint/harnesses/<tool>/`. Its `profile.toml` holds
everything that is data: folders and the variables that move them, files and what they hold,
hosts, binary markers, approval signals, fix commands and the documented feature inventory.
`collector.py` reads what needs code. The registry finds packages on its own, the checks in
`checks/` and the outputs in `reporting/` never name a tool, and `tests/test_architecture.py`
fails if they do.

`--profile` maps a tool's documented features onto this machine and lists paths, config keys
and variables its profile does not cover yet. The `harness-profiler` agent
(`.claude/agents/harness-profiler.md`) researches those in the official docs, writes what it
confirms into the profile, and onboards new tools the same way.

## Safety

The audit is read-only and offline: fixes are printed, not applied, and every external
command comes from a fixed registry of absolute system paths, with tool binaries limited to
`--version` and `--help`. Secrets are reduced in memory to metadata (prefix, length, expiry,
fingerprint, last four characters) and never written out. The dashboard's CSP blocks all
network requests. Two flags opt out: `--live` calls Anthropic's profile endpoint and fetches
OpenAI's public JWKS, and `--capture` launches each tool, which then connects and writes its
own state as usual.

## Development

```sh
uv sync
uv run pytest -q
uv run ruff check && uv run ruff format --check && uv run ty check src tests
uv run scripts/layout_check.py ai-footprint-dashboard.html --shots DIR   # layout and data coverage
prek install
```
