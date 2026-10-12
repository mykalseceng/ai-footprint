# ai-footprint

Audits what local AI coding tools leave on your machine and what that exposes. It covers
Claude Code, Codex CLI and OpenCode.

The report is a narrative, not a list of rated findings. It states what an attacker gets
from each position: holding a stolen token, running code as you, steering the model through
text it reads, or using another account on the same machine. Each tool gets its own page
with the same story, the fixes that close it, and plain answers to the usual questions
(where are the logs, where is the token, when does it expire, who can read what).

For each tool it reports:

- **Credentials**: where tokens and keys are stored, who can read them, expiry, scopes and
  JWT claims, and signature status.
- **Sessions, history, logs and caches**: size, dates, file counts, and effective
  permissions, checked through every parent folder.
- **Instruction files** (`CLAUDE.md`, `AGENTS.md`, auto-memory `MEMORY.md`, agent and
  command definitions): flags hidden Unicode,
  authority/attestation claims, override phrasing, external URLs, download-and-run
  patterns, and embedded secrets.
- **Skills, plugins, MCP servers, hooks, native hosts**: what runs automatically, which
  autostart commands point at missing files, and what each item says it does in its own
  manifest or SKILL.md (two sentences, never paraphrased). A separate page lists them once
  across all tools, with the tools that load each one.
- **Network**: endpoints and signature traits found in the installed binary, hosts mined
  from local logs, and live sockets.
- **Secrets at rest**: a full scan of every byte of the tool's data, run in parallel.
  Only kinds, counts, last-4 characters and file paths are kept.
- **Trusted-access program evidence**: Anthropic CVP and OpenAI TAC.
- **Host issues**: other local accounts, writable PATH folders ahead of `/usr/bin`, tool
  binaries in writable folders, the same credentials stored in several tools, and skill
  folders shared across tools.
- **What an agent inherits**: SSH keys (and whether they have a passphrase), ssh-agent,
  cloud and registry logins, and secret-looking environment variables, by presence only.
- **What can drive the computer**: browser native-messaging bridges, computer-use helpers,
  Claude Desktop MCP servers, and macOS privacy grants when the terminal can read them.
- **Copies elsewhere**: Time Machine coverage, provider-side training and cloud tasks.
- **Unattended work**: orphaned MCP servers, long-running agent processes, login items.
- **Account evidence on disk**: cached data-use settings, whether logout revokes the token
  (checked in the binary), last sign-in method, MFA, last refresh, paired devices, and
  auth events in local logs.
- **Other AI tools** (Claude Desktop, ChatGPT, Cursor, Gemini CLI, Copilot, Windsurf,
  Continue, aider): size, MCP servers, and permissions.

## Usage

```sh
uv run ai-footprint --list                 # supported tools, which are installed, where
uv run ai-footprint                        # audit installed tools (asks which in a terminal)
uv run ai-footprint all                    # audit every installed tool without asking
uv run ai-footprint codex opencode         # audit only these
uv run ai-footprint all --json report.json # also write JSON
uv run ai-footprint all --doctor           # each check exposed or clear, with validated fixes
uv run ai-footprint --validate             # verify probes, fix commands, tool claims, CLI options
uv run ai-footprint claude --live          # opt-in network checks (see below)
```

Tool names are `claude`, `codex` and `opencode`. Naming a tool that is not installed is an
error that lists what is installed. Without a terminal (scripts, CI, agents) and without
names, every installed tool is audited.

`--doctor` and `--validate` exit with status 1 when any check fails, so they can gate CI or
run from a login hook. `--validate` also checks the command line itself: every example in
`--help` must parse and select real tools, every option needs help text, documented
defaults must match, and modes must refuse to combine.

## Observed, not inferred

The report states what is on disk, what the installed binary contains, and what the audit
itself did. It does not guess at tool behaviour:

- **Claim registry.** Every endpoint, signature trait, config key, log marker and behaviour
  marker a collector knows about is registered as a claim with a string that must appear in
  the installed binary. The audit drops a claim the binary does not contain, and
  `--validate` fails on it, so a constant that is wrong or that a newer version removed never
  reaches the report.
- **Settings.** A setting that is not in the config file is shown as "not set", and only when
  the binary knows the key. Defaults are not assumed.
- **Tokens.** Scopes and claims are listed as recorded. No meaning is attached to a scope,
  and nothing is said about what a token cannot do.
- **Logout.** Whether `/logout` revokes a token is reported from markers in the binary; when
  they are absent the report says it cannot tell.

## Safety properties

- **Read-only.** The audit never changes your system. Fixes are printed, not applied.
- **Probe registry.** Every external command is declared in `system.PROBES` with an
  absolute path and run with a fixed `PATH`. On macOS each probe binary must pass an
  Apple code-signature check first. Anything unregistered is refused. Tool binaries may
  only be run with `--version` or `<subcommand> --help`.
- **Validated fixes.** Every fix command is checked before it is shown:
  - it passes `sh -n`;
  - every program it calls resolves;
  - every `chmod` or `cd` target exists;
  - every subcommand appears in the installed tool's `--help`;
  - every recommended config key is present in the installed binary.
- **No secret values leave memory.** Tokens become metadata: prefix, length, expiry,
  claims, and a 16-character SHA-256 fingerprint. Tests enforce that no secret appears in
  the HTML, JSON or terminal output.
- **Offline by default.** `--live` adds two checks:
  - one read-only call to Anthropic's OAuth profile endpoint (the token goes only to its
    issuer);
  - OpenAI JWT signature verification against the issuer's public JWKS (no token leaves
    the machine).
- **Static report.** The HTML has no scripts and no external resources, and ships a CSP
  of `default-src 'none'`. All collected strings are escaped.

## Development

`scripts/layout_check.py ai-footprint-report.html --shots DIR` renders every page in headless
Chrome at 1280 px and 500 px, fails on tables that scroll sideways or words split mid-word,
and saves a screenshot per page. The `report-reviewer` agent in `.claude/agents/` runs the
validators and that script, then reads every screenshot and reports anything inconsistent.

```sh
uv sync
uv run pytest -q
ruff check && ruff format --check && ty check src tests
prek install   # runs the same checks before each commit
```
