# ai-footprint

Audits what local AI coding tools leave on your machine and what that exposes. It covers
Claude Code, Codex CLI, OpenCode and pi.

Each run writes an interactive dashboard (`ai-footprint-dashboard.html`). It is a
narrative of signals to review, not a list of rated findings: each signal is something the
audit observed, with its evidence, and whether it matters is your call. It states what an
attacker gets from each position:
holding a stolen token, running code as you, steering the model through text it reads, or
using another account on the same machine. Each tool gets its own page with the same story,
the fixes that close it, and plain answers to the usual questions (where are the logs, where
is the token, when does it expire, who can read what).

The dashboard is a dark console with tabs for Overview, Signals, Tools, Checklist,
Extensions, Machine, Method and Data. The overview shows each figure with a line saying
what it counts, then a grid of signals by attacker position and tool; selecting a cell
lists those signals. Every signal opens in a side panel (`?f=<id>` on any page) with its
evidence and fix steps, each with a copy button and the checks behind its badge. Tool pages
cover that tool's signals, plain answers to the usual questions, and its full inventory.
The checklist shows each check as review, clear or not checked. The filter box (`/`)
narrows whatever page is open, and "Data" shows the run's whole document as a tree.
"Keys" lists every stored key and login by provider, filterable by type and tool.

For each tool it reports:

- **Credentials**: where tokens and keys are stored, who can read them, expiry, scopes and
  JWT claims, and signature status.
- **Keys**: every API key, login and password the tools store, by provider: one row per
  distinct value with every place that holds it (matched by fingerprint), its start and
  last four characters for matching it in the provider's console, how long it keeps
  working, and who it belongs to when a file on disk records that (a token's email claim,
  Claude Code's account file). Otherwise the row says the owner is not recorded on disk.
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
uv run ai-footprint all --json run.json    # also write the data the dashboard shows
uv run ai-footprint all --html report.html # also write the static report (no scripts)
uv run ai-footprint all --doctor           # each check: review, clear or not checked
uv run ai-footprint --validate             # verify probes, fix commands, tool claims, CLI options
uv run ai-footprint claude --live          # opt-in network checks (see below)
```

Tool names are `claude`, `codex`, `opencode` and `pi`. Naming a tool that is not installed is an
error that lists what is installed. Without a terminal (scripts, CI, agents) and without
names, every installed tool is audited.

`--json` writes the same document the dashboard embeds and renders: the full audit, the
checklist, and every sentence and table derived from them (`views`). Scripts and agents read
exactly what a person sees.

`--html` also writes the static report: the same narrative as pages switched with CSS, with
no JavaScript at all. Both outputs are built from the same run and share every figure.

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
- **Not checked is not clear.** Each check declares the input it reads (a setting key, a
  Keychain credential, a trust list, another local account). When that input is not recorded
  for a tool and nothing was found, the check is "not checked", with the reason, never
  "clear". A check that finds something is always reported.
- **Figures are recounted.** Every number on the dashboard and in the report (tiles, the
  signals grid, the disk chart, checklist counts, the commands summary, counts in the
  headline) is computed once in `figures.py` with a sentence saying exactly what it counts.
  `--validate` recounts each one from the run's JSON with separate code
  (`figurecheck.py`) and fails on any mismatch. Sizes never add a folder and a folder inside
  it; a secret count added across tools says it is distinct only within each tool. The key
  list is rebuilt from the raw credentials the same way: every stored credential is one
  row, every location is real, and an owner appears only if that key's own data records it
  at the stated source.

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
  claims, a 16-character SHA-256 fingerprint and, for values of 20 or more characters that
  are not JWTs, the last four characters. Tests enforce that no secret appears in
  the dashboard, JSON or terminal output.
- **Offline by default.** `--live` adds two checks:
  - one read-only call to Anthropic's OAuth profile endpoint (the token goes only to its
    issuer);
  - OpenAI JWT signature verification against the issuer's public JWKS (no token leaves
    the machine).
- **Self-contained dashboard.** The dashboard is one file with no external resources. Its
  CSP is `default-src 'none'` and allows exactly one inline script and one inline style,
  each pinned by SHA-256 hash, so it cannot make network requests. Collected strings (MCP
  names, instruction text) are embedded as JSON with `<`, `>` and `&` escaped, and inserted
  into the page as text, never parsed as markup. A test fails if the script uses
  `innerHTML`, `eval`, `fetch` or a similar sink.

## Development

`scripts/layout_check.py ai-footprint-dashboard.html --shots DIR` renders every page in
headless Chrome at 1280 px and 500 px. It fails on script errors, a page that scrolls
sideways, tables that scroll sideways at desktop width, words split mid-word and raw ISO
dates. It also fails when any value in the run's data is missing from every page except
"Run data", so nothing the audit collects is left out, and when a tile or signals-grid
cell on screen differs from the figure in the data. Given the static report instead, it
checks that report's tables and words. It saves a screenshot per page. The
`dashboard-reviewer` agent in `.claude/agents/` runs the validators and that script, then
reads every screenshot and reports anything inconsistent.

```sh
uv sync
uv run pytest -q
ruff check && ruff format --check && ty check src tests
prek install   # runs the same checks before each commit
```
