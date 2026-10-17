"""OpenAI Codex CLI (``codex``) footprint collector."""

import json
import re
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

from ai_footprint import extensions, instructions, live
from ai_footprint.collectors.common import (
    ArtifactSpec,
    Claim,
    Context,
    binary_info,
    binary_path,
    confirmed_settings,
    describe_all,
    endpoints,
    fingerprint_items,
    load_json,
    load_toml,
    presence,
    shell_shortcuts,
    value_or_unset,
)
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.host import processes
from ai_footprint.model import (
    BinaryInfo,
    Category,
    Credential,
    Endpoint,
    Extension,
    ProcessInfo,
    ProgramStatus,
    Setting,
    StoreKind,
    ToolPresence,
    ToolReport,
)
from ai_footprint.rules import THREADS_WITHOUT_APPROVAL
from ai_footprint.secrets import scan_paths
from ai_footprint.surface import plural, when
from ai_footprint.tokens import inspect_token, iso_time, verify_rs256

NAME = "codex"
DISPLAY = "Codex CLI"
C = Category

ARTIFACTS = (
    ArtifactSpec(
        "Credentials",
        "auth.json",
        C.CREDENTIAL,
        "ChatGPT OAuth JWTs and refresh token, or an API key, in plaintext",
    ),
    ArtifactSpec(
        "Config",
        "config.toml",
        C.CONFIG,
        "Approval policy, sandbox, MCP servers, plugins, trusted projects",
    ),
    ArtifactSpec("Hooks", "hooks.json", C.EXTENSION, "Commands run on tool events"),
    ArtifactSpec("Command rules", "rules", C.CONFIG, "Pre-approved command prefixes"),
    ArtifactSpec("Global instructions", "AGENTS.md", C.INSTRUCTIONS, "Loaded into every session"),
    ArtifactSpec(
        "Global override", "AGENTS.override.md", C.INSTRUCTIONS, "Replaces AGENTS.md when present"
    ),
    ArtifactSpec(
        "Sessions", "sessions", C.SESSION, "Rollout files: full conversations and tool output"
    ),
    ArtifactSpec("Archived sessions", "archived_sessions", C.SESSION, "Older rollouts"),
    ArtifactSpec("Prompt history", "history.jsonl", C.SESSION, "Every prompt typed"),
    ArtifactSpec("Thread history DB", "thread_history_1.sqlite", C.SESSION, "Thread contents"),
    ArtifactSpec("State DB", "state_5.sqlite", C.SESSION, "Threads, projects, app state"),
    ArtifactSpec("Memories DB", "memories_1.sqlite", C.SESSION, "Saved memories"),
    ArtifactSpec("Memories", "memories", C.SESSION, "Memory files"),
    ArtifactSpec("Goals DB", "goals_1.sqlite", C.SESSION, "Goals"),
    ArtifactSpec("Queue DB", "queue_1.sqlite", C.SESSION, "Queued work"),
    ArtifactSpec("Browser sessions", "browser", C.SESSION, "Browser session data"),
    ArtifactSpec("Dictation history", "dictation-history", C.SESSION, "Dictation history"),
    ArtifactSpec(
        "Transcription history", "transcription-history.jsonl", C.SESSION, "Voice transcriptions"
    ),
    ArtifactSpec("Session index", "session_index.jsonl", C.SESSION, "Session titles and paths"),
    ArtifactSpec("Attachments", "attachments", C.SESSION, "Files attached to prompts"),
    ArtifactSpec("Logs DB", "logs_2.sqlite", C.LOG, "Structured client logs"),
    ArtifactSpec("Logs", "log", C.LOG, "Login and TUI logs"),
    ArtifactSpec("Shell snapshots", "shell_snapshots", C.LOG, "Your shell environment"),
    ArtifactSpec("Global state", ".codex-global-state.json", C.CONFIG, "Desktop/app state"),
    ArtifactSpec("Installation ID", "installation_id", C.CONFIG, "Stable per-install identifier"),
    ArtifactSpec("Skills", "skills", C.EXTENSION, "Codex skills"),
    ArtifactSpec("Plugins", "plugins", C.EXTENSION, "Bundled and curated plugins"),
    ArtifactSpec("Computer use", "computer-use", C.EXTENSION, "Screen and input control helper"),
    ArtifactSpec("Cache", "cache", C.CACHE, "Downloaded assets"),
)

ENDPOINTS = {
    "chatgpt.com": "Codex responses API on your ChatGPT plan (backend-api)",
    "auth.openai.com": "OAuth login and token refresh",
    "api.openai.com": "OpenAI API (API-key mode)",
}

FINGERPRINT = (
    ("Originator header", "originator: codex_cli_rs", "codex_cli_rs"),
    ("User-Agent", "codex_cli_rs/{version} (…)", "codex_cli_rs"),
    ("Responses endpoint", "https://chatgpt.com/backend-api/codex/…", "chatgpt.com/backend-api"),
    ("Auth endpoint", "https://auth.openai.com (token refresh)", "auth.openai.com"),
    (
        "Credential store option",
        "cli_auth_credentials_store = file | keyring | auto",
        "cli_auth_credentials_store",
    ),
    (
        "Instruction files",
        "AGENTS.md, AGENTS.override.md, project_doc_fallback_filenames",
        "AGENTS.override.md",
    ),
)

SETTING_KEYS = (
    "approval_policy",
    "sandbox_mode",
    "notify",
    "cli_auth_credentials_store",
    "persistence",
    "trust_level",
    "project_doc_fallback_filenames",
    "daemon_auto_start",
)
DAEMON_MARKERS = ("managed-daemon", "pid-update-loop", "daemon stop")
REVOKE_MARKERS = ("auth/revoke.rs", "failed to revoke auth tokens during logout")
REMOTE_REVOKE_MARKER = "remoteControl/client/revoke"
LOG_MARKERS = {
    "Your access token could not be refreshed": "token refresh failed",
    "invalid_grant": "refresh rejected (invalid_grant)",
}
NEVER = "never"
BYPASS_FLAG = "--dangerously-bypass-approvals-and-sandbox"
CLAIMS: tuple[Claim, ...] = (
    *(Claim(f"endpoint {host}", host) for host in ENDPOINTS),
    *(Claim(f"signature: {label}", marker) for label, _value, marker in FINGERPRINT),
    *(Claim(f"setting {key}", key) for key in SETTING_KEYS),
    *(Claim("logout revokes tokens", marker) for marker in REVOKE_MARKERS),
    Claim("remote-control device revocation", REMOTE_REVOKE_MARKER),
    *(Claim("app-server daemon", marker) for marker in DAEMON_MARKERS),
    *(Claim(f"log marker {marker}", marker) for marker in LOG_MARKERS),
    Claim("approval_policy value", NEVER),
    Claim("sandbox_mode value", "danger-full-access"),
    Claim("flag that turns off approval and sandbox", BYPASS_FLAG.removeprefix("--")),
    Claim("command rule format", 'decision="allow"'),
)
OTHER_APP_BUNDLE = ".app/Contents/"
"""Path fragment of a codex binary shipped inside another app (the ChatGPT desktop app)."""


class RemoteEnrollment(NamedTuple):
    """One remote-control enrollment row from the state DB."""

    client: str
    server: str
    enabled: bool
    updated: str


def collect(ctx: Context, found: ToolPresence | None = None) -> tuple[ToolReport, dict[str, Any]]:
    """Collect Codex CLI's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence when already detected, so binaries are probed once.

    Returns:
        The report and private facts for the rule engine.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    root = home_dir(ctx)
    config = load_toml(root / "config.toml") or {}
    found = found or detect(ctx, sized=False)
    report.binaries = found.binaries
    report.installed = found.installed
    facts: dict[str, Any] = {"config": config, "root": root}
    if not report.installed:
        return report, facts
    report.artifacts = describe_all(root, ARTIFACTS)
    report.credentials, facts["fingerprints"] = _credentials(ctx, root, config)
    report.processes = _cli_processes(processes(ctx.system, r"(^|/)codex(\s|$)|codex-darwin"))
    report.settings = _settings(ctx, config, root, binary_path(report))
    report.settings += shell_shortcuts(ctx, BYPASS_FLAG)
    threads = thread_approval(root)
    if threads is not None:
        report.settings.append(threads)
    report.trusted_folders = [
        p for p, v in config.get("projects", {}).items() if v.get("trust_level") == "trusted"
    ]
    report.instructions = instructions.collect(_instruction_candidates(root, config))
    report.extensions = _extensions(ctx, root, config)
    report.endpoints = _endpoints(ctx, root, report)
    binary = binary_path(report)
    version = report.binaries[0].version if report.binaries else "?"
    rows = [(label, value.format(version=version), marker) for label, value, marker in FINGERPRINT]
    report.fingerprint = fingerprint_items(ctx, binary, rows)
    report.stats = _stats(root)
    if ctx.scan:
        report.secret_scan = scan_paths(
            [root],
            workers=ctx.workers,
            display=ctx.display,
            known=facts["fingerprints"],
            stores=[root / "auth.json"],
            exclude=[root / "packages", root / "plugins"],
        )
    report.programs = [_tac_status(report)]
    return report, facts


def home_dir(ctx: Context) -> Path:
    """Codex's data folder, honouring CODEX_HOME."""
    return Path(ctx.system.env.get("CODEX_HOME") or ctx.home / ".codex")


def detect(ctx: Context, *, sized: bool = True) -> ToolPresence:
    """Is Codex CLI installed, and where?"""
    return presence(NAME, DISPLAY, _binaries(ctx), [home_dir(ctx)], sized=sized)


def _binaries(ctx: Context) -> list[BinaryInfo]:
    found = []
    for path in ctx.system.which_all("codex"):
        resolved = Path(path).resolve()
        version = ""
        package = resolved.parent.parent / "package.json"
        if package.is_file():
            version = str((load_json(package) or {}).get("version", ""))
        vendor = _find_vendor(resolved)
        info = binary_info(ctx.system, str(vendor or path), version=version)
        info.path = path
        found.append(info)
    return found


def _find_vendor(script: Path) -> Path | None:
    """The native binary behind the npm ``codex.js`` launcher."""
    modules = script.parent.parent / "node_modules" / "@openai"
    if not modules.is_dir():
        return None
    for candidate in modules.glob("codex-*/vendor/*/bin/codex"):
        if candidate.is_file():
            return candidate
    return None


def _cli_processes(found: list[ProcessInfo]) -> list[ProcessInfo]:
    """Drop codex processes run from inside another app's bundle; they are not Codex CLI."""
    return [p for p in found if OTHER_APP_BUNDLE not in p.command]


def _credentials(
    ctx: Context, root: Path, config: dict[str, Any]
) -> tuple[list[Credential], dict[str, str]]:
    fingerprints: dict[str, str] = {}
    creds = []
    auth_path = root / "auth.json"
    store = str(config.get("cli_auth_credentials_store", "not set"))
    if auth_path.is_file():
        creds.append(_auth_file_credential(ctx, auth_path, store, fingerprints))
    for var in ("OPENAI_API_KEY", "CODEX_API_KEY"):
        value = ctx.system.env.get(var)
        if value:
            info = inspect_token(var, value, now=ctx.now)
            fingerprints[info.fingerprint] = f"${var}"
            creds.append(
                Credential(
                    NAME,
                    "OpenAI",
                    StoreKind.ENV,
                    f"${var}",
                    "inherited by every child process",
                    tokens=[info],
                )
            )
    return creds, fingerprints


def _auth_file_credential(
    ctx: Context, path: Path, store: str, fingerprints: dict[str, str]
) -> Credential:
    data = load_json(path) or {}
    tokens = data.get("tokens") or {}
    cred = Credential(
        NAME,
        "OpenAI",
        StoreKind.FILE,
        str(path),
        f"file mode {mode_string(path.stat().st_mode)}; credential store setting: {store}; "
        f"auth mode {data.get('auth_mode', '?')}; "
        f"last refresh {when(str(data.get('last_refresh', '?')))}",
        readable_by_others=readable_by_others(path),
    )
    for field in ("id_token", "access_token", "refresh_token"):
        value = tokens.get(field)
        if isinstance(value, str) and value:
            info = inspect_token(field, value, now=ctx.now)
            cred.tokens.append(info)
            fingerprints[info.fingerprint] = f"current Codex {field}"
    api_key = data.get("OPENAI_API_KEY")
    if isinstance(api_key, str) and api_key:
        info = inspect_token("OPENAI_API_KEY", api_key, now=ctx.now)
        cred.tokens.append(info)
        fingerprints[info.fingerprint] = "Codex OPENAI_API_KEY"
    if ctx.live:
        _verify_signatures(cred, tokens)
    return cred


def _verify_signatures(cred: Credential, tokens: dict[str, Any]) -> None:
    issuers = {t.issuer for t in cred.tokens if t.kind == "jwt" and t.issuer}
    for issuer in issuers:
        try:
            jwks = live.openid_jwks(issuer)
        except live.LiveCheckError as exc:
            cred.live_check = f"JWKS fetch failed: {exc}"
            return
        for info in cred.tokens:
            if info.kind == "jwt" and info.issuer == issuer:
                ok, why = verify_rs256(tokens[info.field], jwks)
                info.signature = f"{why} (issuer {issuer})" if ok else f"INVALID: {why}"
    cred.live_check = "JWT signatures checked against the issuer's published JWKS"


def _settings(ctx: Context, config: dict[str, Any], root: Path, binary: str) -> list[Setting]:
    projects = config.get("projects", {})
    trusted = [p for p, v in projects.items() if v.get("trust_level") == "trusted"]
    notify = config.get("notify")
    history = config.get("history") or {}
    features = config.get("features") or {}
    rules = _rule_count(root / "rules")
    rows: list[tuple[Setting, str]] = [
        (
            Setting(
                "approval_policy",
                value_or_unset(config, "approval_policy"),
                "'never' runs every command without asking",
                concern=config.get("approval_policy") == NEVER,
            ),
            "approval_policy",
        ),
        (
            Setting(
                "sandbox_mode",
                value_or_unset(config, "sandbox_mode"),
                "'danger-full-access' removes the filesystem and network sandbox",
                concern=config.get("sandbox_mode") == "danger-full-access",
            ),
            "sandbox_mode",
        ),
        (Setting("model", value_or_unset(config, "model"), "Model in use"), ""),
        (
            Setting(
                "trusted projects",
                f"{len(trusted)} of {len(projects)}",
                "Project AGENTS.md and config apply in trusted folders",
            ),
            "",
        ),
        (
            Setting(
                "notify",
                " ".join(map(str, notify)) if isinstance(notify, list) else "not set",
                "Program executed after every turn",
            ),
            "notify",
        ),
        (
            Setting(
                "pre-approved command rules",
                str(rules),
                "Command prefixes that run without asking",
                concern=bool(rules),
            ),
            "",
        ),
        (
            Setting(
                "cli_auth_credentials_store",
                value_or_unset(config, "cli_auth_credentials_store"),
                "'keyring' moves tokens out of plaintext auth.json",
            ),
            "cli_auth_credentials_store",
        ),
        (
            Setting(
                "history.persistence",
                value_or_unset(history, "persistence"),
                "Whether prompts are written to history.jsonl",
            ),
            "persistence",
        ),
        (
            Setting(
                "features.daemon_auto_start",
                value_or_unset(features, "daemon_auto_start"),
                "Starts the managed app-server daemon automatically",
            ),
            "daemon_auto_start",
        ),
    ]
    return confirmed_settings(ctx, binary, rows)


def _rule_count(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    total = 0
    for path in directory.glob("*.rules"):
        total += sum(
            1
            for line in path.read_text(errors="replace").splitlines()
            if 'decision="allow"' in line
        )
    return total


def _instruction_candidates(root: Path, config: dict[str, Any]) -> list[instructions.Candidate]:
    names = ["AGENTS.override.md", "AGENTS.md", *config.get("project_doc_fallback_filenames", [])]
    cands = [
        instructions.Candidate(root / "AGENTS.override.md", "global", NAME),
        instructions.Candidate(root / "AGENTS.md", "global", NAME),
    ]
    cands += instructions.project_candidates(config.get("projects", {}).keys(), names, NAME)
    return cands


def _extensions(ctx: Context, root: Path, config: dict[str, Any]) -> list[Extension]:
    out = [_mcp(name, spec, root) for name, spec in (config.get("mcp_servers") or {}).items()]
    out += _plugin_rows(ctx, root, config)
    hooks = load_json(root / "hooks.json") or {}
    out.extend(
        Extension(
            NAME,
            "hook",
            f"{event} [{group.get('matcher', '*')}]",
            "hooks.json",
            str(hook.get("command", "")),
            autostart=True,
            notes="Runs automatically on this event",
            identity=str(hook.get("command", "")),
        )
        for event, groups in (hooks.get("hooks") or {}).items()
        for group in groups
        for hook in group.get("hooks", [])
    )
    notify = config.get("notify")
    if isinstance(notify, list) and notify:
        out.append(
            Extension(
                NAME,
                "hook",
                "notify",
                "config.toml",
                " ".join(map(str, notify)),
                autostart=True,
                notes="Runs after every turn",
                identity=" ".join(map(str, notify)),
            )
        )
    out += extensions.skill_rows(root / "skills", NAME, ctx)
    out += extensions.skill_rows(ctx.home / ".agents" / "skills", NAME, ctx)
    return extensions.dedupe(out)


def _plugin_rows(ctx: Context, root: Path, config: dict[str, Any]) -> list[Extension]:
    """Enabled plugins from config.toml, described by their cached package manifest."""
    out = []
    for plugin, spec in (config.get("plugins") or {}).items():
        if not isinstance(spec, dict) or not spec.get("enabled", True):
            continue
        name, _, market = plugin.partition("@")
        versions = sorted(
            (p for p in (root / "plugins" / "cache" / market / name).glob("*") if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
        )
        install = versions[-1] if versions else None
        description, components = (
            extensions.plugin_manifest(install) if install else (extensions.NO_MANIFEST, "")
        )
        out.append(
            Extension(
                NAME,
                "plugin",
                plugin,
                "config.toml",
                ctx.display(str(install)) if install else "",
                description=description,
                access=components,
                identity=str(install) if install else plugin,
            )
        )
        if install is not None:
            out += extensions.plugin_mcp_rows(install, NAME, plugin)
            out += extensions.skill_rows(install / "skills", NAME, ctx, source=f"plugin {plugin}")
    return out


def _mcp(name: str, spec: dict[str, Any], root: Path) -> Extension:
    cwd = Path(str(spec.get("cwd", root)))
    cwd = cwd if cwd.is_absolute() else root / cwd
    return extensions.mcp_row(
        NAME, name, spec, "config.toml", cwd=cwd, enabled=bool(spec.get("enabled", True))
    )


def _endpoints(ctx: Context, root: Path, report: ToolReport) -> list[Endpoint]:
    remote = [
        Endpoint(NAME, host, f"remote MCP server '{server}'", "config")
        for host, server in report_mcp_urls(report)
    ]
    logs = [root / "log", root / "logs_2.sqlite"]
    return endpoints(ctx, report, ENDPOINTS, logs, extra=remote)


def report_mcp_urls(report: ToolReport) -> list[tuple[str, str]]:
    """(host, name) for remote MCP servers in the report."""
    out = []
    for ext in report.extensions:
        match = re.search(r"https?://([^/\s]+)", ext.detail)
        if ext.kind == "mcp" and match:
            out.append((match.group(1), ext.name))
    return out


def _stats(root: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    folders = [root / "sessions", root / "archived_sessions"]
    if any(folder.is_dir() for folder in folders):
        stats["session rollouts"] = str(sum(_rollout_count(folder) for folder in folders))
    history = root / "history.jsonl"
    if history.is_file():
        stats["typed prompts"] = str(sum(1 for _ in history.open("rb")))
    threads = _sqlite_rows(root / "state_5.sqlite", "SELECT count(*) FROM threads")
    if threads:
        stats["threads (state DB)"] = str(threads[0][0])
    install = root / "installation_id"
    if install.is_file():
        stats["installation id"] = install.read_text().strip()[:8] + "…"
    return stats


def _rollout_count(folder: Path) -> int:
    """Rollout files, plain or zstd-compressed, under one sessions folder."""
    if not folder.is_dir():
        return 0
    return sum(
        1
        for path in folder.rglob("rollout-*")
        if path.name.endswith((".jsonl", ".jsonl.zst")) and path.is_file()
    )


def _sqlite_rows(path: Path, query: str) -> list[tuple[Any, ...]] | None:
    """Rows from a read-only query, or None when the file or the queried table is missing."""
    if not path.is_file():
        return None
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2) as conn:
            return conn.execute(query).fetchall()
    except sqlite3.Error:
        return None


def _sandbox_type(policy: str) -> str:
    """The sandbox type from a thread's ``sandbox_policy`` (JSON object or bare string)."""
    try:
        data = json.loads(policy)
    except ValueError:
        return policy
    return str(data.get("type", "")) if isinstance(data, dict) else str(data)


def _thread_origin(originator: str, source: str) -> str:
    """``desktop`` for the desktop app, ``guardian`` for its review subagents, else ``cli``."""
    if "guardian" in source:
        return "guardian"
    return "desktop" if originator == "Codex Desktop" else "cli"


def thread_approval(root: Path) -> Setting | None:
    """How many recorded CLI threads ran with approval off, from the state DB's per-thread modes.

    Threads written by the Codex desktop app and guardian review subagents share the database;
    they are counted apart and named, not added to the CLI count.

    Returns:
        A setting whose value counts those threads and their sandbox types, or None when the
        state DB or its threads table is not there to read.
    """
    db = root / "state_5.sqlite"
    rows = _sqlite_rows(
        db,
        "SELECT approval_mode, sandbox_policy, coalesce(originator, ''), coalesce(source, ''), "
        "updated_at FROM threads",
    ) or _sqlite_rows(db, "SELECT approval_mode, sandbox_policy, '', '', updated_at FROM threads")
    if rows is None:
        return None
    origins: Counter[str] = Counter()
    sandboxes: Counter[str] = Counter()
    latest = 0
    for mode, policy, originator, source, updated in rows:
        origin = _thread_origin(str(originator), str(source))
        if origin != "cli":
            origins[origin] += mode == NEVER
            continue
        origins["cli"] += 1
        if mode == NEVER:
            sandboxes[_sandbox_type(str(policy))] += 1
            latest = max(latest, int(updated))
    never = sum(sandboxes.values())
    value = f"{never} of {origins['cli']} CLI threads"
    if never:
        kinds = ", ".join(f"{n} {kind}" for kind, n in sandboxes.most_common())
        value += f" (sandbox {kinds}; latest {iso_time(latest)[:10]})"
    others = [
        plural(origins[k], label)
        for k, label in (("desktop", "desktop-app thread"), ("guardian", "guardian review"))
        if origins[k]
    ]
    if others:
        value += f"; not counted: {', '.join(others)}"
    return Setting(
        THREADS_WITHOUT_APPROVAL,
        value,
        "Approval mode each thread ran with, as recorded in ~/.codex/state_5.sqlite",
        concern=bool(never),
    )


def remote_control_enrollments(root: Path) -> list[RemoteEnrollment]:
    """Remote-control enrollments recorded in the state DB, newest first."""
    rows = _sqlite_rows(
        root / "state_5.sqlite",
        "SELECT app_server_client_name, server_name, remote_control_enabled, updated_at "
        "FROM remote_control_enrollments ORDER BY updated_at DESC",
    )
    return [
        RemoteEnrollment(str(client), str(server), bool(enabled), iso_time(int(updated))[:10])
        for client, server, enabled, updated in rows or []
    ]


def _tac_status(report: ToolReport) -> ProgramStatus:
    claimed = [f for f in report.instructions if any("trusted access" in m for m in f.markers)]
    evidence = [
        f"Claimed in {item.path}; the model reads this as an attestation" for item in claimed
    ]
    for cred in report.credentials:
        for token in cred.tokens:
            groups = token.claims.get("https://api.openai.com/auth.groups", "")
            if groups:
                evidence.append(f"{token.field} groups claim: {groups}")
    status = "claimed in instructions, not shown in token claims" if claimed else "no evidence"
    if not evidence:
        evidence.append("No trusted-access claim found in tokens or instruction files")
    return ProgramStatus("OpenAI Trusted Access for Cyber", status, evidence)
