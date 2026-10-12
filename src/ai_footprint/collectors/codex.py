"""OpenAI Codex CLI (``codex``) footprint collector."""

import re
import sqlite3
from pathlib import Path
from typing import Any

from ai_footprint import extensions, instructions, live
from ai_footprint.collectors.common import (
    ArtifactSpec,
    Claim,
    Context,
    binary_info,
    confirmed_settings,
    describe_all,
    fingerprint_items,
    load_json,
    load_toml,
    mine_hosts,
    mined_endpoints,
    presence,
)
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.host import processes, sockets
from ai_footprint.model import (
    BinaryInfo,
    Category,
    Credential,
    Endpoint,
    Extension,
    ProgramStatus,
    Setting,
    ToolPresence,
    ToolReport,
)
from ai_footprint.secrets import scan_paths
from ai_footprint.surface import when
from ai_footprint.tokens import inspect_token, verify_rs256

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
CLAIMS: tuple[Claim, ...] = (
    *(Claim(f"endpoint {host}", host) for host in ENDPOINTS),
    *(Claim(f"signature: {label}", marker) for label, _value, marker in FINGERPRINT),
    *(Claim(f"setting {key}", key) for key in SETTING_KEYS),
    *(Claim("logout revokes tokens", marker) for marker in REVOKE_MARKERS),
    Claim("remote-control device revocation", REMOTE_REVOKE_MARKER),
    *(Claim("app-server daemon", marker) for marker in DAEMON_MARKERS),
    Claim("approval_policy value", "never"),
    Claim("sandbox_mode value", "danger-full-access"),
    Claim("command rule format", 'decision="allow"'),
)


def collect(ctx: Context) -> tuple[ToolReport, dict[str, Any]]:
    """Collect Codex CLI's footprint.

    Returns:
        The report and private facts for the rule engine.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    root = home_dir(ctx)
    config = load_toml(root / "config.toml") or {}
    report.binaries = _binaries(ctx)
    report.installed = bool(report.binaries) or root.is_dir()
    facts: dict[str, Any] = {"config": config, "root": root}
    if not report.installed:
        return report, facts
    report.artifacts = describe_all(root, ARTIFACTS)
    report.credentials, facts["fingerprints"] = _credentials(ctx, root, config)
    report.processes = processes(ctx.system, r"(^|/)codex(\s|$)|codex-darwin|CodexCLI")
    report.settings = _settings(ctx, config, root, _vendor_binary(report.binaries))
    report.trusted_folders = [
        p for p, v in config.get("projects", {}).items() if v.get("trust_level") == "trusted"
    ]
    report.instructions = instructions.collect(_instruction_candidates(root, config))
    report.extensions = _extensions(ctx, root, config)
    report.endpoints = _endpoints(ctx, root, report)
    binary = _vendor_binary(report.binaries)
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
        )
    report.programs = [_tac_status(report)]
    return report, facts


def home_dir(ctx: Context) -> Path:
    """Codex's data folder, honouring CODEX_HOME."""
    return Path(ctx.system.env.get("CODEX_HOME") or ctx.home / ".codex")


def detect(ctx: Context) -> ToolPresence:
    """Is Codex CLI installed, and where?"""
    return presence(NAME, DISPLAY, _binaries(ctx), [home_dir(ctx)])


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


def _vendor_binary(binaries: list[BinaryInfo]) -> str:
    return binaries[0].resolved if binaries else ""


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
                    "environment variable",
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
        "plaintext file",
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
                _value(config, "approval_policy"),
                "'never' runs every command without asking",
                concern=config.get("approval_policy") == "never",
            ),
            "approval_policy",
        ),
        (
            Setting(
                "sandbox_mode",
                _value(config, "sandbox_mode"),
                "'danger-full-access' removes the filesystem and network sandbox",
                concern=config.get("sandbox_mode") == "danger-full-access",
            ),
            "sandbox_mode",
        ),
        (Setting("model", _value(config, "model"), "Model in use"), ""),
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
                _value(config, "cli_auth_credentials_store"),
                "'keyring' moves tokens out of plaintext auth.json",
            ),
            "cli_auth_credentials_store",
        ),
        (
            Setting(
                "history.persistence",
                _value(history, "persistence"),
                "Whether prompts are written to history.jsonl",
            ),
            "persistence",
        ),
        (
            Setting(
                "features.daemon_auto_start",
                _value(features, "daemon_auto_start"),
                "Starts the managed app-server daemon automatically",
            ),
            "daemon_auto_start",
        ),
    ]
    return confirmed_settings(ctx, binary, rows)


def _value(mapping: dict[str, Any], key: str) -> str:
    return str(mapping[key]) if key in mapping else "not set"


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
        description, components = extensions.plugin_manifest(install) if install else ("", "")
        out.append(
            Extension(
                NAME,
                "plugin",
                plugin,
                "config.toml",
                ctx.display(str(install)) if install else "",
                description=description or extensions.NO_MANIFEST,
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
    binary = _vendor_binary(report.binaries)
    present = ctx.binary_has(binary, list(ENDPOINTS)) if binary else {}
    out = [
        Endpoint(NAME, host, purpose, "binary")
        for host, purpose in ENDPOINTS.items()
        if present.get(host)
    ]
    for host, server in report_mcp_urls(report):
        out.append(Endpoint(NAME, host, f"remote MCP server '{server}'", "config"))
    counts = mine_hosts([root / "log", root / "logs_2.sqlite"])
    out += mined_endpoints(NAME, counts, ENDPOINTS)
    for sock in sockets(ctx.system, [p.pid for p in report.processes]):
        if sock.remote:
            out.append(
                Endpoint(NAME, sock.remote, f"open socket from pid {sock.pid}", "live-socket", 1)
            )
    return out


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
    sessions = root / "sessions"
    if sessions.is_dir():
        stats["session rollouts"] = str(sum(1 for _ in sessions.rglob("rollout-*.jsonl")))
    history = root / "history.jsonl"
    if history.is_file():
        stats["typed prompts"] = str(sum(1 for _ in history.open("rb")))
    threads = _sqlite_count(root / "state_5.sqlite", "threads")
    if threads is not None:
        stats["threads (state DB)"] = str(threads)
    install = root / "installation_id"
    if install.is_file():
        stats["installation id"] = install.read_text().strip()[:8] + "…"
    return stats


def _sqlite_count(path: Path, table: str) -> int | None:
    if not path.is_file() or not re.fullmatch(r"\w+", table):
        return None
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2) as conn:
            row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()  # noqa: S608
    except sqlite3.Error:
        return None
    return int(row[0]) if row else None


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
