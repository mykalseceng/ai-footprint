"""OpenCode (``opencode``) footprint collector."""

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ai_footprint import extensions, instructions
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
    load_jsonc,
    presence,
    provider_credential,
    value_or_unset,
)
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.host import Socket, processes, sockets
from ai_footprint.model import (
    BinaryInfo,
    Category,
    Credential,
    Endpoint,
    Extension,
    Setting,
    ToolPresence,
    ToolReport,
)
from ai_footprint.secrets import scan_paths
from ai_footprint.tokens import inspect_token, iso_time

NAME = "opencode"
DISPLAY = "OpenCode"
PROCESS = r"(^|/)opencode2?(\.exe)?(\s|$)"
"""OpenCode's command line; 2.x sessions set their process title to ``opencode2``."""
SESSION_TABLES = ("session", "session_v2")
MESSAGE_TABLES = ("message", "session_message")
C = Category

PROVIDER_HOSTS = {
    "anthropic": "api.anthropic.com",
    "openai": "chatgpt.com / api.openai.com",
    "deepseek": "api.deepseek.com",
    "moonshotai": "api.moonshot.ai",
    "opencode": "opencode.ai (Zen gateway)",
    "github-copilot": "api.githubcopilot.com",
    "google": "generativelanguage.googleapis.com",
    "openrouter": "openrouter.ai",
    "zai": "api.z.ai",
    "zai-coding-plan": "api.z.ai",
}

PROVIDER_NAMES = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "deepseek": "DeepSeek",
    "moonshotai": "Moonshot AI",
    "opencode": "OpenCode Zen",
    "github-copilot": "GitHub Copilot",
    "google": "Google",
    "openrouter": "OpenRouter",
}

ENDPOINTS = {
    "opencode.ai": "Config schema, themes, Zen model gateway, updates",
    "models.dev": "Model catalog",
}

FINGERPRINT = (
    ("User-Agent", "opencode/{version}", '"User-Agent":`opencode/${'),
    (
        "Gateway headers",
        "x-opencode-client, x-opencode-session, x-opencode-project (opencode.ai requests)",
        '"x-opencode-client"',
    ),
    (
        "Local server",
        "HTTP Basic auth; password from OPENCODE_SERVER_PASSWORD (realm 'Secure Area')",
        "OPENCODE_SERVER_PASSWORD",
    ),
    ("Shared skill dirs", "reads ~/.claude and ~/.agents skill folders", '[".claude",".agents"]'),
    (
        "Instruction files",
        "AGENTS.md, CLAUDE.md, CONTEXT.md; ~/.claude/CLAUDE.md unless "
        "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT is set",
        "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT",
    ),
)

DISABLE_CLAUDE_VARS = ("OPENCODE_DISABLE_CLAUDE_CODE", "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT")
SETTING_KEYS = ('"permission"', '"share"', "autoupdate:", '"plugin"', '"instructions"')
CLAIMS: tuple[Claim, ...] = (
    *(Claim(f"endpoint {host}", host) for host in ENDPOINTS),
    *(Claim(f"signature: {label}", marker) for label, _value, marker in FINGERPRINT),
    *(Claim(f"setting {key}", key) for key in SETTING_KEYS),
    Claim("Basic-auth realm", "Secure Area"),
    Claim("share value", '"disabled"'),
)


def _roots(ctx: Context) -> dict[str, Path]:
    env = ctx.system.env
    return {
        "data": Path(env.get("XDG_DATA_HOME") or ctx.home / ".local/share") / "opencode",
        "config": Path(env.get("XDG_CONFIG_HOME") or ctx.home / ".config") / "opencode",
        "state": Path(env.get("XDG_STATE_HOME") or ctx.home / ".local/state") / "opencode",
        "cache": Path(env.get("XDG_CACHE_HOME") or ctx.home / ".cache") / "opencode",
        "install": ctx.home / ".opencode",
    }


def _service_files(roots: dict[str, Path]) -> list[Path]:
    """Files holding the local server password: the configured one and the running server's."""
    return [roots["config"] / "service.json", roots["state"] / "service.json"]


def _presence_roots(roots: dict[str, Path]) -> list[Path]:
    return [roots["data"], roots["config"], roots["install"]]


def _artifact_specs(roots: dict[str, Path]) -> list[ArtifactSpec]:
    data, config, state = roots["data"], roots["config"], roots["state"]
    return [
        ArtifactSpec(
            "Provider credentials",
            str(data / "auth.json"),
            C.CREDENTIAL,
            "OAuth tokens and API keys per provider, plaintext",
        ),
        ArtifactSpec(
            "Database",
            str(data / "opencode.db"),
            C.SESSION,
            "Sessions, messages, tool output, and a credential table",
        ),
        ArtifactSpec(
            "Database WAL", str(data / "opencode.db-wal"), C.SESSION, "Uncommitted database pages"
        ),
        ArtifactSpec("Legacy storage", str(data / "storage"), C.SESSION, "Pre-SQLite sessions"),
        ArtifactSpec(
            "Snapshots",
            str(data / "snapshot"),
            C.CACHE,
            "Git snapshots of project files for undo",
        ),
        ArtifactSpec("Tool output", str(data / "tool-output"), C.SESSION, "Large tool results"),
        ArtifactSpec("Logs", str(data / "log"), C.LOG, "Client and server logs"),
        ArtifactSpec("Config", str(config / "opencode.jsonc"), C.CONFIG, "Main config"),
        ArtifactSpec("Config (json)", str(config / "opencode.json"), C.CONFIG, "Main config"),
        ArtifactSpec(
            "Server password",
            str(config / "service.json"),
            C.CREDENTIAL,
            "Basic-auth password for the local opencode server",
        ),
        ArtifactSpec(
            "Global instructions",
            str(config / "AGENTS.md"),
            C.INSTRUCTIONS,
            "Loaded into every session",
        ),
        ArtifactSpec(
            "Plugin deps",
            str(config / "node_modules"),
            C.EXTENSION,
            "npm packages loaded by plugins",
        ),
        ArtifactSpec(
            "Prompt history",
            str(state / "prompt-history.jsonl"),
            C.SESSION,
            "Prompts typed into the TUI",
        ),
        ArtifactSpec(
            "Server registration",
            str(state / "service.json"),
            C.CREDENTIAL,
            "URL, pid and Basic-auth password of the running local server",
        ),
        ArtifactSpec(
            "Model state", str(state / "model.json"), C.CACHE, "Recent and favourite models"
        ),
        ArtifactSpec("TUI state", str(state / "latest"), C.CACHE, "TUI state and locks"),
        ArtifactSpec("Cache", str(roots["cache"]), C.CACHE, "Model catalog, downloads"),
        ArtifactSpec("Install", str(roots["install"]), C.BINARY, "Installed binary and deps"),
    ]


def collect(ctx: Context, found: ToolPresence | None = None) -> tuple[ToolReport, dict[str, Any]]:
    """Collect OpenCode's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence when already detected, so binaries are probed once.

    Returns:
        The report and private facts for the rule engine.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    roots = _roots(ctx)
    config = (
        load_jsonc(roots["config"] / "opencode.jsonc")
        or load_jsonc(roots["config"] / "opencode.json")
        or {}
    )
    found = found or detect(ctx, sized=False)
    report.binaries = found.binaries
    report.installed = found.installed
    db = roots["data"] / "opencode.db"
    facts: dict[str, Any] = {"config": config, "roots": roots, "db": db}
    if not report.installed:
        return report, facts
    report.artifacts = describe_all(Path("/"), _artifact_specs(roots))
    report.credentials, facts["fingerprints"], providers = _credentials(ctx, roots, db)
    report.processes = processes(ctx.system, PROCESS)
    socks = sockets(ctx.system, [p.pid for p in report.processes])
    binary = binary_path(report)
    report.settings = _settings(ctx, config, db, binary)
    projects = _projects(db)
    report.instructions = instructions.collect(
        _instruction_candidates(ctx, roots, config, projects)
    )
    report.extensions = _extensions(ctx, roots, config)
    report.endpoints = _endpoints(ctx, roots, report, providers, socks)
    server = _server_setting(ctx, roots, socks)
    if server:
        report.settings.append(server)
    version = report.binaries[0].version if report.binaries else "?"
    rows = [(label, value.format(version=version), marker) for label, value, marker in FINGERPRINT]
    report.fingerprint = fingerprint_items(ctx, binary, rows)
    report.stats = _stats(db)
    if ctx.scan:
        report.secret_scan = scan_paths(
            [roots["data"], roots["config"] / "service.json", roots["state"]],
            workers=ctx.workers,
            display=ctx.display,
            known=facts["fingerprints"],
            stores=[roots["data"] / "auth.json", db, *_service_files(roots)],
        )
    return report, facts


def detect(ctx: Context, *, sized: bool = True) -> ToolPresence:
    """Is OpenCode installed, and where?"""
    return presence(NAME, DISPLAY, _binaries(ctx), _presence_roots(_roots(ctx)), sized=sized)


def _binaries(ctx: Context) -> list[BinaryInfo]:
    found = []
    for path in ctx.system.which_all("opencode"):
        resolved = str(Path(path).resolve())
        result = ctx.system.run_tool(resolved, ["--version"])
        match = re.search(r"\d+\.\d+\.\d+", result.stdout)
        found.append(binary_info(ctx.system, path, version=match.group(0) if match else ""))
    return found


def _credentials(
    ctx: Context, roots: dict[str, Path], db: Path
) -> tuple[list[Credential], dict[str, str], set[str]]:
    """Stored credentials, their fingerprints, and the provider ids they belong to."""
    fingerprints: dict[str, str] = {}
    creds: list[Credential] = []
    auth = roots["data"] / "auth.json"
    stored = [(p, e, "plaintext file", auth) for p, e in (load_json(auth) or {}).items()]
    stored += [(p, e, "SQLite table credential", db) for p, e in _db_credentials(db)]
    for provider, entry, store, path in stored:
        if not isinstance(entry, dict):
            continue
        creds.append(
            provider_credential(
                ctx,
                entry,
                tool=NAME,
                provider=PROVIDER_NAMES.get(provider, provider),
                store=store,
                path=path,
                fingerprints=fingerprints,
                label=f"OpenCode {provider}",
            )
        )
    for service in _service_files(roots):
        password = (load_json(service) or {}).get("password")
        if not isinstance(password, str) or not password:
            continue
        info = inspect_token("password", password, now=ctx.now)
        fingerprints.setdefault(info.fingerprint, "OpenCode server password")
        creds.append(
            Credential(
                NAME,
                "OpenCode local server",
                "plaintext file",
                str(service),
                f"file mode {mode_string(service.stat().st_mode)}",
                readable_by_others=readable_by_others(service),
                tokens=[info],
            )
        )
    return creds, fingerprints, {p for p, e, _s, _p in stored if isinstance(e, dict)}


def _db_credentials(db: Path) -> list[tuple[str, dict[str, Any]]]:
    rows = _query(db, "SELECT integration_id, value FROM credential")
    out = []
    for provider, value in rows:
        try:
            entry = json.loads(value)
        except (TypeError, ValueError):
            continue
        if isinstance(entry, dict):
            out.append((str(provider), entry))
    return out


def _query(db: Path, sql: str) -> list[tuple[Any, ...]]:
    if not db.is_file():
        return []
    try:
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2) as conn:
            return list(conn.execute(sql).fetchall())
    except sqlite3.Error:
        return []


def _tables(db: Path, names: tuple[str, ...]) -> list[str]:
    """Which of ``names`` exist; OpenCode 2.x adds ``*_v2`` tables beside the legacy ones."""
    present = {str(row[0]) for row in _query(db, "SELECT name FROM sqlite_master")}
    return [name for name in names if name in present]


def _distinct_count(db: Path, tables: tuple[str, ...], where: str = "1") -> int:
    """Distinct ids across tables, since 2.x copies legacy rows with the same ids."""
    union = " UNION ".join(
        f"SELECT id FROM {t} WHERE {where}"  # noqa: S608 - fixed table names and conditions
        for t in _tables(db, tables)
    )
    rows = _query(db, f"SELECT count(*) FROM ({union})") if union else []  # noqa: S608 - same
    return int(rows[0][0]) if rows else 0


def _projects(db: Path) -> list[str]:
    return [
        str(row[0])
        for row in _query(db, "SELECT worktree FROM project")
        if row[0] and row[0] != "/"
    ]


def _settings(ctx: Context, config: dict[str, Any], db: Path, binary: str) -> list[Setting]:
    permission = config.get("permission")
    saved = _query(db, "SELECT action, count(*) FROM permission GROUP BY action")
    share_count = _distinct_count(db, SESSION_TABLES, "share_url IS NOT NULL")
    plugins = config.get("plugin", [])
    extra = config.get("instructions", [])
    rows: list[tuple[Setting, str]] = [
        (
            Setting(
                "permission",
                json.dumps(permission) if permission else "not set",
                "Per-tool ask/allow/deny rules",
            ),
            '"permission"',
        ),
        (
            Setting(
                "saved approvals",
                ", ".join(f"{a}: {n}" for a, n in saved) or "none",
                "Actions approved permanently from the prompt",
            ),
            "",
        ),
        (
            Setting(
                "share",
                value_or_unset(config, "share"),
                "'auto' uploads every new session to a share link",
                concern=config.get("share") == "auto",
            ),
            '"share"',
        ),
        (
            Setting(
                "shared sessions",
                str(share_count),
                "Sessions with a share URL",
                concern=bool(share_count),
            ),
            "",
        ),
        (
            Setting("autoupdate", value_or_unset(config, "autoupdate"), "Self-update behaviour"),
            "autoupdate:",
        ),
        (
            Setting(
                "plugins",
                ", ".join(map(str, plugins)) or "not set",
                "npm plugins loaded at startup in-process",
                concern=bool(plugins),
            ),
            '"plugin"',
        ),
        (
            Setting(
                "instructions",
                ", ".join(map(str, extra)) or "not set",
                "Extra instruction files or URLs loaded every session",
                concern=any(str(i).startswith("http") for i in extra),
            ),
            '"instructions"',
        ),
    ]
    return confirmed_settings(ctx, binary, rows)


def _instruction_candidates(
    ctx: Context, roots: dict[str, Path], config: dict[str, Any], projects: list[str]
) -> list[instructions.Candidate]:
    """AGENTS.md, CONTEXT.md and (unless disabled by env) the Claude Code CLAUDE.md files."""
    claude_files = not any(ctx.system.env.get(var) for var in DISABLE_CLAUDE_VARS)
    cands = [instructions.Candidate(roots["config"] / "AGENTS.md", "global", NAME)]
    if claude_files:
        cands.append(instructions.Candidate(ctx.home / ".claude" / "CLAUDE.md", "global", NAME))
    for extra in config.get("instructions", []):
        path = Path(str(extra)).expanduser()
        if not str(extra).startswith("http") and path.is_absolute():
            cands.append(instructions.Candidate(path, "global", NAME))
    names = ("AGENTS.md", *(("CLAUDE.md",) if claude_files else ()), "CONTEXT.md")
    cands += instructions.project_candidates(projects, names, NAME)
    return cands


def _extensions(ctx: Context, roots: dict[str, Path], config: dict[str, Any]) -> list[Extension]:
    out = [_mcp(name, spec) for name, spec in (config.get("mcp") or {}).items()]
    node_modules = roots["config"] / "node_modules"
    out.extend(
        Extension(
            NAME,
            "plugin",
            str(plugin),
            "opencode config",
            "npm package",
            autostart=True,
            notes="Runs in-process",
            description=extensions.package_description(node_modules, str(plugin))
            or extensions.NO_MANIFEST,
            access="npm package",
            identity=f"npm {plugin}",
        )
        for plugin in config.get("plugin", [])
    )
    for folder in ("plugin", "plugins", "skill", "skills", "agent", "agents", "command"):
        kind = "plugin" if folder.startswith("plugin") else "skill"
        for row in extensions.skill_rows(roots["config"] / folder, NAME, ctx):
            row.kind = kind
            out.append(row)
    for shared in (ctx.home / ".claude" / "skills", ctx.home / ".agents" / "skills"):
        out += extensions.skill_rows(shared, NAME, ctx)
    return extensions.dedupe(out)


def _mcp(name: str, spec: dict[str, Any]) -> Extension:
    enabled = bool(spec.get("enabled", True))
    if spec.get("type") == "remote" or spec.get("url"):
        return extensions.mcp_row(
            NAME,
            name,
            {"url": spec.get("url", "?"), "type": "remote"},
            "opencode config",
            enabled=enabled,
        )
    command = [str(c) for c in spec.get("command", [])]
    stdio = {
        "command": command[0] if command else "",
        "args": command[1:],
        "env": spec.get("environment"),
    }
    return extensions.mcp_row(NAME, name, stdio, "opencode config", enabled=enabled)


def _endpoints(
    ctx: Context,
    roots: dict[str, Path],
    report: ToolReport,
    providers: set[str],
    socks: list[Socket],
) -> list[Endpoint]:
    hosts = [
        Endpoint(NAME, PROVIDER_HOSTS[p], f"{p} provider API", "credentials")
        for p in sorted(providers & set(PROVIDER_HOSTS))
    ]
    logs = [roots["data"] / "log"]
    return endpoints(ctx, report, ENDPOINTS, logs, extra=hosts, socks=socks)


def _server_setting(ctx: Context, roots: dict[str, Path], socks: list[Socket]) -> Setting | None:
    """Whether the listening server's own registration records a password.

    OpenCode 2.x writes each running server's URL, pid and password to service.json in its
    state folder. Only a registration for the listening port says anything about that server;
    without one the password is not checked, since the audit sends the server no requests.
    """
    listeners = [s for s in socks if s.state == "LISTEN"]
    if not listeners:
        return None
    address = listeners[0].local
    path = roots["state"] / "service.json"
    record = load_json(path) or {}
    url = str(record.get("url", ""))
    if not url or str(urlsplit(url).port) != address.rsplit(":", 1)[-1]:
        return Setting(
            f"listening server {address}",
            "no service.json registration for this port; password not checked",
            "OpenCode records each running server's password in its state folder",
        )
    password = record.get("password")
    has_password = isinstance(password, str) and bool(password)
    where = ctx.display(str(path))
    return Setting(
        f"local server {address}",
        f"password set ({where})" if has_password else f"no password in its registration ({where})",
        "Any local process or user can drive a server without a password",
        concern=not has_password,
    )


def _stats(db: Path) -> dict[str, str]:
    stats = {}
    for key, tables in (("sessions", SESSION_TABLES), ("messages", MESSAGE_TABLES)):
        if _tables(db, tables):
            stats[key] = str(_distinct_count(db, tables))
    for table in ("part", "project"):
        rows = _query(db, f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed table names
        if rows:
            stats[f"{table}s"] = str(rows[0][0])
    spans = [
        row
        for table in _tables(db, SESSION_TABLES)
        for row in _query(db, f"SELECT min(time_created), max(time_created) FROM {table}")  # noqa: S608 - fixed table names
        if row[0]
    ]
    if spans:
        stats["first session"] = iso_time(min(r[0] for r in spans))[:10]
        stats["last session"] = iso_time(max(r[1] for r in spans))[:10]
    return stats
