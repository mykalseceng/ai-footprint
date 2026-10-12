"""OpenCode (``opencode``) footprint collector."""

import json
import re
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ai_footprint import extensions, instructions
from ai_footprint.collectors.common import (
    ArtifactSpec,
    Claim,
    Context,
    binary_info,
    confirmed_settings,
    describe_all,
    fingerprint_items,
    load_json,
    load_jsonc,
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
    Setting,
    ToolPresence,
    ToolReport,
)
from ai_footprint.secrets import scan_paths
from ai_footprint.tokens import inspect_token, iso_time

NAME = "opencode"
DISPLAY = "OpenCode"
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


def _artifact_specs(roots: dict[str, Path]) -> list[ArtifactSpec]:
    data, config = roots["data"], roots["config"]
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
            C.SESSION,
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
        ArtifactSpec("State", str(roots["state"]), C.CACHE, "UI state, prompt history"),
        ArtifactSpec("Cache", str(roots["cache"]), C.CACHE, "Model catalog, downloads"),
        ArtifactSpec("Install", str(roots["install"]), C.BINARY, "Installed binary and deps"),
    ]


def collect(ctx: Context) -> tuple[ToolReport, dict[str, Any]]:
    """Collect OpenCode's footprint.

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
    report.binaries = _binaries(ctx)
    report.installed = bool(report.binaries) or roots["data"].is_dir()
    db = roots["data"] / "opencode.db"
    facts: dict[str, Any] = {"config": config, "roots": roots, "db": db}
    if not report.installed:
        return report, facts
    report.artifacts = describe_all(Path("/"), _artifact_specs(roots))
    report.credentials, facts["fingerprints"] = _credentials(ctx, roots, db)
    report.processes = processes(ctx.system, r"(^|/)opencode(\.exe)?(\s|$)")
    binary = report.binaries[0].resolved if report.binaries else ""
    report.settings = _settings(ctx, config, db, binary)
    projects = _projects(db)
    report.instructions = instructions.collect(
        _instruction_candidates(ctx, roots, config, projects)
    )
    report.extensions = _extensions(ctx, roots, config)
    report.endpoints = _endpoints(ctx, roots, report)
    facts["server"] = _server_probe(ctx, report)
    if facts["server"]:
        report.settings.append(facts["server"])
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
            stores=[roots["data"] / "auth.json", db, roots["config"] / "service.json"],
        )
    return report, facts


def detect(ctx: Context) -> ToolPresence:
    """Is OpenCode installed, and where?"""
    roots = _roots(ctx)
    return presence(
        NAME, DISPLAY, _binaries(ctx), [roots["data"], roots["config"], roots["install"]]
    )


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
) -> tuple[list[Credential], dict[str, str]]:
    fingerprints: dict[str, str] = {}
    creds: list[Credential] = []
    auth = roots["data"] / "auth.json"
    for provider, entry in (load_json(auth) or {}).items():
        creds.append(
            _provider_credential(ctx, provider, entry, "plaintext file", auth, fingerprints)
        )
    for provider, entry in _db_credentials(db):
        creds.append(
            _provider_credential(ctx, provider, entry, "SQLite table credential", db, fingerprints)
        )
    service = roots["config"] / "service.json"
    password = (load_json(service) or {}).get("password")
    if isinstance(password, str) and password:
        info = inspect_token("password", password, now=ctx.now)
        fingerprints[info.fingerprint] = "OpenCode server password"
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
    return creds, fingerprints


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


def _provider_credential(
    ctx: Context,
    provider: str,
    entry: dict[str, Any],
    store: str,
    path: Path,
    fingerprints: dict[str, str],
) -> Credential:
    kind = str(entry.get("type", "?"))
    cred = Credential(
        NAME,
        PROVIDER_NAMES.get(provider, provider),
        store,
        str(path),
        f"{kind} credential; file mode {mode_string(path.stat().st_mode)}",
        readable_by_others=readable_by_others(path),
    )
    for field in ("access", "refresh", "key"):
        value = entry.get(field)
        if isinstance(value, str) and value:
            info = inspect_token(
                field,
                value,
                now=ctx.now,
                expires_at=entry.get("expires") if field == "access" else None,
            )
            cred.tokens.append(info)
            fingerprints.setdefault(info.fingerprint, f"OpenCode {provider} {field}")
    return cred


def _query(db: Path, sql: str) -> list[tuple[Any, ...]]:
    if not db.is_file():
        return []
    try:
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2) as conn:
            return list(conn.execute(sql).fetchall())
    except sqlite3.Error:
        return []


def _projects(db: Path) -> list[str]:
    return [
        str(row[0])
        for row in _query(db, "SELECT worktree FROM project")
        if row[0] and row[0] != "/"
    ]


def _settings(ctx: Context, config: dict[str, Any], db: Path, binary: str) -> list[Setting]:
    permission = config.get("permission")
    saved = _query(db, "SELECT action, count(*) FROM permission GROUP BY action")
    shares = _query(db, "SELECT count(*) FROM session WHERE share_url IS NOT NULL")
    share_count = int(shares[0][0]) if shares else 0
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
                _value(config, "share"),
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
            Setting("autoupdate", _value(config, "autoupdate"), "Self-update behaviour"),
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


def _value(mapping: dict[str, Any], key: str) -> str:
    return str(mapping[key]) if key in mapping else "not set"


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


def _endpoints(ctx: Context, roots: dict[str, Path], report: ToolReport) -> list[Endpoint]:
    binary = report.binaries[0].resolved if report.binaries else ""
    present = ctx.binary_has(binary, list(ENDPOINTS)) if binary else {}
    out = [
        Endpoint(NAME, host, purpose, "binary")
        for host, purpose in ENDPOINTS.items()
        if present.get(host)
    ]
    raw = {name: key for key, name in PROVIDER_NAMES.items()}
    providers = sorted(
        {raw.get(c.provider, c.provider) for c in report.credentials} & set(PROVIDER_HOSTS)
    )
    out += [
        Endpoint(NAME, PROVIDER_HOSTS[p], f"{p} provider API", "credentials") for p in providers
    ]
    out += mined_endpoints(NAME, mine_hosts([roots["data"] / "log"]), ENDPOINTS)
    for sock in sockets(ctx.system, [p.pid for p in report.processes]):
        label = sock.remote or f"{sock.local} (listening)"
        out.append(
            Endpoint(
                NAME, label, f"socket of pid {sock.pid} {sock.state}".strip(), "live-socket", 1
            )
        )
    return out


def _server_probe(ctx: Context, report: ToolReport) -> Setting | None:
    """Ask each loopback opencode listener whether it demands authentication."""
    listeners = [
        s
        for s in sockets(ctx.system, [p.pid for p in report.processes])
        if s.state == "LISTEN" and s.local.startswith(("127.0.0.1:", "localhost:"))
    ]
    if not listeners:
        return None
    port = listeners[0].local.rsplit(":", 1)[-1]
    url = f"http://127.0.0.1:{port}/session"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - fixed loopback URL
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, TimeoutError):
        return None
    open_server = status == 200
    return Setting(
        f"local server 127.0.0.1:{port}",
        "no authentication" if open_server else f"HTTP {status} without credentials",
        "Any local process or user can drive an unauthenticated server",
        concern=bool(open_server),
    )


def _stats(db: Path) -> dict[str, str]:
    stats = {}
    for table in ("session", "message", "part", "project"):
        rows = _query(db, f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed table names
        if rows:
            stats[f"{table}s"] = str(rows[0][0])
    span = _query(db, "SELECT min(time_created), max(time_created) FROM session")
    if span and span[0][0]:
        stats["first session"] = iso_time(span[0][0])[:10]
        stats["last session"] = iso_time(span[0][1])[:10]
    return stats
