"""Claude Code (``claude``) footprint collector."""

import json
import re
from pathlib import Path
from typing import Any

from ai_footprint import extensions, instructions, keychain, live
from ai_footprint.collectors.common import (
    ArtifactSpec,
    Claim,
    Context,
    binary_info,
    confirmed_settings,
    describe_all,
    fingerprint_items,
    load_json,
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
from ai_footprint.tokens import inspect_token

NAME = "claude"
DISPLAY = "Claude Code"
KEYCHAIN_SERVICE = "Claude Code-credentials"
CYBER_MARKER = b'"apiRefusalCategory":"cyber"'
BYPASS_MODE = "bypassPermissions"
C = Category

ARTIFACTS = (
    ArtifactSpec(
        "Global config",
        ".claude.json",
        C.CONFIG,
        "Account profile, project paths and trust, MCP servers",
    ),
    ArtifactSpec("Config backup", ".claude.json.backup", C.CONFIG, "Older copy of .claude.json"),
    ArtifactSpec("Config backups", ".claude/backups", C.CONFIG, "Timestamped .claude.json copies"),
    ArtifactSpec(
        "Settings", ".claude/settings.json", C.CONFIG, "Permissions, hooks, plugins, env vars"
    ),
    ArtifactSpec("Local settings", ".claude/settings.local.json", C.CONFIG, "Per-machine settings"),
    ArtifactSpec(
        "Plaintext credentials", ".claude/.credentials.json", C.CREDENTIAL, "OAuth tokens as JSON"
    ),
    ArtifactSpec(
        "Transcripts",
        ".claude/projects",
        C.SESSION,
        "Full conversations including every tool input and output",
    ),
    ArtifactSpec("Prompt history", ".claude/history.jsonl", C.SESSION, "Every prompt typed"),
    ArtifactSpec(
        "File snapshots", ".claude/file-history", C.SESSION, "Before/after copies of edited files"
    ),
    ArtifactSpec("Paste cache", ".claude/paste-cache", C.SESSION, "Large pasted content"),
    ArtifactSpec("Todos", ".claude/todos", C.SESSION, "Task lists"),
    ArtifactSpec("Plans", ".claude/plans", C.SESSION, "Plan-mode plans"),
    ArtifactSpec("Tasks", ".claude/tasks", C.SESSION, "Background task state"),
    ArtifactSpec("Teams", ".claude/teams", C.SESSION, "Agent-team state"),
    ArtifactSpec(
        "Session registry",
        ".claude/sessions",
        C.SESSION,
        "Per-pid files (process start, peer token) and session key files",
    ),
    ArtifactSpec("Debug logs", ".claude/debug", C.LOG, "Per-session debug logs"),
    ArtifactSpec("Telemetry", ".claude/telemetry", C.LOG, "Telemetry event batches"),
    ArtifactSpec("Statsig cache", ".claude/statsig", C.LOG, "Feature-flag cache"),
    ArtifactSpec(
        "Shell snapshots",
        ".claude/shell-snapshots",
        C.LOG,
        "Your aliases, functions and PATH, sourced before each command",
    ),
    ArtifactSpec("Session env", ".claude/session-env", C.LOG, "Per-session env files"),
    ArtifactSpec(
        "Global instructions", ".claude/CLAUDE.md", C.INSTRUCTIONS, "Loaded into every session"
    ),
    ArtifactSpec("Skills", ".claude/skills", C.EXTENSION, "User skills"),
    ArtifactSpec("Commands", ".claude/commands", C.EXTENSION, "Custom slash commands"),
    ArtifactSpec("Agents", ".claude/agents", C.EXTENSION, "Custom subagents"),
    ArtifactSpec("Plugins", ".claude/plugins", C.EXTENSION, "Marketplaces and plugin cache"),
    ArtifactSpec("Chrome bridge", ".claude/chrome", C.EXTENSION, "Native-messaging host wrapper"),
    ArtifactSpec("Status line", ".claude/statusline.sh", C.EXTENSION, "Status line script"),
    ArtifactSpec(
        "MCP logs (macOS)",
        "Library/Caches/claude-cli-nodejs",
        C.LOG,
        "Per-project MCP connection logs",
    ),
    ArtifactSpec("MCP logs", ".cache/claude-cli-nodejs", C.LOG, "Per-project MCP connection logs"),
    ArtifactSpec("Install", ".local/share/claude", C.BINARY, "Native install and old versions"),
)

ENDPOINTS = {
    "api.anthropic.com": "Inference, OAuth profile and roles",
    "platform.claude.com": "OAuth authorize and token refresh",
    "claude.com": "OAuth authorize for claude.ai logins",
    "claude.ai": "OAuth client metadata, settings pages",
    "mcp-proxy.anthropic.com": "claude.ai connectors (Gmail, Drive, Calendar, ...)",
    "downloads.claude.ai": "Version checks and updates",
    "storage.googleapis.com": "Release artifacts",
    "http-intake.logs.us5.datadoghq.com": "Error and event logging",
    "cdn.growthbook.io": "Feature flags",
    "raw.githubusercontent.com": "Plugin marketplaces",
    "github.com": "Plugin marketplaces",
}

FINGERPRINT = (
    ("User-Agent", "claude-cli/{version} (external, cli)", "claude-cli/"),
    ("App header", "x-app: cli", '"x-app"'),
    (
        "Beta header",
        "anthropic-beta: claude-code-20250219,oauth-2025-04-20,…",
        "claude-code-20250219",
    ),
    ("Auth header", "Authorization: Bearer sk-ant-oat01-…", "oauth-2025-04-20"),
    (
        "OAuth client",
        "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
    ),
    ("Token endpoint", "https://platform.claude.com/v1/oauth/token", "/v1/oauth/token"),
    ("Keychain item", f"{KEYCHAIN_SERVICE} (name assembled at runtime)", "-credentials"),
    ("Child shell", "zsh -c source ~/.claude/shell-snapshots/snapshot-*.sh", "shell-snapshots"),
    (
        "Child env",
        "CLAUDECODE=1, CLAUDE_CODE_ENTRYPOINT, CLAUDE_CODE_SESSION_ID",
        "CLAUDE_CODE_ENTRYPOINT",
    ),
    (
        "Keychain read",
        'spawns "security" by bare name (PATH lookup)',
        '"security",["find-generic-password"',
    ),
)

ENDPOINT_MARKERS = {"claude.com": "https://claude.com/"}
SETTING_KEYS = (
    "defaultMode",
    "skipDangerousModePermissionPrompt",
    "disableBypassPermissionsMode",
    "enableAllProjectMcpServers",
    "cleanupPeriodDays",
    "DISABLE_TELEMETRY",
    "DISABLE_ERROR_REPORTING",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "claudeInChromeDefaultEnabled",
)
REVOKE_MARKERS = ("oauth_token_revoke", "continuing with local logout")
OAUTH_URL = "https://platform.claude.com/v1/oauth/token"
TRAINING_MARKERS = ("Help improve our AI models", "extends data retention from 30 days to 5 years")
LOG_MARKERS = {
    "invalid_grant": "refresh rejected (invalid_grant)",
    "Please run /login": "asked to log in again",
}
CLAIMS: tuple[Claim, ...] = (
    *(Claim(f"endpoint {host}", ENDPOINT_MARKERS.get(host, host)) for host in ENDPOINTS),
    *(Claim(f"signature: {label}", marker) for label, _value, marker in FINGERPRINT),
    *(Claim(f"setting {key}", key) for key in SETTING_KEYS),
    Claim("permissions.defaultMode value", BYPASS_MODE),
    *(Claim("logout revokes the token", marker) for marker in REVOKE_MARKERS),
    Claim("OAuth token endpoint", OAUTH_URL),
    *(Claim("training setting wording", marker) for marker in TRAINING_MARKERS),
    *(Claim(f"log marker {marker}", marker) for marker in LOG_MARKERS),
    Claim("refusal category in transcripts", "apiRefusalCategory"),
)


def collect(ctx: Context) -> tuple[ToolReport, dict[str, Any]]:
    """Collect Claude Code's footprint.

    Returns:
        The report and a private ``facts`` dict the rule engine uses (never rendered).
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    home = ctx.home
    config = load_json(home / ".claude.json") or {}
    settings = load_json(home / ".claude" / "settings.json") or {}
    report.binaries = _binaries(ctx)
    report.installed = bool(report.binaries) or any(p.exists() for p in data_paths(ctx))
    facts: dict[str, Any] = {"config": config, "settings": settings}
    if not report.installed:
        return report, facts
    report.artifacts = describe_all(home, ARTIFACTS)
    report.credentials, facts["fingerprints"] = _credentials(ctx, report.binaries)
    _set_owner(report.credentials, config)
    report.processes = processes(ctx.system, r"(^|/)claude(\s|$)")
    report.settings = _settings(ctx, settings, config, report)
    report.trusted_folders = [
        p for p, v in config.get("projects", {}).items() if v.get("hasTrustDialogAccepted")
    ]
    report.instructions = instructions.collect(_instruction_candidates(home, config))
    report.extensions = _extensions(ctx, settings, config)
    report.endpoints = _endpoints(ctx, report)
    binary = report.binaries[0].resolved if report.binaries else ""
    version = report.binaries[0].version if report.binaries else "?"
    rows = [(label, value.format(version=version), marker) for label, value, marker in FINGERPRINT]
    report.fingerprint = fingerprint_items(ctx, binary, rows)
    report.stats = _stats(ctx, config)
    if ctx.scan:
        report.secret_scan = scan_paths(
            _scan_roots(home),
            workers=ctx.workers,
            display=ctx.display,
            markers={"cyber": ("Cyber-safeguard refusals", CYBER_MARKER)},
            known=facts["fingerprints"],
            stores=[home / ".claude" / ".credentials.json"],
        )
    report.programs = [_cvp_status(report)]
    return report, facts


def data_paths(ctx: Context) -> list[Path]:
    """Folders and files Claude Code writes."""
    return [ctx.home / ".claude", ctx.home / ".claude.json"]


def detect(ctx: Context) -> ToolPresence:
    """Is Claude Code installed, and where?"""
    return presence(NAME, DISPLAY, _binaries(ctx), data_paths(ctx))


def _binaries(ctx: Context) -> list[BinaryInfo]:
    found = []
    for path in ctx.system.which_all("claude"):
        resolved = Path(path).resolve()
        version = resolved.name if re.fullmatch(r"\d+\.\d+\.\d+", resolved.name) else ""
        if not version:
            result = ctx.system.run_tool(str(resolved), ["--version"])
            match = re.search(r"\d+\.\d+\.\d+", result.stdout)
            version = match.group(0) if match else ""
        found.append(binary_info(ctx.system, path, version=version))
    return found


def _credentials(
    ctx: Context, binaries: list[BinaryInfo]
) -> tuple[list[Credential], dict[str, str]]:
    creds: list[Credential] = []
    fingerprints: dict[str, str] = {}
    version = binaries[0].version if binaries else "0"
    keychain_cred = _keychain_credential(ctx, fingerprints, version)
    if keychain_cred:
        creds.append(keychain_cred)
    file_path = ctx.home / ".claude" / ".credentials.json"
    if file_path.is_file():
        data = load_json(file_path) or {}
        cred = _oauth_credential(
            ctx, data, store="plaintext file", location=str(file_path), fingerprints=fingerprints
        )
        cred.readable_by_others = readable_by_others(file_path)
        cred.protection = f"file mode {mode_string(file_path.stat().st_mode)}"
        creds.append(cred)
    creds.extend(_env_credentials(ctx, fingerprints))
    return creds, fingerprints


def _set_owner(creds: list[Credential], config: dict[str, Any]) -> None:
    """The claude.ai login belongs to the account ~/.claude.json records; API keys do not."""
    email = config.get("oauthAccount", {}).get("emailAddress")
    if not isinstance(email, str) or not email:
        return
    for cred in creds:
        if cred.store != "environment variable":
            cred.owner = email
            cred.owner_source = "~/.claude.json oauthAccount.emailAddress"


def _keychain_credential(
    ctx: Context, fingerprints: dict[str, str], version: str
) -> Credential | None:
    item = keychain.find_item(ctx.system, KEYCHAIN_SERVICE)
    if item is None:
        return None
    read = keychain.read_secret(ctx.system, KEYCHAIN_SERVICE)
    try:
        data = json.loads(read.value or "{}")
    except ValueError:
        data = {}
    cred = _oauth_credential(
        ctx,
        data,
        store="macOS Keychain",
        location=f"{item.keychain} · service '{KEYCHAIN_SERVICE}'",
        fingerprints=fingerprints,
    )
    cred.protection = (
        f"account {item.account}; created {item.created}; last written {item.modified}"
        + (
            f"; this audit read it via /usr/bin/security in {read.seconds}s with stdin closed, "
            "so any process running as you can read it without a prompt"
            if read.silent
            else ""
        )
    )
    access = data.get("claudeAiOauth", {}).get("accessToken")
    if ctx.live and isinstance(access, str):
        try:
            cred.live_check = live.anthropic_profile(access, version)
        except live.LiveCheckError as exc:
            cred.live_check = f"live check failed: {exc}"
    return cred


def _oauth_credential(
    ctx: Context, data: dict[str, Any], *, store: str, location: str, fingerprints: dict[str, str]
) -> Credential:
    oauth = data.get("claudeAiOauth", {}) if isinstance(data, dict) else {}
    cred = Credential(
        tool=NAME, provider="Anthropic", store=store, location=location, protection=""
    )
    scopes = [str(s) for s in oauth.get("scopes", [])]
    for field, expiry in (("accessToken", "expiresAt"), ("refreshToken", "refreshTokenExpiresAt")):
        value = oauth.get(field)
        if isinstance(value, str) and value:
            info = inspect_token(
                field,
                value,
                now=ctx.now,
                expires_at=oauth.get(expiry),
                scopes=scopes if field == "accessToken" else None,
            )
            cred.tokens.append(info)
            fingerprints[info.fingerprint] = f"current Claude {field}"
    if oauth.get("subscriptionType"):
        cred.protection = f"subscription recorded as {oauth['subscriptionType']}"
    return cred


def _env_credentials(ctx: Context, fingerprints: dict[str, str]) -> list[Credential]:
    creds = []
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        value = ctx.system.env.get(var)
        if not value:
            continue
        info = inspect_token(var, value, now=ctx.now)
        fingerprints[info.fingerprint] = f"${var}"
        creds.append(
            Credential(
                tool=NAME,
                provider="Anthropic",
                store="environment variable",
                location=f"${var}",
                protection="inherited by every child process",
                tokens=[info],
            )
        )
    return creds


def _settings(
    ctx: Context, settings: dict[str, Any], config: dict[str, Any], report: ToolReport
) -> list[Setting]:
    perms = settings.get("permissions", {})
    cleanup = settings.get("cleanupPeriodDays")
    rows: list[tuple[Setting, str]] = [
        (
            Setting(
                "permissions.defaultMode",
                _value(perms, "defaultMode"),
                f"{BYPASS_MODE} runs every tool without asking",
                concern=perms.get("defaultMode") == BYPASS_MODE,
            ),
            "defaultMode",
        ),
        (
            Setting(
                "skipDangerousModePermissionPrompt",
                _value(settings, "skipDangerousModePermissionPrompt"),
                "Skips the confirmation shown before --dangerously-skip-permissions",
                concern=bool(settings.get("skipDangerousModePermissionPrompt")),
            ),
            "skipDangerousModePermissionPrompt",
        ),
        (
            Setting(
                "permissions.disableBypassPermissionsMode",
                _value(perms, "disableBypassPermissionsMode"),
                "'disable' blocks bypass mode",
            ),
            "disableBypassPermissionsMode",
        ),
        (
            Setting(
                "permissions deny/allow rules",
                f"{len(perms.get('deny', []))} deny / {len(perms.get('allow', []))} allow",
                "Rules in settings.json",
            ),
            "",
        ),
        (
            Setting(
                "enableAllProjectMcpServers",
                _value(settings, "enableAllProjectMcpServers"),
                "true starts MCP servers from any repo's .mcp.json without asking",
                concern=bool(settings.get("enableAllProjectMcpServers")),
            ),
            "enableAllProjectMcpServers",
        ),
        (
            Setting(
                "cleanupPeriodDays",
                _value(settings, "cleanupPeriodDays"),
                "Days transcripts are kept",
                concern=isinstance(cleanup, int) and cleanup > 30,
            ),
            "cleanupPeriodDays",
        ),
    ]
    rows += _settings_env(settings)
    rows += _settings_account(config)
    rows += [(setting, "") for setting in _bypass_evidence(ctx, report)]
    binary = report.binaries[0].resolved if report.binaries else ""
    return confirmed_settings(ctx, binary, rows)


def _value(mapping: dict[str, Any], key: str) -> str:
    return str(mapping[key]) if key in mapping else "not set"


def _settings_env(settings: dict[str, Any]) -> list[tuple[Setting, str]]:
    env = settings.get("env", {})
    flags = (
        "DISABLE_TELEMETRY",
        "DISABLE_ERROR_REPORTING",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    )
    return [
        (Setting(f"env.{flag}", _value(env, flag), "Turns off a class of outbound traffic"), flag)
        for flag in flags
    ]


def _settings_account(config: dict[str, Any]) -> list[tuple[Setting, str]]:
    account = config.get("oauthAccount", {})
    projects = config.get("projects", {})
    trusted = [p for p, v in projects.items() if v.get("hasTrustDialogAccepted")]
    return [
        (
            Setting(
                "account",
                f"{account.get('emailAddress', '?')} · "
                f"{account.get('organizationType', '?')} · role "
                f"{account.get('organizationRole', '?')}",
                "Identity behind the token",
            ),
            "",
        ),
        (
            Setting(
                "trusted folders",
                f"{len(trusted)} of {len(projects)}",
                "Instructions, hooks and settings in trusted folders apply automatically",
            ),
            "",
        ),
        (
            Setting(
                "claudeInChromeDefaultEnabled",
                _value(config, "claudeInChromeDefaultEnabled"),
                "Claude in Chrome enabled by default",
                concern=bool(config.get("claudeInChromeDefaultEnabled")),
            ),
            "claudeInChromeDefaultEnabled",
        ),
    ]


def _bypass_evidence(ctx: Context, report: ToolReport) -> list[Setting]:
    out = []
    running = [p for p in report.processes if "--dangerously-skip-permissions" in p.command]
    if running:
        out.append(
            Setting(
                "running with --dangerously-skip-permissions",
                ", ".join(str(p.pid) for p in running),
                "These sessions run every tool call without asking",
                concern=True,
            )
        )
    for rc in (".zshrc", ".bashrc", ".bash_profile", ".zprofile", ".config/fish/config.fish"):
        path = ctx.home / rc
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            if "dangerously-skip-permissions" in line and not line.lstrip().startswith("#"):
                out.append(
                    Setting(
                        f"~/{rc}:{number}",
                        line.strip()[:120],
                        "Shell shortcut that launches bypass mode",
                        concern=True,
                    )
                )
    return out


def _instruction_candidates(home: Path, config: dict[str, Any]) -> list[instructions.Candidate]:
    """CLAUDE.md files, auto-memory indexes, and agent and command definitions."""
    root = home / ".claude"
    cands = [instructions.Candidate(root / "CLAUDE.md", "global", NAME)]
    projects = list(config.get("projects", {}))
    cands += instructions.project_candidates(
        projects, ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md"), NAME
    )
    cands += [
        instructions.Candidate(path, "memory", NAME)
        for path in sorted((root / "projects").glob("*/memory/MEMORY.md"))
    ]
    cands += [
        instructions.Candidate(path, "agent", NAME)
        for path in sorted((root / "agents").glob("*.md"))
    ]
    cands += [
        instructions.Candidate(path, "command", NAME)
        for path in sorted((root / "commands").rglob("*.md"))
    ]
    return cands


def _extensions(ctx: Context, settings: dict[str, Any], config: dict[str, Any]) -> list[Extension]:
    out = _mcp_extensions(ctx, config)
    out += _hook_extensions(settings)
    out += _plugin_extensions(ctx, settings)
    out += extensions.skill_rows(ctx.home / ".claude" / "skills", NAME, ctx)
    out += _chrome_extensions(ctx, config)
    status = settings.get("statusLine", {})
    if isinstance(status, dict) and status.get("command"):
        out.append(
            Extension(
                NAME,
                "statusline",
                "status line",
                "settings.json",
                str(status["command"]),
                autostart=True,
                identity=str(status["command"]),
            )
        )
    return extensions.dedupe(out)


def _mcp_extensions(ctx: Context, config: dict[str, Any]) -> list[Extension]:
    scopes: list[tuple[str, dict[str, Any], Path | None]] = [
        ("user", config.get("mcpServers", {}), None)
    ]
    for project, value in config.get("projects", {}).items():
        if value.get("mcpServers"):
            scopes.append((f"project {ctx.display(project)}", value["mcpServers"], Path(project)))
    out = [
        extensions.mcp_row(NAME, name, spec, scope, cwd=cwd)
        for scope, servers, cwd in scopes
        for name, spec in servers.items()
    ]
    out.extend(
        Extension(
            NAME,
            "connector",
            str(connector),
            "claude.ai (server-side)",
            "Reached through mcp-proxy.anthropic.com with the OAuth token",
            description="claude.ai connector; no manifest on disk",
            access="claude.ai proxy",
            identity=f"connector {connector}",
        )
        for connector in config.get("claudeAiMcpEverConnected", [])
    )
    return out


def _hook_extensions(settings: dict[str, Any], source: str = "settings.json") -> list[Extension]:
    commands = [
        (event, group, hook)
        for event, groups in (settings.get("hooks") or {}).items()
        for group in (groups if isinstance(groups, list) else [])
        for hook in group.get("hooks", [])
        if hook.get("type") == "command"
    ]
    return [
        Extension(
            NAME,
            "hook",
            f"{event} [{group.get('matcher', '*')}]",
            source,
            str(hook.get("command", ""))[:200],
            autostart=True,
            notes="Runs automatically on this event",
        )
        for event, group, hook in commands
    ]


def _plugin_extensions(ctx: Context, settings: dict[str, Any]) -> list[Extension]:
    out = []
    plugins_dir = ctx.home / ".claude" / "plugins"
    installed = (load_json(plugins_dir / "installed_plugins.json") or {}).get("plugins", {})
    marketplaces = load_json(plugins_dir / "known_marketplaces.json") or {}
    for plugin_id, enabled in (settings.get("enabledPlugins") or {}).items():
        if not enabled:
            continue
        market = plugin_id.split("@", 1)[-1]
        source = (marketplaces.get(market) or {}).get("source", {})
        origin = source.get("repo") or source.get("path") or market
        entries = installed.get(plugin_id) or [{}]
        install = Path(entries[-1].get("installPath", "")) if entries[-1] else None
        description, components = extensions.plugin_manifest(install) if install else ("", "")
        out.append(
            Extension(
                NAME,
                "plugin",
                plugin_id,
                f"marketplace {origin}",
                ctx.display(str(install)) if install else "",
                notes="Directory marketplace (local path)"
                if source.get("source") == "directory"
                else "",
                description=description or extensions.NO_MANIFEST,
                access=components,
                identity=str(install) if install else plugin_id,
            )
        )
        if install is None:
            continue
        if (install / "hooks" / "hooks.json").is_file():
            hooks = load_json(install / "hooks" / "hooks.json") or {}
            out += _hook_extensions(hooks, source=f"plugin {plugin_id}")
        out += extensions.plugin_mcp_rows(install, NAME, plugin_id)
        out += extensions.skill_rows(install / "skills", NAME, ctx, source=f"plugin {plugin_id}")
    return out


def _chrome_extensions(ctx: Context, config: dict[str, Any]) -> list[Extension]:
    out = []
    hosts_dirs = (
        ctx.home / "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        ctx.home / ".config/google-chrome/NativeMessagingHosts",
    )
    for hosts in hosts_dirs:
        for manifest in sorted(hosts.glob("com.anthropic.*.json")) if hosts.is_dir() else []:
            data = load_json(manifest) or {}
            out.append(
                Extension(
                    NAME,
                    "native-host",
                    str(data.get("name", manifest.stem)),
                    ctx.display(str(hosts)),
                    f"{data.get('path', '?')} · origins "
                    f"{', '.join(data.get('allowed_origins', []))}",
                    autostart=True,
                    notes="Chrome launches this program"
                    + (
                        "; claudeInChromeDefaultEnabled is true"
                        if config.get("claudeInChromeDefaultEnabled")
                        else ""
                    ),
                    identity=str(data.get("path", manifest)),
                )
            )
    return out


def _endpoints(ctx: Context, report: ToolReport) -> list[Endpoint]:
    binary = report.binaries[0].resolved if report.binaries else ""
    markers = {host: ENDPOINT_MARKERS.get(host, host) for host in ENDPOINTS}
    in_binary = ctx.binary_has(binary, list(markers.values())) if binary else {}
    out = [
        Endpoint(NAME, host, purpose, "binary")
        for host, purpose in ENDPOINTS.items()
        if in_binary.get(markers[host])
    ]
    counts = mine_hosts(
        [ctx.home / ".claude" / "debug", ctx.home / "Library/Caches/claude-cli-nodejs"]
    )
    out += mined_endpoints(NAME, counts, ENDPOINTS)
    for sock in sockets(ctx.system, [p.pid for p in report.processes]):
        if sock.remote:
            out.append(
                Endpoint(NAME, sock.remote, f"open socket from pid {sock.pid}", "live-socket", 1)
            )
    return out


def _stats(ctx: Context, config: dict[str, Any]) -> dict[str, str]:
    root = ctx.home / ".claude"
    transcripts = list((root / "projects").rglob("*.jsonl")) if (root / "projects").is_dir() else []
    history = root / "history.jsonl"
    lines = sum(1 for _ in history.open("rb")) if history.is_file() else 0
    return {
        "transcripts": str(len(transcripts)),
        "project folders": str(len(config.get("projects", {}))),
        "typed prompts": str(lines),
        "startups": str(config.get("numStartups", "?")),
        "first start": str(config.get("firstStartTime", "?"))[:10],
    }


def _scan_roots(home: Path) -> list[Path]:
    return [
        home / ".claude",
        home / ".claude.json",
        home / ".claude.json.backup",
        home / "Library/Caches/claude-cli-nodejs",
        home / ".cache/claude-cli-nodejs",
    ]


def _cvp_status(report: ToolReport) -> ProgramStatus:
    """What the transcripts show about cyber-safeguard refusals; enrollment is not on disk."""
    scan = report.secret_scan
    if scan is None:
        return ProgramStatus(
            "Anthropic Cyber Verification Program",
            "not assessed",
            ["Run the full audit (without --doctor) to search transcripts"],
        )
    hit = next((m for m in scan.markers if m.marker == "cyber"), None)
    if hit is None:
        return ProgramStatus(
            "Anthropic Cyber Verification Program",
            "no cyber-safeguard refusals in transcripts",
            ["Enrollment is not recorded locally"],
        )
    return ProgramStatus(
        "Anthropic Cyber Verification Program",
        "cyber-safeguard refusals in transcripts",
        [
            f'{hit.count} API responses carried apiRefusalCategory "cyber" across '
            f"{hit.file_count} transcript(s)",
            "Enrollment is not recorded locally",
        ],
    )
