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
    binary_path,
    confirmed_settings,
    describe_all,
    endpoints,
    fingerprint_items,
    load_json,
    presence,
    shell_shortcuts,
    value_or_unset,
)
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.host import processes
from ai_footprint.model import (
    BARE_SECURITY,
    BinaryInfo,
    Category,
    Credential,
    Endpoint,
    Extension,
    ProgramStatus,
    Setting,
    StoreKind,
    ToolPresence,
    ToolReport,
)
from ai_footprint.secrets import scan_paths
from ai_footprint.surface import plural
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
        BARE_SECURITY,
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
GROVE_NOTICE_MARKER = "Grove notice config"
NATIVE_HOST = "com.anthropic.claude_code_browser_extension"
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
    Claim("groveConfigCache holds the Grove notice config", GROVE_NOTICE_MARKER),
    Claim("browser native host name", NATIVE_HOST),
    *(Claim(f"log marker {marker}", marker) for marker in LOG_MARKERS),
    Claim("refusal category in transcripts", "apiRefusalCategory"),
)


def collect(ctx: Context, found: ToolPresence | None = None) -> tuple[ToolReport, dict[str, Any]]:
    """Collect Claude Code's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence when already detected, so binaries are probed once.

    Returns:
        The report and a private ``facts`` dict the rule engine uses (never rendered).
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    home = ctx.home
    config = load_json(home / ".claude.json") or {}
    settings = load_json(home / ".claude" / "settings.json") or {}
    found = found or detect(ctx, sized=False)
    report.binaries = found.binaries
    report.installed = found.installed
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
    binary = binary_path(report)
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
            exclude=[home / ".claude" / "plugins"],
        )
    report.programs = [_cvp_status(report)]
    return report, facts


def data_paths(ctx: Context) -> list[Path]:
    """Folders and files Claude Code writes."""
    return [ctx.home / ".claude", ctx.home / ".claude.json"]


def detect(ctx: Context, *, sized: bool = True) -> ToolPresence:
    """Is Claude Code installed, and where?"""
    return presence(NAME, DISPLAY, _binaries(ctx), data_paths(ctx), sized=sized)


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
            ctx, data, store=StoreKind.FILE, location=str(file_path), fingerprints=fingerprints
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
        if cred.store is not StoreKind.ENV:
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
        store=StoreKind.KEYCHAIN,
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
    cred.keychain_written = item.modified
    cred.silent_read_seconds = read.seconds if read.silent else None
    access = data.get("claudeAiOauth", {}).get("accessToken")
    if ctx.live and isinstance(access, str):
        try:
            cred.live_check = live.anthropic_profile(access, version)
        except live.LiveCheckError as exc:
            cred.live_check = f"live check failed: {exc}"
    return cred


def _oauth_credential(
    ctx: Context,
    data: dict[str, Any],
    *,
    store: StoreKind,
    location: str,
    fingerprints: dict[str, str],
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
                store=StoreKind.ENV,
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
                value_or_unset(perms, "defaultMode"),
                f"{BYPASS_MODE} runs every tool without asking",
                concern=perms.get("defaultMode") == BYPASS_MODE,
            ),
            "defaultMode",
        ),
        (
            Setting(
                "skipDangerousModePermissionPrompt",
                value_or_unset(settings, "skipDangerousModePermissionPrompt"),
                "Skips the confirmation shown before --dangerously-skip-permissions",
                concern=bool(settings.get("skipDangerousModePermissionPrompt")),
            ),
            "skipDangerousModePermissionPrompt",
        ),
        (
            Setting(
                "permissions.disableBypassPermissionsMode",
                value_or_unset(perms, "disableBypassPermissionsMode"),
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
                value_or_unset(settings, "enableAllProjectMcpServers"),
                "true starts MCP servers from any repo's .mcp.json without asking",
                concern=bool(settings.get("enableAllProjectMcpServers")),
            ),
            "enableAllProjectMcpServers",
        ),
        (
            Setting(
                "cleanupPeriodDays",
                value_or_unset(settings, "cleanupPeriodDays"),
                "Days transcripts are kept",
                concern=isinstance(cleanup, int) and cleanup > 30,
            ),
            "cleanupPeriodDays",
        ),
    ]
    rows += _settings_env(settings)
    rows += _settings_account(config)
    rows += [(setting, "") for setting in _bypass_evidence(ctx, report)]
    binary = binary_path(report)
    return confirmed_settings(ctx, binary, rows)


def _settings_env(settings: dict[str, Any]) -> list[tuple[Setting, str]]:
    env = settings.get("env", {})
    flags = (
        "DISABLE_TELEMETRY",
        "DISABLE_ERROR_REPORTING",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    )
    return [
        (
            Setting(
                f"env.{flag}", value_or_unset(env, flag), "Turns off a class of outbound traffic"
            ),
            flag,
        )
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
                value_or_unset(config, "claudeInChromeDefaultEnabled"),
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
    return out + shell_shortcuts(ctx, "--dangerously-skip-permissions")


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
        description, components = (
            extensions.plugin_manifest(install) if install else (extensions.NO_MANIFEST, "")
        )
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
                description=description,
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
        for manifest in sorted(hosts.glob(f"{NATIVE_HOST}*.json")) if hosts.is_dir() else []:
            data = load_json(manifest) or {}
            out.append(
                Extension(
                    NAME,
                    "native-host",
                    str(data.get("name", manifest.stem)),
                    ctx.display(str(hosts)),
                    f"{data.get('path', '?')} · origins "
                    f"{', '.join(data.get('allowed_origins', []))}",
                    autostart=False,
                    notes="Chrome launches this program when the extension connects"
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
    logs = [ctx.home / ".claude" / "debug", ctx.home / "Library/Caches/claude-cli-nodejs"]
    return endpoints(ctx, report, ENDPOINTS, logs, markers=ENDPOINT_MARKERS)


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
            "no refusal marker in Claude Code data",
            ["Enrollment is not recorded locally"],
        )
    return ProgramStatus(
        "Anthropic Cyber Verification Program",
        "refusal marker found in Claude Code data",
        [
            f'The marker apiRefusalCategory "cyber" appears {plural(hit.count, "time")} in '
            f"{plural(hit.file_count, 'file')}; enrollment is not recorded locally",
        ],
    )
