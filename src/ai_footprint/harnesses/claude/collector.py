"""Claude Code (``claude``) footprint collector."""

import json
import re
from pathlib import Path
from typing import Any

from ai_footprint import extensions, instructions, keychain, live
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.harnesses import profile
from ai_footprint.harnesses.base import (
    artifacts,
    endpoint_markers,
    fingerprint,
    known_endpoints,
    project_artifacts,
    resolve_roots,
)
from ai_footprint.harnesses.claude import scopes
from ai_footprint.harnesses.common import (
    Claim,
    Context,
    binary_info,
    binary_path,
    confirmed_settings,
    endpoints,
    load_json,
    shell_shortcuts,
    value_or_unset,
)
from ai_footprint.host import processes
from ai_footprint.model import (
    RUNNING_BYPASS,
    BinaryInfo,
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
from ai_footprint.text import plural
from ai_footprint.tokens import inspect_token

PROFILE = profile.load_beside(__name__)
NAME = PROFILE.name
DISPLAY = PROFILE.display_name
KEYCHAIN_SERVICE = "Claude Code-credentials"
CYBER_MARKER = b'"apiRefusalCategory":"cyber"'
BYPASS_MODE = "bypassPermissions"
REVOKE_MARKERS = ("oauth_token_revoke", "continuing with local logout")
OAUTH_URL = "https://platform.claude.com/v1/oauth/token"
TRAINING_MARKERS = ("Help improve our AI models", "extends data retention from 30 days to 5 years")
GROVE_NOTICE_MARKER = "Grove notice config"
NATIVE_HOST = "com.anthropic.claude_code_browser_extension"
LOG_MARKERS = {
    "invalid_grant": "refresh rejected (invalid_grant)",
    "Please run /login": "asked to log in again",
}
EXTRA_CLAIMS: tuple[Claim, ...] = (
    Claim("permissions.defaultMode value", BYPASS_MODE),
    *(Claim("logout revokes the token", marker) for marker in REVOKE_MARKERS),
    Claim("OAuth token endpoint", OAUTH_URL),
    *(Claim("training setting wording", marker) for marker in TRAINING_MARKERS),
    Claim("groveConfigCache holds the Grove notice config", GROVE_NOTICE_MARKER),
    Claim("browser native host name", NATIVE_HOST),
    *(Claim(f"log marker {marker}", marker) for marker in LOG_MARKERS),
    Claim("refusal category in transcripts", "apiRefusalCategory"),
)


def collect(ctx: Context, found: ToolPresence) -> tuple[ToolReport, dict[str, Any]]:
    """Collect Claude Code's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence from ``detect``.

    Returns:
        The report and the parsed ``~/.claude.json``, which the account notes read.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    home = ctx.home
    config = load_json(home / ".claude.json") or {}
    settings = load_json(home / ".claude" / "settings.json") or {}
    report.binaries = found.binaries
    report.installed = found.installed
    if not report.installed:
        return report, config
    projects = scopes.known_projects(config, home)
    managed_folder = resolve_roots(ctx, PROFILE)["managed"]
    managed_settings, managed_extensions = scopes.managed(managed_folder)
    report.artifacts = artifacts(ctx, PROFILE) + project_artifacts(PROFILE, projects)
    report.credentials, known = _credentials(ctx, report.binaries)
    _set_owner(report.credentials, config)
    report.processes = processes(ctx.system, PROFILE.process)
    report.settings = _settings(ctx, settings, config, report)
    report.settings += scopes.project_settings(ctx, projects) + managed_settings
    report.trusted_folders = [
        p for p, v in config.get("projects", {}).items() if v.get("hasTrustDialogAccepted")
    ]
    report.instructions = instructions.collect(
        _instruction_candidates(home, config) + scopes.project_instructions(projects)
    )
    report.extensions = extensions.dedupe(
        _extensions(ctx, settings, config)
        + scopes.project_extensions(ctx, projects)
        + managed_extensions
    )
    report.endpoints = _endpoints(ctx, report)
    report.fingerprint = fingerprint(ctx, PROFILE, report)
    report.stats = _stats(ctx, config)
    if ctx.scan:
        report.secret_scan = scan_paths(
            _scan_roots(home),
            workers=ctx.workers,
            display=ctx.display,
            markers={"cyber": ("Cyber-safeguard refusals", CYBER_MARKER)},
            known=known,
            stores=[home / ".claude" / ".credentials.json"],
            exclude=[home / ".claude" / "plugins"],
        )
    report.programs = [_cvp_status(report)]
    return report, config


def binaries(ctx: Context) -> list[BinaryInfo]:
    """Each claude on PATH; the native installer names the resolved file after its version."""
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
                RUNNING_BYPASS,
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
    out += scopes.hook_rows(settings, "settings.json")
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
            out += scopes.hook_rows(hooks, f"plugin {plugin_id}")
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
    return endpoints(ctx, report, known_endpoints(PROFILE), logs, markers=endpoint_markers(PROFILE))


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
