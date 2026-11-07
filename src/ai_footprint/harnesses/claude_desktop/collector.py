"""Claude Desktop footprint collector: the app, its Cowork agent mode and Code tab sessions.

Everything lives under ``~/Library/Application Support/Claude`` and ``~/Library/Logs/Claude``.
The claude.ai sign-in is an OAuth token cache in ``config.json``; SSH controller tokens and
sensitive desktop extension settings sit in their own files. Each is Electron safeStorage
ciphertext when the app could reach the Keychain, and is classified by its ``v10`` prefix,
never decrypted. Session records are read for permission modes and flags only; prompts,
titles and message text are never read into the report.
"""

import base64
import binascii
import plistlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, NamedTuple

from ai_footprint import extensions, keychain
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.harnesses import profile
from ai_footprint.harnesses.base import (
    artifacts,
    fingerprint,
    known_endpoints,
    resolve_roots,
)
from ai_footprint.harnesses.common import (
    Claim,
    Context,
    binary_info,
    confirmed_settings,
    endpoints,
    load_json,
)
from ai_footprint.host import processes
from ai_footprint.model import (
    BinaryInfo,
    Credential,
    Extension,
    Setting,
    StoreKind,
    ToolPresence,
    ToolReport,
)
from ai_footprint.secrets import scan_paths
from ai_footprint.text import join, plural

PROFILE = profile.load_beside(__name__)
NAME = PROFILE.name
DISPLAY = PROFILE.display_name
APP_NAME = "Claude.app"
ASAR = "Contents/Resources/app.asar"
SAFE_STORAGE = "Claude Safe Storage"
SAFE_STORAGE_PREFIX = "v10"
ENCRYPTED_SETTING = "__encrypted__:"
TOKEN_KEYS = ("oauth:tokenCacheV2", "oauth:tokenCache")
ALLOWLIST_PREFIX = "dxt:allowlistEnabled:"
CONFIG = "claude_desktop_config.json"
CODE_SESSIONS = "claude-code-sessions"
COWORK_SESSIONS = "local-agent-mode-sessions"
EXTENSIONS_DIR = "Claude Extensions"
EXTENSION_SETTINGS_DIR = "Claude Extensions Settings"
SSH_STATE = "ssh-remote-server-state.json"
REMOTE_STATE = "remote-control-state.json"
BYPASS = "bypassPermissions"
CHROME_SKIP = "skip_all_permission_checks"
SESSIONS_BYPASS = f"sessions with permissionMode={BYPASS}"
SESSIONS_CHROME_SKIP = f"sessions with chromePermissionMode={CHROME_SKIP}"
TASKS_SKIP = "scheduled tasks that skip approval"
EXTRA_CLAIMS: tuple[Claim, ...] = (
    Claim("account token cache key", "oauth:tokenCacheV2"),
    Claim("extension secret prefix", ENCRYPTED_SETTING),
    Claim("SSH controller token store", "ssh-remote-server-state"),
    Claim("Remote Control state file", REMOTE_STATE),
    Claim("session steered by a remote client", "steeredByRemoteClient"),
    Claim("Remote Control off switch", "disableRemoteControl"),
    Claim("Cowork session records", COWORK_SESSIONS),
    Claim("Code session records", CODE_SESSIONS),
    Claim("desktop extension allowlist key", "dxt:allowlistEnabled"),
)


@dataclass(frozen=True)
class Preference:
    """An app preference reported as a setting, and the value that makes it a concern."""

    key: str
    note: str
    concern_when: object = None


PREFERENCES = (
    Preference(
        "bypassPermissionsModeEnabled",
        "Allow bypass permissions mode: Bypass permissions can be chosen in Code sessions",
        concern_when=True,
    ),
    Preference(
        "dispatchCodeTasksPermissionMode",
        "Permission mode of Code sessions that Dispatch starts",
        concern_when=BYPASS,
    ),
    Preference(
        "ccRemoteControlDefaultEnabled",
        "Connect new sessions to Remote Control",
        concern_when=True,
    ),
    Preference(
        "chicagoEnabled",
        "Computer use: Claude clicks and types in the apps you allow, with no sandbox",
        concern_when=True,
    ),
    Preference("coworkBrowserToolsEnabled", "Browser tools in Cowork sessions"),
    Preference("coworkScheduledTasksEnabled", "Cowork scheduled tasks"),
    Preference("ccdScheduledTasksEnabled", "Code scheduled tasks"),
    Preference("keepAwakeEnabled", "Keep computer awake while Claude works"),
)


class Session(NamedTuple):
    """The permission fields of one session record, without its prompts or messages."""

    kind: str
    permission_mode: str
    chrome_mode: str
    steered: bool


class Collected(NamedTuple):
    """What the account notes read besides the report."""

    support: Path
    preferences: dict[str, Any]
    sessions: list[Session]


def roots(ctx: Context) -> dict[str, Path]:
    """Claude Desktop's folders on this machine."""
    return resolve_roots(ctx, PROFILE)


def binaries(ctx: Context) -> list[BinaryInfo]:
    """Each installed app bundle; markers are searched in its JavaScript bundle (app.asar)."""
    found = []
    folders = roots(ctx)
    for folder in (folders["system_apps"], folders["user_apps"]):
        app = folder / APP_NAME
        plist = load_plist(app / "Contents" / "Info.plist")
        if not plist:
            continue
        executable = app / "Contents" / "MacOS" / str(plist.get("CFBundleExecutable", ""))
        version = str(plist.get("CFBundleShortVersionString", ""))
        info = binary_info(ctx.system, str(executable), version=version)
        info.resolved = str(app / ASAR)
        found.append(info)
    return found


def load_plist(path: Path) -> dict[str, Any]:
    """A property list as a dict, or empty when missing or unreadable."""
    try:
        data = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_object(path: Path) -> dict[str, Any]:
    """A JSON object, or empty when the file is missing, malformed or not an object."""
    data = load_json(path)
    return data if isinstance(data, dict) else {}


def collect(ctx: Context, found: ToolPresence) -> tuple[ToolReport, Collected]:
    """Collect Claude Desktop's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence from ``detect``.

    Returns:
        The report, and the data folder, preferences and sessions for the account notes.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    folders = roots(ctx)
    support = folders["support"]
    desktop_config = load_object(support / CONFIG)
    preferences = desktop_config.get("preferences")
    preferences = preferences if isinstance(preferences, dict) else {}
    report.binaries = found.binaries
    report.installed = found.installed
    if not report.installed:
        return report, Collected(support, preferences, [])
    sessions = read_sessions(support)
    tasks = read_tasks(support)
    app_config = load_object(support / "config.json")
    report.artifacts = artifacts(ctx, PROFILE)
    report.credentials = _credentials(ctx, support, app_config)
    report.processes = processes(ctx.system, PROFILE.process)
    report.settings = _settings(ctx, report, preferences, sessions, tasks, app_config)
    report.extensions = (
        _mcp_rows(desktop_config, CONFIG)
        + _mcp_rows(load_object(folders["third_party"] / CONFIG), f"Claude-3p/{CONFIG}")
        + _desktop_extensions(support)
        + [_task_row(task, kind) for kind, task in tasks]
    )
    report.endpoints = endpoints(ctx, report, known_endpoints(PROFILE), [folders["logs"]])
    report.fingerprint = fingerprint(ctx, PROFILE, report)
    report.stats = _stats(support, sessions, tasks, report.extensions)
    if ctx.scan:
        report.secret_scan = scan_paths(
            [
                folders["logs"],
                support / CODE_SESSIONS,
                support / COWORK_SESSIONS,
                support / CONFIG,
                support / EXTENSION_SETTINGS_DIR,
            ],
            workers=ctx.workers,
            display=ctx.display,
            stores=[support / "config.json", support / SSH_STATE, support / EXTENSION_SETTINGS_DIR],
        )
    return report, Collected(support, preferences, sessions)


def _session_files(support: Path, folder: str) -> list[Path]:
    """Session records: ``<folder>/<account>/<organization>/local_<id>.json``."""
    return sorted((support / folder).glob("*/*/local_*.json"))


def read_sessions(support: Path) -> list[Session]:
    """Permission fields of every Code and Cowork session record."""
    out = []
    for kind, folder in (("Code", CODE_SESSIONS), ("Cowork", COWORK_SESSIONS)):
        for path in _session_files(support, folder):
            data = load_object(path)
            out.append(
                Session(
                    kind,
                    str(data.get("permissionMode") or ""),
                    str(data.get("chromePermissionMode") or ""),
                    data.get("steeredByRemoteClient") is True,
                )
            )
    return out


def read_tasks(support: Path) -> list[tuple[str, dict[str, Any]]]:
    """(kind, task) for each local scheduled task Code and Cowork keep."""
    out = []
    for kind, folder in (("Code", CODE_SESSIONS), ("Cowork", COWORK_SESSIONS)):
        for path in sorted((support / folder).glob("*/*/scheduled-tasks.json")):
            tasks = load_object(path).get("scheduledTasks")
            out += [(kind, t) for t in tasks or [] if isinstance(t, dict)]
    return out


def is_ciphertext(value: str) -> bool:
    """Electron safeStorage output on macOS: ``v10`` bytes, raw or base64-encoded."""
    if value.startswith(SAFE_STORAGE_PREFIX):
        return True
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error:
        return False
    return raw.startswith(SAFE_STORAGE_PREFIX.encode())


class KeyLocation:
    """Where the safeStorage key is, looked up in the Keychain once and only when asked."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx

    @cached_property
    def text(self) -> str:
        """The Keychain item holding the key, by its attributes only."""
        item = keychain.find_item(self._ctx.system, SAFE_STORAGE)
        return (
            f"Keychain item '{SAFE_STORAGE}'" if item else "a Keychain item this audit did not find"
        )


def _file_credential(path: Path, provider: str, detail: str, *, encrypted: bool) -> Credential:
    mode = f"file mode {mode_string(path.stat().st_mode)}"
    return Credential(
        NAME,
        provider,
        StoreKind.ENCRYPTED_FILE if encrypted else StoreKind.FILE,
        str(path),
        f"{detail}; {mode}",
        readable_by_others=readable_by_others(path),
    )


def _credentials(ctx: Context, support: Path, app_config: dict[str, Any]) -> list[Credential]:
    """Stored credentials, classified as safeStorage ciphertext or plaintext; none are opened.

    Ciphertext is not inspected: its key is in the Keychain, so the file alone does not yield
    the value, and a fingerprint of ciphertext would match nothing else. No value is read in
    plaintext, so the secret scan gets no fingerprints of current credentials.
    """
    key = KeyLocation(ctx)
    creds = [
        cred
        for cred in (
            _account_token(key, support / "config.json", app_config),
            _ssh_tokens(key, support / SSH_STATE),
        )
        if cred is not None
    ]
    creds += _extension_secrets(key, support)
    return creds


def _account_token(key: KeyLocation, path: Path, app_config: dict[str, Any]) -> Credential | None:
    values = {k: v for k in TOKEN_KEYS if isinstance(v := app_config.get(k), str) and v}
    if not values:
        return None
    plain = [k for k, v in values.items() if not is_ciphertext(v)]
    keys = join(list(values))
    if plain:
        detail = f"{keys} in config.json; {join(plain)} is not safeStorage ciphertext"
    else:
        detail = f"{keys}: Electron safeStorage ciphertext; key in {key.text}"
    return _file_credential(path, "claude.ai account (OAuth)", detail, encrypted=not plain)


def ssh_tokens(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """(tokens, plaintext tokens) of the SSH remote state, keyed by host; values unread."""
    data = load_object(path)
    tokens, plain = data.get("tokens"), data.get("e2ePlaintextTokens")
    return (
        tokens if isinstance(tokens, dict) else {},
        plain if isinstance(plain, dict) else {},
    )


def _ssh_tokens(key: KeyLocation, path: Path) -> Credential | None:
    """Controller tokens for SSH remote machines, one per host, by count only."""
    tokens, plain_store = ssh_tokens(path)
    if not tokens and not plain_store:
        return None
    plain = len(plain_store) + sum(
        1 for v in tokens.values() if not (isinstance(v, str) and is_ciphertext(v))
    )
    hosts = plural(len(tokens) + len(plain_store), "SSH host")
    if plain:
        detail = f"controller tokens for {hosts}; {plain} not safeStorage ciphertext"
    else:
        detail = f"controller tokens for {hosts}; safeStorage ciphertext; key in "
        detail += key.text
    return _file_credential(path, "SSH remote controller tokens", detail, encrypted=not plain)


def _extension_secrets(key: KeyLocation, support: Path) -> list[Credential]:
    """Sensitive desktop extension settings: ciphertext (``__encrypted__:``) or plaintext."""
    out = []
    settings_dir = support / EXTENSION_SETTINGS_DIR
    for path in sorted(settings_dir.glob("*.json")) if settings_dir.is_dir() else []:
        config = load_object(path).get("userConfig")
        if not isinstance(config, dict):
            continue
        manifest = load_object(support / EXTENSIONS_DIR / path.stem / "manifest.json")
        sensitive = _sensitive_keys(manifest)
        encrypted = [k for k, v in config.items() if _encrypted_setting(v)]
        plain = [k for k, v in config.items() if k in sensitive and _plain_value(v)]
        if not encrypted and not plain:
            continue
        detail = f"{plural(len(encrypted), 'encrypted value')}"
        if plain:
            detail += f"; sensitive {join(sorted(plain))} stored as plaintext"
        else:
            detail += f" (safeStorage); key in {key.text}"
        provider = f"desktop extension {_extension_name(manifest, path.stem)}"
        out.append(_file_credential(path, provider, detail, encrypted=not plain))
    return out


def _sensitive_keys(manifest: dict[str, Any]) -> set[str]:
    fields = manifest.get("user_config")
    if not isinstance(fields, dict):
        return set()
    return {k for k, v in fields.items() if isinstance(v, dict) and v.get("sensitive") is True}


def _encrypted_setting(value: object) -> bool:
    if isinstance(value, list):
        return any(_encrypted_setting(v) for v in value)
    return isinstance(value, str) and value.startswith(ENCRYPTED_SETTING)


def _plain_value(value: object) -> bool:
    if isinstance(value, list):
        return any(_plain_value(v) for v in value)
    return isinstance(value, str) and bool(value) and not value.startswith(ENCRYPTED_SETTING)


def _extension_name(manifest: dict[str, Any], fallback: str) -> str:
    return str(manifest.get("display_name") or manifest.get("name") or fallback)


def _settings(
    ctx: Context,
    report: ToolReport,
    preferences: dict[str, Any],
    sessions: list[Session],
    tasks: list[tuple[str, dict[str, Any]]],
    app_config: dict[str, Any],
) -> list[Setting]:
    rows = [(s, "") for s in (*_session_modes(sessions), *_task_modes(tasks)) if s is not None]
    rows += [(_preference(preferences, p), p.key) for p in PREFERENCES]
    allowlist = _allowlist(app_config)
    if allowlist is not None:
        rows.append((allowlist, "dxt:allowlistEnabled"))
    binary = report.binaries[0].resolved if report.binaries else ""
    return confirmed_settings(ctx, binary, rows)


def kinds(sessions: Iterable[Session]) -> str:
    """Sessions counted by kind, e.g. ``2 Code and 1 Cowork``."""
    counts = Counter(s.kind for s in sessions)
    return join([f"{n} {kind}" for kind, n in sorted(counts.items())])


def _session_modes(sessions: list[Session]) -> tuple[Setting | None, Setting | None]:
    """How many sessions run with approval off, for Bash and edits and for Chrome."""
    if not sessions:
        return None, None
    total = plural(len(sessions), "session")
    bypass = [s for s in sessions if s.permission_mode == BYPASS]
    chrome = [s for s in sessions if s.chrome_mode == CHROME_SKIP]
    return (
        Setting(
            SESSIONS_BYPASS,
            f"{len(bypass)} of {total}" + (f" ({kinds(bypass)})" if bypass else ""),
            "Bypass permissions runs commands and edits without approval prompts",
            concern=bool(bypass),
        ),
        Setting(
            SESSIONS_CHROME_SKIP,
            f"{len(chrome)} of {total}" + (f" ({kinds(chrome)})" if chrome else ""),
            "Skip all approvals: Claude in Chrome acts in your signed-in browser and nothing "
            "checks its actions",
            concern=bool(chrome),
        ),
    )


def _skips_approval(task: dict[str, Any]) -> bool:
    return task.get("permissionMode") == BYPASS or task.get("chromePermissionMode") == CHROME_SKIP


def _task_modes(tasks: list[tuple[str, dict[str, Any]]]) -> tuple[Setting | None]:
    if not tasks:
        return (None,)
    skipping = [t for _kind, t in tasks if _skips_approval(t)]
    return (
        Setting(
            TASKS_SKIP,
            f"{len(skipping)} of {plural(len(tasks), 'task')}",
            "Tasks that run on a schedule in Bypass permissions or with Chrome approvals skipped",
            concern=bool(skipping),
        ),
    )


def _preference(preferences: dict[str, Any], pref: Preference) -> Setting:
    value = preferences.get(pref.key)
    if value is None:
        return Setting(f"preferences.{pref.key}", "not set", pref.note)
    text = str(value).lower() if isinstance(value, bool) else str(value)
    return Setting(
        f"preferences.{pref.key}",
        text,
        pref.note,
        concern=pref.concern_when is not None and value == pref.concern_when,
    )


def _allowlist(app_config: dict[str, Any]) -> Setting | None:
    """Whether the organization's desktop extension allowlist is on, per cached organization."""
    flags = [bool(v) for k, v in app_config.items() if k.startswith(ALLOWLIST_PREFIX)]
    if not flags:
        return None
    return Setting(
        "desktop extension allowlist",
        f"on for {sum(flags)} of {plural(len(flags), 'organization')}",
        "With the allowlist off, any extension in the directory can be installed",
    )


def _mcp_rows(config: dict[str, Any], source: str) -> list[Extension]:
    """Local MCP servers from ``mcpServers``; Desktop starts each one when it launches."""
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    return [
        extensions.mcp_row(NAME, name, spec, source)
        for name, spec in servers.items()
        if isinstance(spec, dict) and "extensionId" not in spec
    ]


def _desktop_extensions(support: Path) -> list[Extension]:
    """Installed desktop extensions as the local MCP servers they run.

    Each is a stdio server unpacked under ``Claude Extensions/<id>``; an enabled one starts
    with the app. Its command comes from the manifest's ``mcp_config`` with ``${__dirname}``
    resolved to that folder, so a missing entry point is reported as dangling.
    """
    folder = support / EXTENSIONS_DIR
    out = []
    for install in sorted(p for p in folder.iterdir() if p.is_dir()) if folder.is_dir() else []:
        manifest = load_object(install / "manifest.json")
        settings = load_object(support / EXTENSION_SETTINGS_DIR / f"{install.name}.json")
        row = extensions.mcp_row(
            NAME,
            _extension_name(manifest, install.name),
            _server_command(manifest, install),
            f"desktop extension {install.name}",
            cwd=install,
            enabled=settings.get("isEnabled") is True,
        )
        description = extensions.two_sentences(str(manifest.get("description", "")))
        row.description = description or extensions.NO_MANIFEST
        out.append(row)
    return out


SERVER_COMMANDS = {"node": "node", "python": "python3"}
"""Interpreter for a manifest server ``type`` when it gives no ``mcp_config`` command."""


def _server_command(manifest: dict[str, Any], install: Path) -> dict[str, Any]:
    """``{command, args}`` a desktop extension runs, with ``${__dirname}`` filled in."""
    server = manifest.get("server")
    server = server if isinstance(server, dict) else {}
    config = server.get("mcp_config")
    if isinstance(config, dict) and config.get("command"):
        args = config.get("args") if isinstance(config.get("args"), list) else []
        return {
            "command": _dirname(str(config["command"]), install),
            "args": [_dirname(str(a), install) for a in args],
            "env": config.get("env") if isinstance(config.get("env"), dict) else {},
        }
    entry = str(install / str(server.get("entry_point", "")))
    command = SERVER_COMMANDS.get(str(server.get("type", "")))
    return {"command": command, "args": [entry]} if command else {"command": entry, "args": []}


def _dirname(text: str, install: Path) -> str:
    return text.replace("${__dirname}", str(install))


def _task_row(task: dict[str, Any], kind: str) -> Extension:
    """A local scheduled task: it starts a session with nobody watching while it is enabled."""
    schedule = task.get("cronExpression") or ("one run" if task.get("fireAt") else "")
    modes = [
        f"{key} {task[key]}" for key in ("permissionMode", "chromePermissionMode") if task.get(key)
    ]
    return Extension(
        NAME,
        "scheduled-task",
        str(task.get("displayName") or task.get("id") or "?"),
        f"{kind} scheduled tasks",
        f"cron {schedule}" if task.get("cronExpression") else schedule or "runs when started",
        autostart=task.get("enabled") is True and bool(schedule),
        notes="; ".join(modes),
        description=f"Local {kind} scheduled task",
        identity=f"{kind}:{task.get('id', '')}",
    )


def _stats(
    support: Path,
    sessions: list[Session],
    tasks: list[tuple[str, dict[str, Any]]],
    rows: list[Extension],
) -> dict[str, str]:
    kinds = Counter(s.kind for s in sessions)
    bundled = support / "claude-code"
    return {
        "Cowork sessions": str(kinds["Cowork"]),
        "Code sessions": str(kinds["Code"]),
        "scheduled tasks": str(len(tasks)),
        "MCP servers": str(sum(1 for r in rows if r.kind == "mcp")),
        "desktop extensions": str(sum(1 for r in rows if r.source.startswith("desktop extension"))),
        "bundled Claude Code versions": str(
            sum(1 for p in bundled.iterdir() if p.is_dir()) if bundled.is_dir() else 0
        ),
    }
