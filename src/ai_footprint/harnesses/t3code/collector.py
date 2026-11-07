"""T3 Code footprint collector.

T3 Code keeps everything under ``~/.t3`` (``T3CODE_HOME``): an account token, the local
server's signing keys, and one SQLite database holding threads, paired client sessions,
pairing links and scheduled tasks. It drives other harnesses with their own logins, so the
report names which ones it ran. The database is opened read-only and immutable; only
counts, modes and names are read from it, never message text or prompts.
"""

import json
import plistlib
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

from ai_footprint import keychain
from ai_footprint.fsinfo import mode_string, readable_by_others
from ai_footprint.harnesses import profile, registry
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
from ai_footprint.tokens import inspect_token

PROFILE = profile.load_beside(__name__)
NAME = PROFILE.name
DISPLAY = PROFILE.display_name
APP_NAMES = ("T3 Code.app", "T3 Code (Beta).app")
ASAR = "Contents/Resources/app.asar"
SERVICE_LABEL = "com.t3tools.t3code.service"
FULL_ACCESS = "full-access"
THREADS_FULL_ACCESS = "threads with runtime_mode=full-access"
TOKEN_FIELD = "__clerk_client_jwt"  # noqa: S105 - the JSON key holding the token, not a token
LOCAL_CLIENT = "desktop"
ENCRYPTED_PREFIX = "enc:"
RAW_PREFIX = "raw:"
SAFE_STORAGE = "t3code Safe Storage"
EXTRA_CLAIMS: tuple[Claim, ...] = (
    Claim("permission mode value", FULL_ACCESS),
    Claim("paired client sessions table", "auth_sessions"),
    Claim("revoke command", "t3 auth"),
    Claim("settings page for access", "Sharing & access"),
    Claim("background service uninstall", "service uninstall"),
    Claim("safeStorage ciphertext prefix", 'ENCRYPTED_PREFIX = "enc:"'),
)


class Collected(NamedTuple):
    """What the account notes read besides the report."""

    home: Path
    service_env: dict[str, str]


class Session(NamedTuple):
    """One paired client session, without its token."""

    device: str
    method: str
    scopes: list[str]
    last_connected: str


def roots(ctx: Context) -> dict[str, Path]:
    """T3 Code's folders on this machine."""
    return resolve_roots(ctx, PROFILE)


def binaries(ctx: Context) -> list[BinaryInfo]:
    """Each installed app bundle; markers are searched in its JavaScript bundle (app.asar)."""
    found = []
    folders = roots(ctx)
    for folder in (folders["system_apps"], folders["user_apps"]):
        for name in APP_NAMES:
            app = folder / name
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


def collect(ctx: Context, found: ToolPresence) -> tuple[ToolReport, Collected]:
    """Collect T3 Code's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence from ``detect``.

    Returns:
        The report, and the data folder and service environment for the account notes.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    folders = roots(ctx)
    home = folders["home"]
    service_env = read_env_file(home / "service.env")
    report.binaries = found.binaries
    report.installed = found.installed
    if not report.installed:
        return report, Collected(home, service_env)
    db = home / "userdata" / "statev2.sqlite"
    report.artifacts = artifacts(ctx, PROFILE)
    report.credentials, known = _credentials(ctx, home)
    report.processes = processes(ctx.system, PROFILE.process)
    report.settings = _settings(ctx, report, db, service_env)
    report.extensions = _extensions(ctx, folders, db)
    report.endpoints = endpoints(
        ctx, report, known_endpoints(PROFILE), [home / "userdata" / "logs"]
    )
    report.fingerprint = fingerprint(ctx, PROFILE, report)
    report.stats = _stats(home, db)
    if ctx.scan:
        report.secret_scan = scan_paths(
            [home / "userdata", home / "caches", home / "service.env"],
            workers=ctx.workers,
            display=ctx.display,
            known=known,
            stores=[home / "userdata" / "clerk-tokens.json", home / "userdata" / "secrets"],
        )
    return report, Collected(home, service_env)


def read_env_file(path: Path) -> dict[str, str]:
    """``KEY=value`` lines of an env file; comments and malformed lines are skipped."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    out = {}
    for line in lines:
        key, sep, value = line.strip().removeprefix("export ").partition("=")
        if sep and key and not key.startswith("#"):
            out[key.strip()] = value.strip().strip("'\"")
    return out


def query(db: Path, sql: str) -> list[tuple[Any, ...]]:
    """Rows from the state DB opened read-only and immutable, or none if it cannot be read."""
    if not db.is_file():
        return []
    try:
        with sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True, timeout=2) as conn:
            return conn.execute(sql).fetchall()
    except sqlite3.Error:
        return []


def _credentials(ctx: Context, home: Path) -> tuple[list[Credential], dict[str, str]]:
    known: dict[str, str] = {}
    creds = []
    account = home / "userdata" / "clerk-tokens.json"
    value = (load_json(account) or {}).get(TOKEN_FIELD) if account.is_file() else None
    if isinstance(value, str) and value:
        creds.append(_account_token(ctx, account, value, known))
    keys = _server_keys(home / "userdata" / "secrets")
    if keys is not None:
        creds.append(keys)
    return creds, known


def _account_token(ctx: Context, path: Path, value: str, known: dict[str, str]) -> Credential:
    """The T3 account token: Electron safeStorage ciphertext (``enc:``) or plaintext.

    Ciphertext is not inspected: its key is in the Keychain, so the file alone does not
    yield the token, and a fingerprint of ciphertext would match nothing else.
    """
    mode = f"file mode {mode_string(path.stat().st_mode)}"
    cred = Credential(
        NAME,
        "T3 account (Clerk)",
        StoreKind.FILE,
        str(path),
        mode,
        readable_by_others=readable_by_others(path),
    )
    if value.startswith(ENCRYPTED_PREFIX):
        cred.store = StoreKind.ENCRYPTED_FILE
        item = keychain.find_item(ctx.system, SAFE_STORAGE)
        where = (
            f"Keychain item '{SAFE_STORAGE}'" if item else "a Keychain item this audit did not find"
        )
        cred.protection = f"Electron safeStorage ciphertext; key in {where}; {mode}"
        return cred
    token = inspect_token(TOKEN_FIELD, value.removeprefix(RAW_PREFIX), now=ctx.now)
    cred.tokens.append(token)
    known.setdefault(token.fingerprint, "T3 Code account token")
    return cred


def _server_keys(folder: Path) -> Credential | None:
    """The server's signing keys as one credential: one folder, one owner, one rotation."""
    files = sorted(folder.glob("*.bin")) if folder.is_dir() else []
    if not files:
        return None
    modes = sorted({mode_string(f.stat().st_mode) for f in files})
    return Credential(
        NAME,
        "T3 Code server keys",
        StoreKind.FILE,
        str(folder),
        f"{plural(len(files), 'key file')} ({', '.join(f.stem for f in files)}); file mode "
        f"{', '.join(modes)}; folder mode {mode_string(folder.stat().st_mode)}",
        readable_by_others=any(readable_by_others(f) for f in files),
        local_service=True,
    )


def _settings(
    ctx: Context, report: ToolReport, db: Path, service_env: dict[str, str]
) -> list[Setting]:
    rows = [
        (setting, "")
        for setting in (
            _full_access(db),
            _sessions_setting(db),
            _pairing_links(db),
            _peer_links(db),
            _scheduled(db),
            _driven(db),
        )
        if setting is not None
    ]
    for env in PROFILE.env:
        value = ctx.system.env.get(env.name) or service_env.get(env.name)
        where = "this environment" if env.name in ctx.system.env else "~/.t3/service.env"
        rows.append(
            (
                Setting(
                    f"env.{env.name}",
                    value or "not set",
                    f"Set in {where}" if value else "Read by the installed app",
                ),
                env.marker,
            )
        )
    binary = report.binaries[0].resolved if report.binaries else ""
    return confirmed_settings(ctx, binary, rows)


def _full_access(db: Path) -> Setting | None:
    rows = query(
        db,
        "SELECT runtime_mode, count(*) FROM orchestration_v2_projection_threads "
        "WHERE deleted_at IS NULL GROUP BY runtime_mode",
    )
    if not rows:
        return None
    modes = {str(mode): int(count) for mode, count in rows}
    full = modes.get(FULL_ACCESS, 0)
    return Setting(
        THREADS_FULL_ACCESS,
        f"{full} of {plural(sum(modes.values()), 'thread')}",
        "Full access runs commands and edits without approval prompts",
        concern=full > 0,
    )


def paired_sessions(db: Path) -> list[Session]:
    """Client sessions that are neither revoked nor expired."""
    rows = query(
        db,
        "SELECT client_device_type, method, scopes, last_connected_at FROM auth_sessions "
        "WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))",
    )
    out = []
    for device, method, scopes, last in rows:
        try:
            parsed = json.loads(scopes or "[]")
        except ValueError:
            parsed = []
        out.append(Session(str(device or "unknown"), str(method), list(parsed), str(last or "")))
    return out


def _sessions_setting(db: Path) -> Setting | None:
    sessions = paired_sessions(db)
    if not sessions:
        return None
    devices = Counter(s.device for s in sessions)
    remote = sum(n for device, n in devices.items() if device != LOCAL_CLIENT)
    return Setting(
        "paired client sessions",
        join([plural(n, f"{device} client") for device, n in sorted(devices.items())]),
        "Each session can use the server with the scopes it was granted",
        concern=remote > 0,
    )


def _pairing_links(db: Path) -> Setting | None:
    rows = query(
        db,
        "SELECT count(*) FROM auth_pairing_links WHERE consumed_at IS NULL AND revoked_at IS "
        "NULL AND (expires_at IS NULL OR expires_at > datetime('now'))",
    )
    open_links = int(rows[0][0]) if rows else 0
    if not open_links:
        return None
    return Setting(
        "open pairing links",
        str(open_links),
        "Anyone holding an open link can pair a client to this server",
        concern=True,
    )


def _peer_links(db: Path) -> Setting | None:
    rows = query(db, "SELECT count(*) FROM peer_environment_links")
    count = int(rows[0][0]) if rows else 0
    if not count:
        return None
    return Setting("linked environments", str(count), "Other machines this one is linked to")


def _scheduled(db: Path) -> Setting | None:
    rows = query(db, "SELECT count(*), coalesce(sum(enabled), 0) FROM scheduled_tasks")
    if not rows or not rows[0][0]:
        return None
    total, enabled = int(rows[0][0]), int(rows[0][1])
    return Setting(
        "scheduled tasks",
        f"{enabled} of {total} enabled",
        "Prompts that run on a schedule or webhook with nobody watching",
        concern=enabled > 0,
    )


def driven(db: Path) -> Counter[str]:
    """Threads per provider T3 Code ran, by its own provider id."""
    rows = query(
        db,
        "SELECT provider_name, count(*) FROM provider_session_runtime GROUP BY provider_name",
    )
    return Counter({str(provider): int(count) for provider, count in rows})


def driven_name(provider: str) -> str:
    """Display name of the harness behind a T3 provider id, or the id when none matches."""
    harness = registry().get(PROFILE.drives.get(provider, ""))
    return harness.display_name if harness else provider


def _driven(db: Path) -> Setting | None:
    providers = driven(db)
    if not providers:
        return None
    named = [f"{driven_name(p)} ({plural(n, 'thread')})" for p, n in providers.most_common()]
    return Setting(
        "agents driven",
        join(named),
        "T3 Code runs these harnesses with their own stored logins",
    )


def _extensions(ctx: Context, folders: dict[str, Path], db: Path) -> list[Extension]:
    out = []
    plist_path = folders["launch_agents"] / f"{SERVICE_LABEL}.plist"
    plist = load_plist(plist_path)
    if plist:
        program = " ".join(
            [str(plist.get("Program", "")), *map(str, plist.get("ProgramArguments", []))]
        ).strip()
        out.append(
            Extension(
                NAME,
                "service",
                SERVICE_LABEL,
                ctx.display(str(plist_path)),
                program,
                autostart=bool(plist.get("RunAtLoad") or plist.get("KeepAlive")),
                description="Starts the T3 server at login",
                identity=str(plist_path),
            )
        )
    for title, enabled in query(db, "SELECT title, enabled FROM scheduled_tasks ORDER BY title"):
        out.append(
            Extension(
                NAME,
                "scheduled-task",
                str(title),
                "statev2.sqlite",
                "prompt run on a schedule or webhook",
                autostart=bool(enabled),
                description="Scheduled T3 Code task",
            )
        )
    return out


def _stats(home: Path, db: Path) -> dict[str, str]:
    def count(sql: str) -> str:
        rows = query(db, sql)
        return str(rows[0][0]) if rows else "?"

    worktrees = home / "worktrees"
    return {
        "threads": count(
            "SELECT count(*) FROM orchestration_v2_projection_threads WHERE deleted_at IS NULL"
        ),
        "messages": count("SELECT count(*) FROM orchestration_v2_projection_messages"),
        "projects": count("SELECT count(*) FROM projection_projects WHERE deleted_at IS NULL"),
        "worktrees": str(len(list(worktrees.iterdir()))) if worktrees.is_dir() else "0",
    }
