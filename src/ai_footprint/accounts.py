"""Provider-account evidence available on disk: data use, revocation, and detection.

Account settings live on the provider's servers, but each tool caches some of them locally,
and the installed binary shows whether logging out revokes a token. These functions report
only what is on disk or in the binary, and say so when the answer needs the web settings.
Every binary-derived statement is gated on markers registered in the collector's ``CLAIMS``.
"""

import datetime
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ai_footprint.collectors import claude as claude_cli
from ai_footprint.collectors import codex as codex_cli
from ai_footprint.collectors.common import Context, load_json
from ai_footprint.model import AccountNote, ToolReport
from ai_footprint.surface import when
from ai_footprint.tokens import iso_time

MAX_LOG_BYTES = 400 * 1024 * 1024


def _note(topic: str, text: str, source: str, *, concern: bool = False) -> AccountNote:
    return AccountNote(topic=topic, text=when(text), source=source, concern=concern)


def _files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from (p for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def log_markers(paths: Iterable[Path], markers: Iterable[str]) -> dict[str, tuple[int, str]]:
    """Count auth-event markers in log files: ``{marker: (count, newest file date)}``."""
    wanted = list(markers)
    found: dict[str, tuple[int, float]] = {}
    budget = MAX_LOG_BYTES
    for path in _files(paths):
        if budget <= 0:
            break
        try:
            data = path.read_bytes()[:budget]
        except OSError:
            continue
        budget -= len(data)
        for marker in wanted:
            count = data.count(marker.encode())
            if count:
                total, newest = found.get(marker, (0, 0.0))
                found[marker] = (total + count, max(newest, path.stat().st_mtime))
    return {m: (n, iso_time(t)[:10]) for m, (n, t) in found.items()}


def _marker_text(markers: dict[str, tuple[int, str]], labels: Mapping[str, str]) -> str:
    return "; ".join(f"{labels[m]}: {n} times (latest {d})" for m, (n, d) in markers.items())


# --- Claude Code -------------------------------------------------------------------------------


def _claude_data(ctx: Context, config: dict[str, Any], binary: str) -> list[AccountNote]:
    notes = []
    account = config.get("oauthAccount", {}).get("accountUuid", "")
    grove = (config.get("groveConfigCache") or {}).get(account)
    markers = [*claude_cli.TRAINING_MARKERS, claude_cli.GROVE_NOTICE_MARKER]
    found = ctx.binary_has(binary, markers) if binary else {}
    if all(found.get(marker) for marker in claude_cli.TRAINING_MARKERS):
        notes.append(
            _note(
                "data",
                "Claude Code's own text says turning on 'Help improve our AI models' extends "
                "data retention from 30 days to 5 years.",
                "markers in the installed claude binary",
            )
        )
    if isinstance(grove, dict) and found.get(claude_cli.GROVE_NOTICE_MARKER):
        when = iso_time(grove.get("timestamp"))[:10]
        state = "true" if grove.get("grove_enabled") else "false"
        notes.append(
            _note(
                "data",
                f"The cached Grove notice config has grove_enabled {state} (cached {when}); "
                "your training choice itself is not cached on disk, so check "
                "claude.ai/settings/data-privacy-controls.",
                "~/.claude.json groveConfigCache",
            )
        )
    github = (config.get("githubWebConnectionStatusCache") or {}).get("status")
    if github:
        notes.append(
            _note(
                "data",
                f"GitHub connection for Claude Code on the web: {github}.",
                "~/.claude.json githubWebConnectionStatusCache",
                concern=github == "connected",
            )
        )
    connectors = config.get("claudeAiMcpEverConnected", [])
    if connectors:
        notes.append(
            _note(
                "data",
                f"claude.ai connectors used from this CLI: {', '.join(connectors)}.",
                "~/.claude.json claudeAiMcpEverConnected",
                concern=True,
            )
        )
    return notes


def _claude_revoke(ctx: Context, report: ToolReport, binary: str) -> list[AccountNote]:
    markers = [*claude_cli.REVOKE_MARKERS, claude_cli.OAUTH_URL]
    found = ctx.binary_has(binary, markers) if binary else {}
    expiry = next(
        (
            t.expires_at
            for c in report.credentials
            for t in c.tokens
            if t.field == "refreshToken" and t.expires_at
        ),
        "",
    )
    if all(found.get(m) for m in claude_cli.REVOKE_MARKERS):
        endpoint = (
            f"{claude_cli.OAUTH_URL}/revoke"
            if found.get(claude_cli.OAUTH_URL)
            else "the OAuth token endpoint's /revoke path"
        )
        text = (
            f"`claude /logout` posts the refresh token to {endpoint}, and clears the local "
            "copy even if that request fails."
        )
    else:
        text = (
            "No token-revocation marker was found in the installed Claude Code binary, so "
            "this audit cannot say whether `claude /logout` revokes the token at Anthropic."
        )
    notes = [_note("revoke", text, "markers in the installed claude binary")]
    if expiry:
        notes.append(
            _note(
                "revoke",
                f"The stored refresh token's recorded expiry is {expiry[:10]}.",
                f"Keychain item {claude_cli.KEYCHAIN_SERVICE}",
            )
        )
    return notes


def _claude_detect(ctx: Context, report: ToolReport, config: dict[str, Any]) -> list[AccountNote]:
    notes = []
    for cred in report.credentials:
        if cred.store == "macOS Keychain" and "last written " in cred.protection:
            written = cred.protection.split("last written ", 1)[1].split(";", 1)[0]
            notes.append(
                _note(
                    "detect",
                    f"Last token refresh written to the Keychain: {written}.",
                    "Keychain item modification time",
                )
            )
    fetched = config.get("oauthAccount", {}).get("profileFetchedAt")
    if fetched:
        notes.append(
            _note(
                "detect",
                f"Account profile last fetched {iso_time(fetched)}.",
                "~/.claude.json oauthAccount.profileFetchedAt",
            )
        )
    markers = log_markers([ctx.home / ".claude" / "debug"], claude_cli.LOG_MARKERS)
    if markers:
        notes.append(
            _note(
                "detect",
                "Auth events in local debug logs: "
                f"{_marker_text(markers, claude_cli.LOG_MARKERS)}.",
                "~/.claude/debug",
            )
        )
    notes.append(
        _note(
            "detect",
            "Nothing on disk records where else the token is used. Check "
            "active sessions at claude.ai and treat an unexpected login prompt as a "
            "signal.",
            "manual check",
        )
    )
    return notes


def claude(ctx: Context, report: ToolReport, facts: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for Claude Code."""
    binary = report.binaries[0].resolved if report.binaries else ""
    config = facts.get("config", {})
    return (
        _claude_data(ctx, config, binary)
        + _claude_revoke(ctx, report, binary)
        + _claude_detect(ctx, report, config)
    )


# --- Codex CLI ---------------------------------------------------------------------------------


def _claims(report: ToolReport, field: str) -> dict[str, str]:
    for cred in report.credentials:
        for token in cred.tokens:
            if token.field == field:
                return token.claims
    return {}


def _codex_data(report: ToolReport, root: Path, config: dict[str, Any]) -> list[AccountNote]:
    notes = []
    groups = _claims(report, "id_token").get("https://api.openai.com/auth.groups", "")
    if groups:
        notes.append(
            _note(
                "data",
                f"Your OpenAI id_token lists the group(s) {groups}. Data controls for the "
                "account are at platform.openai.com and chatgpt.com.",
                "~/.codex/auth.json id_token claims",
            )
        )
    state = load_json(root / ".codex-global-state.json") or {}
    atoms = state.get("electron-persisted-atom-state", {})
    cloud = atoms.get("codexCloudAccess")
    repos = sorted({k.split("codex:cloud:", 1)[1] for k in atoms if "codex:cloud:" in k})
    if cloud or repos:
        notes.append(
            _note(
                "data",
                f"Codex cloud access: {cloud or 'unknown'}; cloud-linked repos: "
                f"{', '.join(repos) or 'none'}.",
                "~/.codex/.codex-global-state.json",
                concern=bool(repos),
            )
        )
    history = config.get("history") or {}
    if "persistence" in history:
        notes.append(
            _note(
                "data",
                f"Local prompt history: history.persistence = {history['persistence']}.",
                "~/.codex/config.toml",
            )
        )
    return notes


def _codex_revoke(ctx: Context, report: ToolReport, binary: str) -> list[AccountNote]:
    markers = [*codex_cli.REVOKE_MARKERS, codex_cli.REMOTE_REVOKE_MARKER]
    found = ctx.binary_has(binary, markers) if binary else {}
    if all(found.get(m) for m in codex_cli.REVOKE_MARKERS):
        text = (
            "The installed Codex revokes its auth tokens during `codex logout` "
            "(login/src/auth/revoke.rs)."
        )
    else:
        text = (
            "No token-revocation marker was found in the installed Codex binary, so this "
            "audit cannot say whether `codex logout` revokes anything at OpenAI."
        )
    if found.get(codex_cli.REMOTE_REVOKE_MARKER):
        text += " The binary also carries a remote-control device revocation call."
    notes = [_note("revoke", text, "markers in the installed codex binary")]
    expiry = next(
        (t.expires_at for c in report.credentials for t in c.tokens if t.field == "access_token"),
        "",
    )
    if expiry:
        notes.append(
            _note(
                "revoke",
                f"The access token is a JWT whose exp claim is {expiry}.",
                "~/.codex/auth.json access_token",
            )
        )
    notes.append(
        _note(
            "revoke",
            "To end sessions elsewhere, sign out of other devices in ChatGPT security settings.",
            "manual check",
        )
    )
    return notes


def _codex_remote(config: dict[str, Any], root: Path) -> list[AccountNote]:
    """Remote-control state as recorded: the desktop app's flag, enrollments and config."""
    notes = []
    state = load_json(root / ".codex-global-state.json") or {}
    if state.get("codex-mobile-has-connected-device"):
        notes.append(
            _note(
                "detect",
                "The Codex desktop app's state records codex-mobile-has-connected-device = true.",
                "~/.codex/.codex-global-state.json",
            )
        )
    for row in codex_cli.remote_control_enrollments(root):
        state_word = "enabled" if row.enabled else "not enabled"
        notes.append(
            _note(
                "detect",
                f"Remote control is {state_word} for server {row.server} through client "
                f"{row.client} (updated {row.updated}). Which devices are paired now is not "
                "recorded locally.",
                "~/.codex/state_5.sqlite remote_control_enrollments",
                concern=row.enabled,
            )
        )
    desktop = config.get("desktop") or {}
    if "keepRemoteControlAwakeWhilePluggedIn" in desktop:
        notes.append(
            _note(
                "detect",
                "desktop.keepRemoteControlAwakeWhilePluggedIn = "
                f"{str(desktop['keepRemoteControlAwakeWhilePluggedIn']).lower()}.",
                "~/.codex/config.toml",
            )
        )
    return notes


def _codex_detect(ctx: Context, report: ToolReport, root: Path, binary: str) -> list[AccountNote]:
    claims = _claims(report, "id_token")
    notes = []
    auth_time = claims.get("auth_time")
    if auth_time and auth_time.isdigit():
        methods = ", ".join(
            m.strip().removeprefix("urn:openai:amr:")
            for m in claims.get("amr", "").split(",")
            if m.strip() and m.strip() != "pop"
        )
        mfa = _claims(report, "access_token").get("https://api.openai.com/mfa.required", "")
        notes.append(
            _note(
                "detect",
                f"Last interactive sign-in {iso_time(int(auth_time))} via "
                f"{methods or 'unknown method'}; MFA required: {mfa or 'unknown'}.",
                "~/.codex/auth.json id_token claims",
            )
        )
    auth = load_json(root / "auth.json") or {}
    if auth.get("last_refresh"):
        notes.append(
            _note(
                "detect",
                f"Tokens last refreshed {auth['last_refresh'][:19]} UTC.",
                "~/.codex/auth.json last_refresh",
            )
        )
    known = ctx.binary_has(binary, list(codex_cli.LOG_MARKERS)) if binary else {}
    labels = {m: label for m, label in codex_cli.LOG_MARKERS.items() if known.get(m)}
    markers = log_markers([root / "log", root / "logs_2.sqlite"], labels)
    if markers:
        notes.append(
            _note(
                "detect",
                f"Auth events in local logs: {_marker_text(markers, labels)}.",
                "~/.codex/log, logs_2.sqlite",
            )
        )
    return notes


def codex(ctx: Context, report: ToolReport, facts: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for Codex CLI."""
    root = Path(facts.get("root", ctx.home / ".codex"))
    binary = report.binaries[0].resolved if report.binaries else ""
    config = facts.get("config", {})
    return (
        _codex_data(report, root, config)
        + _codex_revoke(ctx, report, binary)
        + _codex_detect(ctx, report, root, binary)
        + _codex_remote(config, root)
    )


# --- OpenCode ----------------------------------------------------------------------------------


def opencode(ctx: Context, report: ToolReport, facts: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for OpenCode, whose credentials belong to other providers."""
    del ctx
    config = facts.get("config", {})
    share = config.get("share", "not set")
    providers = sorted({c.provider for c in report.credentials if "local server" not in c.provider})
    notes = [
        _note(
            "data",
            f"Session sharing: share = {share}. Each provider's own data policy applies to "
            f"what OpenCode sends: {', '.join(providers) or 'none'}.",
            "opencode config",
            concern=share == "auto",
        ),
        _note(
            "revoke",
            "Whether `opencode auth logout` revokes anything at the provider is not something "
            "this audit can observe. Revoke at each provider: sign out of all sessions at "
            "claude.ai and in ChatGPT security settings, and delete API keys in each "
            "provider's console.",
            "OpenCode credential model",
        ),
    ]
    now = datetime.datetime.now(datetime.UTC).isoformat()
    idle = [
        f"{cred.provider} (last refreshed before {token.expires_at[:10]})"
        for cred in report.credentials
        for token in cred.tokens
        if token.field == "access" and token.expires_at and token.expires_at < now
    ]
    if idle:
        notes.append(
            _note(
                "detect",
                "Stored logins that OpenCode has not refreshed recently: "
                f"{', '.join(sorted(set(idle)))}. Their refresh tokens have no recorded "
                "expiry, and nothing local records use elsewhere.",
                "access-token expiry fields",
                concern=True,
            )
        )
    return notes


def pi(ctx: Context, report: ToolReport, facts: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for pi: analytics settings, sharing, and whether logout revokes."""
    settings = facts.get("settings", {})
    binary = report.binaries[0].resolved if report.binaries else ""
    viewer = ctx.binary_has(binary, ["https://pi.dev/session/"]) if binary else {}
    notes = [
        _note(
            "data",
            f"enableAnalytics = {settings.get('enableAnalytics', 'not set')}; "
            f"enableInstallTelemetry = {settings.get('enableInstallTelemetry', 'not set')}.",
            "~/.pi/agent/settings.json",
            concern=bool(settings.get("enableAnalytics")),
        )
    ]
    if viewer.get("https://pi.dev/session/"):
        notes.append(
            _note(
                "data",
                "/share uploads a session to a gist and links the viewer at "
                "https://pi.dev/session/ (PI_SHARE_VIEWER_URL overrides the viewer).",
                "pi binary",
            )
        )
    notes.append(
        _note(
            "revoke",
            "Whether pi's /logout revokes anything at the provider is not something this audit "
            "can observe. Revoke at each provider: sign out of all devices in ChatGPT security "
            "settings and delete API keys in each provider's console.",
            "pi credential model",
        )
    )
    now = datetime.datetime.now(datetime.UTC).isoformat()
    idle = sorted(
        {
            f"{cred.provider} (last refreshed before {token.expires_at[:10]})"
            for cred in report.credentials
            for token in cred.tokens
            if token.field == "access" and token.expires_at and token.expires_at < now
        }
    )
    if idle:
        notes.append(
            _note(
                "detect",
                f"Stored logins that pi has not refreshed recently: {', '.join(idle)}. Their "
                "refresh tokens have no recorded expiry, and nothing local records use elsewhere.",
                "access-token expiry fields",
                concern=True,
            )
        )
    return notes


COLLECTORS = {"claude": claude, "codex": codex, "opencode": opencode, "pi": pi}


def collect(ctx: Context, report: ToolReport, facts: dict[str, Any]) -> list[AccountNote]:
    """Account notes for a tool, or none when the tool is not installed."""
    if not report.installed or report.name not in COLLECTORS:
        return []
    return COLLECTORS[report.name](ctx, report, facts)
