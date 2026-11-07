"""Claude Code account notes: data use, token revocation, and signs of use elsewhere."""

from typing import Any

from ai_footprint.harnesses.account_notes import log_markers, marker_text, note
from ai_footprint.harnesses.claude import collector as claude_cli
from ai_footprint.harnesses.common import Context, binary_path
from ai_footprint.model import AccountNote, StoreKind, ToolReport
from ai_footprint.tokens import iso_time


def data_notes(ctx: Context, config: dict[str, Any], binary: str) -> list[AccountNote]:
    """What the config and binary say about training, connectors and GitHub."""
    notes = []
    account = config.get("oauthAccount", {}).get("accountUuid", "")
    grove = (config.get("groveConfigCache") or {}).get(account)
    markers = [*claude_cli.TRAINING_MARKERS, claude_cli.GROVE_NOTICE_MARKER]
    found = ctx.binary_has(binary, markers) if binary else {}
    if all(found.get(marker) for marker in claude_cli.TRAINING_MARKERS):
        notes.append(
            note(
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
            note(
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
            note(
                "data",
                f"GitHub connection for Claude Code on the web: {github}.",
                "~/.claude.json githubWebConnectionStatusCache",
                concern=github == "connected",
            )
        )
    connectors = config.get("claudeAiMcpEverConnected", [])
    if connectors:
        notes.append(
            note(
                "data",
                f"claude.ai connectors used from this CLI: {', '.join(connectors)}.",
                "~/.claude.json claudeAiMcpEverConnected",
                concern=True,
            )
        )
    return notes


def revoke_notes(ctx: Context, report: ToolReport, binary: str) -> list[AccountNote]:
    """Whether logging out revokes the token, and when the refresh token expires."""
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
    notes = [note("revoke", text, "markers in the installed claude binary")]
    if expiry:
        notes.append(
            note(
                "revoke",
                f"The stored refresh token's recorded expiry is {expiry[:10]}.",
                f"Keychain item {claude_cli.KEYCHAIN_SERVICE}",
            )
        )
    return notes


def detect_notes(ctx: Context, report: ToolReport, config: dict[str, Any]) -> list[AccountNote]:
    """Local traces of token use: refresh times, profile fetches, auth events."""
    notes = []
    for cred in report.credentials:
        if cred.store is StoreKind.KEYCHAIN and cred.keychain_written:
            written = cred.keychain_written
            notes.append(
                note(
                    "detect",
                    f"Last token refresh written to the Keychain: {written}.",
                    "Keychain item modification time",
                )
            )
    fetched = config.get("oauthAccount", {}).get("profileFetchedAt")
    if fetched:
        notes.append(
            note(
                "detect",
                f"Account profile last fetched {iso_time(fetched)}.",
                "~/.claude.json oauthAccount.profileFetchedAt",
            )
        )
    markers = log_markers([ctx.home / ".claude" / "debug"], claude_cli.LOG_MARKERS)
    if markers:
        notes.append(
            note(
                "detect",
                f"Auth events in local debug logs: {marker_text(markers, claude_cli.LOG_MARKERS)}.",
                "~/.claude/debug",
            )
        )
    notes.append(
        note(
            "detect",
            "Nothing on disk records where else the token is used. Check "
            "active sessions at claude.ai and treat an unexpected login prompt as a "
            "signal.",
            "manual check",
        )
    )
    return notes


def notes(ctx: Context, report: ToolReport, config: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for Claude Code."""
    binary = binary_path(report)
    return (
        data_notes(ctx, config, binary)
        + revoke_notes(ctx, report, binary)
        + detect_notes(ctx, report, config)
    )
