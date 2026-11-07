"""Claude Desktop account notes: Remote Control, remote steering, SSH hosts, how to turn off."""

from typing import Any

from ai_footprint.harnesses.account_notes import note
from ai_footprint.harnesses.claude_desktop import collector as desktop
from ai_footprint.harnesses.common import Context, binary_path
from ai_footprint.model import REMOTE_CONTROL, AccountNote, ToolReport
from ai_footprint.text import join, plural

SERVE_OFF = "off"
SERVE_ON = "on"


def _identities(collected: desktop.Collected) -> list[dict[str, Any]]:
    state = desktop.load_object(collected.support / desktop.REMOTE_STATE)
    identities = state.get("identities")
    if not isinstance(identities, dict):
        return []
    return [i for i in identities.values() if isinstance(i, dict)]


def remote_control_notes(collected: desktop.Collected) -> list[AccountNote]:
    """Environments this machine registered for Remote Control, and auto-connect."""
    notes = []
    identities = _identities(collected)
    folders = sum(len(i.get("folders") or {}) for i in identities)
    serving = [str(i.get("serve", "")) for i in identities]
    if folders or SERVE_ON in serving:
        notes.append(
            note(
                "detect",
                f"Remote Control has {plural(folders, 'folder')} registered for "
                f"{plural(len(identities), 'identity')} (serve: {join(sorted(set(serving)))}); "
                "sessions there can be steered from other devices.",
                f"~/Library/Application Support/Claude/{desktop.REMOTE_STATE}",
                concern=any(s != SERVE_OFF for s in serving),
                signal=REMOTE_CONTROL,
            )
        )
    if collected.preferences.get("ccRemoteControlDefaultEnabled") is True:
        notes.append(
            note(
                "detect",
                "Connect new sessions to Remote Control is on: every new Code session can be "
                "steered from other devices signed in to the account.",
                f"~/Library/Application Support/Claude/{desktop.CONFIG} preferences",
                concern=True,
                signal=REMOTE_CONTROL,
            )
        )
    return notes


def steered_notes(collected: desktop.Collected) -> list[AccountNote]:
    """Sessions a remote client sent messages to."""
    steered = [s for s in collected.sessions if s.steered]
    if not steered:
        return []
    return [
        note(
            "detect",
            f"{plural(len(steered), 'session')} ({desktop.kinds(steered)}) took input from a "
            "Remote Control client on another device.",
            "session records (steeredByRemoteClient)",
            concern=True,
            signal=REMOTE_CONTROL,
        )
    ]


def ssh_notes(collected: desktop.Collected) -> list[AccountNote]:
    """SSH remote machines this app holds a controller token for."""
    tokens, plain = desktop.ssh_tokens(collected.support / desktop.SSH_STATE)
    hosts = len(tokens) + len(plain)
    if not hosts:
        return []
    return [
        note(
            "detect",
            f"Claude Desktop holds controller tokens for {plural(hosts, 'SSH remote machine')}; "
            "whoever holds them can drive the Claude Code helper on those machines.",
            f"~/Library/Application Support/Claude/{desktop.SSH_STATE}",
            concern=True,
            signal=REMOTE_CONTROL,
        )
    ]


def revoke_notes(ctx: Context, report: ToolReport) -> list[AccountNote]:
    """Where Remote Control is turned off for every session on this machine."""
    binary = binary_path(report)
    found = ctx.binary_has(binary, ["disableRemoteControl"]) if binary else {}
    if not found.get("disableRemoteControl"):
        return []
    return [
        note(
            "revoke",
            "disableRemoteControl: true in ~/.claude/settings.json stops every session on this "
            "computer, Desktop and CLI, from connecting to Remote Control.",
            "markers in the installed app",
        )
    ]


def notes(ctx: Context, report: ToolReport, collected: desktop.Collected) -> list[AccountNote]:
    """Account evidence for Claude Desktop."""
    return (
        revoke_notes(ctx, report)
        + remote_control_notes(collected)
        + steered_notes(collected)
        + ssh_notes(collected)
    )
