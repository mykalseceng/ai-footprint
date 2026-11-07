"""Codex CLI account notes: data use, token revocation, remote control, signs of use."""

from pathlib import Path
from typing import Any

from ai_footprint.harnesses.account_notes import log_markers, marker_text, note, token_claims
from ai_footprint.harnesses.codex import collector as codex_cli
from ai_footprint.harnesses.common import Context, binary_path, load_json
from ai_footprint.model import REMOTE_CONTROL, AccountNote, ToolReport
from ai_footprint.tokens import iso_time


def data_notes(report: ToolReport, root: Path, config: dict[str, Any]) -> list[AccountNote]:
    """Account groups, cloud access and prompt-history settings."""
    notes = []
    groups = token_claims(report, "id_token").get("https://api.openai.com/auth.groups", "")
    if groups:
        notes.append(
            note(
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
            note(
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
            note(
                "data",
                f"Local prompt history: history.persistence = {history['persistence']}.",
                "~/.codex/config.toml",
            )
        )
    return notes


def revoke_notes(ctx: Context, report: ToolReport, binary: str) -> list[AccountNote]:
    """Whether logging out revokes tokens, and when the access token expires."""
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
    notes = [note("revoke", text, "markers in the installed codex binary")]
    expiry = next(
        (t.expires_at for c in report.credentials for t in c.tokens if t.field == "access_token"),
        "",
    )
    if expiry:
        notes.append(
            note(
                "revoke",
                f"The access token is a JWT whose exp claim is {expiry}.",
                "~/.codex/auth.json access_token",
            )
        )
    notes.append(
        note(
            "revoke",
            "To end sessions elsewhere, sign out of other devices in ChatGPT security settings.",
            "manual check",
        )
    )
    return notes


def remote_notes(config: dict[str, Any], root: Path) -> list[AccountNote]:
    """Remote-control state as recorded: the desktop app's flag, enrollments and config."""
    notes = []
    state = load_json(root / ".codex-global-state.json") or {}
    if state.get("codex-mobile-has-connected-device"):
        notes.append(
            note(
                "detect",
                "The Codex desktop app's state records codex-mobile-has-connected-device = true.",
                "~/.codex/.codex-global-state.json",
            )
        )
    for row in codex_cli.remote_control_enrollments(root):
        state_word = "enabled" if row.enabled else "not enabled"
        relay = row.relay or "an unrecorded host"
        notes.append(
            note(
                "detect",
                f"Codex records remote control {state_word} for this machine (server "
                f"{row.server}) through {row.client}, relayed by {relay} (updated "
                f"{row.updated}). Which devices are paired now is not recorded locally.",
                "~/.codex/state_5.sqlite remote_control_enrollments",
                concern=row.enabled,
                signal=REMOTE_CONTROL,
            )
        )
    desktop = config.get("desktop") or {}
    if "keepRemoteControlAwakeWhilePluggedIn" in desktop:
        notes.append(
            note(
                "detect",
                "desktop.keepRemoteControlAwakeWhilePluggedIn = "
                f"{str(desktop['keepRemoteControlAwakeWhilePluggedIn']).lower()}.",
                "~/.codex/config.toml",
            )
        )
    return notes


def detect_notes(ctx: Context, report: ToolReport, root: Path, binary: str) -> list[AccountNote]:
    """Sign-in method, last refresh and auth events in local logs."""
    claims = token_claims(report, "id_token")
    notes = []
    auth_time = claims.get("auth_time")
    if auth_time and auth_time.isdigit():
        methods = ", ".join(
            m.strip().removeprefix("urn:openai:amr:")
            for m in claims.get("amr", "").split(",")
            if m.strip() and m.strip() != "pop"
        )
        mfa = token_claims(report, "access_token").get("https://api.openai.com/mfa.required", "")
        notes.append(
            note(
                "detect",
                f"Last interactive sign-in {iso_time(int(auth_time))} via "
                f"{methods or 'unknown method'}; MFA required: {mfa or 'unknown'}.",
                "~/.codex/auth.json id_token claims",
            )
        )
    auth = load_json(root / "auth.json") or {}
    if auth.get("last_refresh"):
        notes.append(
            note(
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
            note(
                "detect",
                f"Auth events in local logs: {marker_text(markers, labels)}.",
                "~/.codex/log, logs_2.sqlite",
            )
        )
    return notes


def notes(
    ctx: Context, report: ToolReport, root: Path, config: dict[str, Any]
) -> list[AccountNote]:
    """Account evidence for Codex CLI."""
    binary = binary_path(report)
    return (
        data_notes(report, root, config)
        + revoke_notes(ctx, report, binary)
        + detect_notes(ctx, report, root, binary)
        + remote_notes(config, root)
    )
