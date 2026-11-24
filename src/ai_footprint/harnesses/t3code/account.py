"""T3 Code account notes: usage data, paired clients, and how to revoke access."""

from ai_footprint.harnesses import telemetry
from ai_footprint.harnesses.account_notes import note
from ai_footprint.harnesses.common import Context, binary_path
from ai_footprint.harnesses.t3code import collector as t3
from ai_footprint.model import REMOTE_CONTROL, AccountNote, ToolReport
from ai_footprint.text import join, plural

POWERFUL_SCOPES = ("terminal:operate", "filesystem:write", "access:write")


def detect_notes(report: ToolReport, collected: t3.Collected) -> list[AccountNote]:
    """Paired client sessions, with the scopes that let a client run commands or edit files."""
    db = collected.home / "userdata" / "statev2.sqlite"
    notes = []
    for session in t3.paired_sessions(db):
        powerful = [s for s in POWERFUL_SCOPES if s in session.scopes]
        remote = session.device != t3.LOCAL_CLIENT
        notes.append(
            note(
                "detect",
                f"Paired {session.device} client ({session.method}) with "
                f"{plural(len(session.scopes), 'scope')}"
                + (f", including {join(powerful)}" if powerful else "")
                + (f"; last connected {session.last_connected}" if session.last_connected else "")
                + ".",
                "~/.t3/userdata/statev2.sqlite auth_sessions",
                concern=remote,
                signal=REMOTE_CONTROL,
            )
        )
    del report
    return notes


def revoke_notes(ctx: Context, report: ToolReport) -> list[AccountNote]:
    """Where paired clients and the account token are revoked."""
    binary = binary_path(report)
    found = ctx.binary_has(binary, ["t3 auth", "Sharing & access"]) if binary else {}
    notes = []
    if found.get("t3 auth") and found.get("Sharing & access"):
        notes.append(
            note(
                "revoke",
                "Paired clients are revoked in Settings → Sharing & access or with `t3 auth`; "
                "revoking a client does not sign the T3 account out.",
                "markers in the installed app",
            )
        )
    expiry = next((t.expires_at for c in report.credentials for t in c.tokens if t.expires_at), "")
    if expiry:
        notes.append(
            note(
                "revoke",
                f"The stored T3 account token's exp claim is {expiry}.",
                "~/.t3/userdata/clerk-tokens.json",
            )
        )
    return notes


def notes(ctx: Context, report: ToolReport, collected: t3.Collected) -> list[AccountNote]:
    """Account evidence for T3 Code."""
    sources = [
        ("the environment", ctx.system.env),
        (ctx.display(str(collected.home / "service.env")), collected.service_env),
    ]
    return (
        telemetry.notes(ctx, t3.PROFILE, report, sources)
        + revoke_notes(ctx, report)
        + detect_notes(report, collected)
    )
