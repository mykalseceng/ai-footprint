"""pi account notes: usage data, sharing, and revocation for the providers it stores."""

from typing import Any

from ai_footprint.harnesses import telemetry
from ai_footprint.harnesses.account_notes import note, revoke_advice, unused_logins
from ai_footprint.harnesses.base import endpoint_markers
from ai_footprint.harnesses.common import Context, binary_path
from ai_footprint.harnesses.pi import collector as pi_cli
from ai_footprint.model import AccountNote, ToolReport


def notes(ctx: Context, report: ToolReport, settings: dict[str, Any]) -> list[AccountNote]:
    """Account evidence for pi: usage data, sharing, and whether logout revokes."""
    binary = binary_path(report)
    viewer_url = endpoint_markers(pi_cli.PROFILE)["pi.dev"]
    viewer = ctx.binary_has(binary, [viewer_url]) if binary else {}
    providers = sorted({c.provider for c in report.credentials})
    sources = [
        ("the environment", ctx.system.env),
        (ctx.display(str(pi_cli.agent_dir(ctx) / "settings.json")), settings),
    ]
    notes = telemetry.notes(ctx, pi_cli.PROFILE, report, sources)
    if viewer.get(viewer_url):
        notes.append(
            note(
                "data",
                f"/share uploads a session to a gist and links the viewer at {viewer_url} "
                "(PI_SHARE_VIEWER_URL overrides the viewer).",
                "pi binary",
            )
        )
    notes.append(
        note(
            "revoke",
            "Whether pi's /logout revokes anything at the provider is not something this audit "
            f"can observe. {revoke_advice(providers)}",
            "pi credential model",
        )
    )
    return notes + unused_logins(report)
