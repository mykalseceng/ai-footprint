"""Account notes shared by harnesses: log markers, token claims, revocation advice.

Account settings live on the provider's servers, but each tool caches some of them locally,
and the installed binary shows whether logging out revokes a token. Harnesses report only
what is on disk or in the binary, and say so when the answer needs the web settings. Every
binary-derived statement is gated on markers the harness registers as claims.
"""

import datetime
from collections.abc import Iterable, Mapping
from pathlib import Path

from ai_footprint.model import AccountNote, ToolReport
from ai_footprint.text import join, when
from ai_footprint.tokens import iso_time

MAX_LOG_BYTES = 400 * 1024 * 1024


def note(topic: str, text: str, source: str, *, concern: bool = False) -> AccountNote:
    """An account note with its timestamps rewritten to read one way."""
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


def marker_text(markers: dict[str, tuple[int, str]], labels: Mapping[str, str]) -> str:
    """``label: N times (latest date)`` for each marker found."""
    return "; ".join(f"{labels[m]}: {n} times (latest {d})" for m, (n, d) in markers.items())


def token_claims(report: ToolReport, field: str) -> dict[str, str]:
    """Claims of the first stored token whose field is ``field``."""
    for cred in report.credentials:
        for token in cred.tokens:
            if token.field == field:
                return token.claims
    return {}


REVOKE_STEPS = {
    "Anthropic": "sign out of all sessions at claude.ai",
    "OpenAI": "sign out of all devices in ChatGPT security settings",
}


def revoke_advice(providers: list[str]) -> str:
    """Where to revoke each stored provider credential."""
    steps = [REVOKE_STEPS[p] for p in providers if p in REVOKE_STEPS]
    keys = [p for p in providers if p not in REVOKE_STEPS]
    if keys:
        steps.append(f"delete each API key in its provider's console ({join(keys)})")
    return f"Revoke at each provider: {'; '.join(steps)}." if steps else ""


def unused_logins(report: ToolReport) -> list[AccountNote]:
    """Stored logins whose access token expired and was never replaced on disk."""
    now = datetime.datetime.now(datetime.UTC).isoformat()
    stale = sorted(
        {
            f"{cred.provider} access token"
            + (f" issued {token.issued_at[:10]}," if token.issued_at else "")
            + f" expired {token.expires_at[:10]}"
            for cred in report.credentials
            for token in cred.tokens
            if token.field == "access" and token.expires_at and token.expires_at < now
        }
    )
    if not stale:
        return []
    return [
        note(
            "detect",
            f"Stored {report.display_name} logins whose access token expired and was not "
            f"replaced: {'; '.join(stale)}. Their refresh tokens have no recorded expiry.",
            "access-token issue and expiry claims",
            concern=True,
        )
    ]
