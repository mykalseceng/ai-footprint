"""Every key and login the audited tools have configured, one row per distinct secret.

A row groups the credential entries that hold the same values (same fingerprints) for the
same provider, so a login kept in two files is one row with two locations. Nothing here
holds a secret: a row shows the recorded prefix, the last four characters (values of 20+
characters) and the fingerprint. The owner is shown only when the data records it: a field
the collector read from a file, or an email claim inside the token itself. Otherwise the
row says the owner is not recorded on disk.
"""

from dataclasses import dataclass, field

from ai_footprint import surface
from ai_footprint.model import AuditReport, Credential, TokenInfo
from ai_footprint.tokens import API_KEY, LOGIN, PASSWORD, SECRET, kind_of

EMAIL_CLAIMS = ("email", "https://api.openai.com/profile.email")


@dataclass
class KeyLocation:
    """One place a key is stored."""

    tool: str
    store: str
    location: str
    readable_by_others: bool


@dataclass
class KeyRow:
    """One distinct key or login for one provider.

    Attributes:
        kind: ``API key``, ``OAuth login``, ``Password`` or ``Secret`` (format not recognised).
        shown: The recorded prefix and last four characters, or the token fields of a login.
        owner: Who the key belongs to, only when the data records it; else empty.
        owner_source: Where ``owner`` was read.
    """

    provider: str
    kind: str
    shown: str
    length: int
    fingerprints: list[str]
    owner: str
    owner_source: str
    lifetime: str
    used_by: list[str] = field(default_factory=list)
    locations: list[KeyLocation] = field(default_factory=list)


def _shown(kind: str, tokens: list[TokenInfo]) -> str:
    if kind == LOGIN:
        return ", ".join(t.field for t in tokens)
    token = tokens[0]
    return token.prefix + token.last4


def owner_of(creds: list[Credential]) -> tuple[str, str]:
    """(owner, where it was read), from a collected field or a token's email claim."""
    for cred in creds:
        if cred.owner:
            return cred.owner, cred.owner_source
    for cred in creds:
        for token in cred.tokens:
            for claim in EMAIL_CLAIMS:
                if token.claims.get(claim):
                    return token.claims[claim], f"{token.field} token claim {claim}"
    return "", ""


def rows(audit: AuditReport) -> list[KeyRow]:
    """One row per provider and distinct set of values, across every installed tool."""
    groups: dict[tuple[str, tuple[str, ...]], list[tuple[str, Credential]]] = {}
    for tool in audit.tools:
        if not tool.installed:
            continue
        for cred in tool.credentials:
            if not cred.tokens:
                continue
            key = (cred.provider, tuple(sorted(t.fingerprint for t in cred.tokens)))
            groups.setdefault(key, []).append((tool.display_name, cred))
    out = []
    for (provider, fingerprints), held in groups.items():
        creds = [cred for _tool, cred in held]
        tokens = creds[0].tokens
        kind = kind_of(tokens)
        owner, source = owner_of(creds)
        out.append(
            KeyRow(
                provider=provider,
                kind=kind,
                shown=_shown(kind, tokens),
                length=tokens[0].length if len(tokens) == 1 else 0,
                fingerprints=list(fingerprints),
                owner=owner,
                owner_source=source,
                lifetime=surface.lifetime(creds),
                used_by=list(dict.fromkeys(name for name, _cred in held)),
                locations=[
                    KeyLocation(name, cred.store, cred.location, cred.readable_by_others)
                    for name, cred in held
                ],
            )
        )
    order = [API_KEY, LOGIN, PASSWORD, SECRET]
    return sorted(out, key=lambda r: (r.provider.lower(), order.index(r.kind)))
