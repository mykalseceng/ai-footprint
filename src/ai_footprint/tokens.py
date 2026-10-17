"""Turn credential values into non-secret metadata.

Opaque tokens are classified by prefix. JWTs are decoded (header and claims only) and,
when a JWKS is supplied, their RS256 signature is verified in pure Python. No function in
this module returns or logs a secret value; the fingerprint is a truncated SHA-256 that
lets the secret scanner say "the current token is also stored in file X".
"""

import base64
import binascii
import datetime
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from ai_footprint.model import TokenInfo

KNOWN_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("sk-ant-oat01-", "anthropic_oauth_access", "Anthropic OAuth access token (opaque bearer)"),
    ("sk-ant-ort01-", "anthropic_oauth_refresh", "Anthropic OAuth refresh token (opaque)"),
    ("sk-ant-api03-", "anthropic_api_key", "Anthropic API key (no expiry until revoked)"),
    ("sk-ant-admin01-", "anthropic_admin_key", "Anthropic Admin API key"),
    ("sk-proj-", "openai_project_key", "OpenAI project API key (no expiry until revoked)"),
    ("rt.1.", "openai_refresh", "OpenAI OAuth refresh token (opaque)"),
    ("rt_", "openai_refresh", "OpenAI OAuth refresh token (opaque)"),
    ("ghp_", "github_pat_classic", "GitHub personal access token"),
    ("github_pat_", "github_pat_fine", "GitHub fine-grained token"),
    ("gho_", "github_oauth", "GitHub OAuth token"),
    ("sk-", "api_key", "Provider API key (sk- format, no expiry until revoked)"),
    ("ak_", "api_key", "Provider API key (ak_ format)"),
)

_DROPPED_CLAIMS = frozenset({"jti", "at_hash", "nonce", "c_hash", "sid", "session_id"})
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_MAX_CLAIMS = 40
LAST4_MIN_LENGTH = 20
"""Shorter values keep no last four characters: together with the prefix they would show
too much of the secret."""


API_KEY = "API key"
LOGIN = "OAuth login"
PASSWORD = "Password"  # noqa: S105 - a row label, not a password
SECRET = "Secret"  # noqa: S105 - a row label, not a secret
API_KINDS = frozenset(
    {"api_key", "anthropic_api_key", "anthropic_admin_key", "openai_project_key"}
    | {"github_pat_classic", "github_pat_fine"}
)
API_FIELDS = frozenset({"key", "apikey", "api_key"})
LOGIN_KINDS = frozenset(
    {"jwt", "anthropic_oauth_access", "anthropic_oauth_refresh", "openai_refresh", "github_oauth"}
)


def kind_of(tokens: list[TokenInfo]) -> str:
    """What a credential entry is, from its recorded token formats and field names."""
    for token in tokens:
        name = token.field.lower()
        if token.kind in API_KINDS or name in API_FIELDS or name.endswith("_api_key"):
            return API_KEY
    if any(t.kind in LOGIN_KINDS for t in tokens):
        return LOGIN
    if any(t.field.lower() == "password" for t in tokens):
        return PASSWORD
    return SECRET


def fingerprint(value: str) -> str:
    """Short, non-reversible identifier for a secret value."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def b64url_decode(segment: str) -> bytes:
    """Decode base64url without padding."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_jwt(value: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return (header, claims) for a compact JWS, or None when it is not a JWT."""
    parts = value.split(".")
    if len(parts) != 3 or not value.startswith("eyJ"):
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims


def iso_time(epoch: float | int | None) -> str:
    """ISO-8601 UTC timestamp from seconds or milliseconds since epoch."""
    if epoch is None:
        return ""
    seconds = epoch / 1000 if epoch > 1e12 else epoch
    return datetime.datetime.fromtimestamp(seconds, datetime.UTC).isoformat(timespec="seconds")


def is_expired(epoch: float | int | None, now: float) -> bool | None:
    """Whether an expiry (seconds or ms) is in the past; None when unknown."""
    if epoch is None:
        return None
    seconds = epoch / 1000 if epoch > 1e12 else epoch
    return seconds < now


def flatten_claims(claims: Mapping[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten nested claims to ``a.b`` keys with short string values, dropping session ids."""
    flat: dict[str, str] = {}
    for key, value in claims.items():
        if key in _DROPPED_CLAIMS:
            continue
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten_claims(value, prefix=f"{name}."))
        elif isinstance(value, list):
            flat[name] = ", ".join(json.dumps(v) if isinstance(v, dict) else str(v) for v in value)
        else:
            flat[name] = str(value)
    return {k: (v if len(v) <= 160 else v[:157] + "…") for k, v in list(flat.items())[:_MAX_CLAIMS]}


def _scopes(claims: Mapping[str, Any]) -> list[str]:
    raw = claims.get("scp", claims.get("scope", []))
    if isinstance(raw, str):
        return raw.split()
    return [str(s) for s in raw] if isinstance(raw, list) else []


def classify_opaque(value: str) -> tuple[str, str]:
    """(kind, description) for a non-JWT secret based on its prefix."""
    for prefix, kind, description in KNOWN_PREFIXES:
        if value.startswith(prefix):
            return kind, description
    return "opaque", "Opaque secret (format not recognised)"


def inspect_token(
    field: str,
    value: str,
    *,
    now: float,
    expires_at: float | None = None,
    scopes: list[str] | None = None,
) -> TokenInfo:
    """Describe a credential value without retaining it.

    Args:
        field: Name of the field the value came from, e.g. ``accessToken``.
        value: The secret. Used only to derive metadata.
        now: Current time in epoch seconds (injected for testability).
        expires_at: Expiry recorded next to an opaque token, seconds or milliseconds.
        scopes: Scopes recorded next to an opaque token.

    Returns:
        Metadata including a 16-hex-character fingerprint.
    """
    shown = value[:13] if value.startswith("sk-ant-") else value[:6]
    decoded = decode_jwt(value)
    if decoded is None:
        kind, description = classify_opaque(value)
        return TokenInfo(
            field=field,
            kind=kind,
            description=description,
            prefix=shown + "…",
            length=len(value),
            fingerprint=fingerprint(value),
            last4=value[-4:] if len(value) >= LAST4_MIN_LENGTH else "",
            expires_at=iso_time(expires_at),
            expired=is_expired(expires_at, now),
            scopes=list(scopes or []),
            signature="none: opaque token, validated only by the issuer's servers",
        )
    header, claims = decoded
    audience = claims.get("aud", "")
    return TokenInfo(
        field=field,
        kind="jwt",
        description=f"JWT signed with {header.get('alg', '?')}",
        prefix="eyJ…",
        length=len(value),
        fingerprint=fingerprint(value),
        issuer=str(claims.get("iss", "")),
        audience=", ".join(audience) if isinstance(audience, list) else str(audience),
        algorithm=str(header.get("alg", "")),
        key_id=str(header.get("kid", "")),
        issued_at=iso_time(claims.get("iat")),
        expires_at=iso_time(claims.get("exp")),
        expired=is_expired(claims.get("exp"), now),
        scopes=_scopes(claims),
        claims=flatten_claims(claims),
        signature="present, not verified (run with --live to check against the issuer's JWKS)",
    )


def verify_rs256(token: str, jwks: Mapping[str, Any]) -> tuple[bool, str]:
    """Verify a compact RS256 JWS against a JWKS document.

    Implements RSASSA-PKCS1-v1_5 with SHA-256 using integer arithmetic.

    Returns:
        (valid, explanation).
    """
    decoded = decode_jwt(token)
    if decoded is None:
        return False, "not a JWT"
    header, _claims = decoded
    if header.get("alg") != "RS256":
        return False, f"unsupported algorithm {header.get('alg')}"
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")]
    if not keys:
        return False, f"kid {header.get('kid')} not in issuer JWKS"
    key = keys[0]
    modulus = int.from_bytes(b64url_decode(key["n"]), "big")
    exponent = int.from_bytes(b64url_decode(key["e"]), "big")
    signing_input, _, signature_b64 = token.rpartition(".")
    signature = int.from_bytes(b64url_decode(signature_b64), "big")
    size = (modulus.bit_length() + 7) // 8
    encoded = pow(signature, exponent, modulus).to_bytes(size, "big")
    digest = hashlib.sha256(signing_input.encode()).digest()
    suffix = _SHA256_DIGEST_INFO + digest
    padding = size - len(suffix) - 3
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + suffix
    if encoded == expected:
        return True, f"valid RS256 signature, key {header.get('kid')}"
    return False, "signature does not match issuer key"
