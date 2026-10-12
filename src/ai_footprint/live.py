"""Opt-in network checks (``--live``). Nothing here runs unless the user asks.

* Anthropic: one read-only call to the OAuth profile endpoint proves whether a token is live
  and shows what identity it unlocks. The token goes only to its issuer.
* OpenAI: the issuer's public JWKS is fetched and JWT signatures are verified locally.
  No token leaves the machine for this check.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

TIMEOUT = 15
ANTHROPIC_PROFILE = "https://api.anthropic.com/api/oauth/profile"


class LiveCheckError(RuntimeError):
    """A live check could not complete."""


def _get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    if urllib.parse.urlparse(url).scheme != "https":
        raise LiveCheckError(f"refusing non-HTTPS URL {url}")
    request = urllib.request.Request(url, headers=headers or {})  # noqa: S310 - scheme checked
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise LiveCheckError(f"GET {url} failed: {exc}") from exc


def anthropic_profile(access_token: str, cli_version: str) -> str:
    """Summarise what an Anthropic OAuth token unlocks, or why it failed."""
    status, body = _get_json(
        ANTHROPIC_PROFILE,
        {
            "Authorization": f"Bearer {access_token}",
            "anthropic-beta": "oauth-2025-04-20",
            "User-Agent": f"ai-footprint (claude-cli/{cli_version} compatible)",
        },
    )
    if status != 200 or not isinstance(body, dict):
        return f"HTTP {status}: token rejected or expired"
    account = body.get("account", {})
    org = body.get("organization", {})
    app = body.get("application", {})
    return (
        f"HTTP 200: live. Unlocks {account.get('email', '?')} "
        f"({account.get('full_name', '?')}), org type {org.get('organization_type', '?')}, "
        f"rate tier {org.get('rate_limit_tier', '?')}, subscription "
        f"{org.get('subscription_status', '?')}, OAuth app {app.get('name', '?')}"
    )


def openid_jwks(issuer: str) -> dict[str, Any]:
    """Fetch an issuer's JWKS via OpenID discovery."""
    base = issuer.rstrip("/")
    status, config = _get_json(f"{base}/.well-known/openid-configuration")
    if status != 200 or not isinstance(config, dict) or "jwks_uri" not in config:
        raise LiveCheckError(f"no OpenID configuration at {base} (HTTP {status})")
    jwks_host = urllib.parse.urlparse(config["jwks_uri"]).hostname or ""
    issuer_host = urllib.parse.urlparse(base).hostname or ""
    if not jwks_host.endswith(issuer_host.split(".", 1)[-1]):
        raise LiveCheckError(f"JWKS host {jwks_host} does not belong to issuer {issuer_host}")
    status, jwks = _get_json(config["jwks_uri"])
    if status != 200 or not isinstance(jwks, dict):
        raise LiveCheckError(f"JWKS fetch failed (HTTP {status})")
    return jwks
