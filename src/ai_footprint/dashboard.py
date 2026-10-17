"""Interactive dashboard: one self-contained HTML file that renders the run's document.

The document (``document.build``) is embedded as a JSON data block and laid out in the
browser by ``assets/dashboard.js``. The file makes no network requests and ships a CSP
that allows exactly one inline script and one inline style, each pinned by its SHA-256
hash. Collected strings (MCP names, instruction text) reach the page only as JSON data and
are inserted with ``textContent``, so markup in them is shown, never parsed.
"""

import base64
import hashlib
import html
import json
from importlib import resources
from typing import Any

ASSETS = resources.files("ai_footprint") / "assets"
_JSON_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def embed_json(document: dict[str, Any]) -> str:
    """JSON safe to place inside ``<script type="application/json">``.

    Escaping ``<``, ``>`` and ``&`` means no collected string can close the data block or
    open a comment, whatever it contains; ``JSON.parse`` restores the original text.
    """
    text = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    for char, escape in _JSON_ESCAPES.items():
        text = text.replace(char, escape)
    return text


def csp_hash(source: str) -> str:
    """CSP source expression that allows exactly this inline script or style."""
    digest = hashlib.sha256(source.encode()).digest()
    return f"'sha256-{base64.b64encode(digest).decode()}'"


def script() -> str:
    """The dashboard's script, exactly as embedded."""
    return "\n" + (ASSETS / "dashboard.js").read_text(encoding="utf-8")


def render(document: dict[str, Any]) -> str:
    """The full dashboard HTML for one run's document."""
    style = "\n" + (ASSETS / "dashboard.css").read_text(encoding="utf-8")
    code = script()
    policy = (
        f"default-src 'none'; script-src {csp_hash(code)}; style-src {csp_hash(style)}; "
        "base-uri 'none'; form-action 'none'"
    )
    host = document["host"]["hostname"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="{html.escape(policy)}">
<meta name="referrer" content="no-referrer">
<title>AI footprint · {html.escape(host)}</title>
<style>{style}</style></head><body>
<noscript><p class="noscript">This dashboard needs JavaScript. The same data is written by
<code>ai-footprint --json</code>.</p></noscript>
<script type="application/json" id="audit-data">{embed_json(document)}</script>
<script>{code}</script>
</body></html>
"""
