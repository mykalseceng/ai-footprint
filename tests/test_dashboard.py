"""The dashboard file: embedded data cannot escape its block, and only pinned code runs."""

import json
import re

from hypothesis import given
from hypothesis import strategies as st

from ai_footprint import dashboard

SCRIPT = (dashboard.ASSETS / "dashboard.js").read_text(encoding="utf-8")
# Anything that turns a string into markup or code, or reaches the network.
UNSAFE_SINKS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
    'setAttribute("style"',
    "fetch(",
    "XMLHttpRequest",
    "WebSocket",
    "sendBeacon",
    "import(",
)


def minimal(text: str) -> dict:
    return {"host": {"hostname": text, "home": "/Users/x"}, "value": text}


@given(st.text())
def test_embedded_json_round_trips_and_never_closes_its_block(text: str):
    embedded = dashboard.embed_json(minimal(text))
    assert json.loads(embedded) == minimal(text)
    assert "<" not in embedded
    assert ">" not in embedded
    assert "&" not in embedded


def test_markup_in_collected_strings_stays_inside_the_data_block():
    page = dashboard.render(minimal("</script><script>alert(1)</script><!--"))
    assert page.count("<script") == 2
    assert "alert(1)</script>" not in page
    assert "<title>AI footprint · &lt;/script&gt;" in page


def test_csp_pins_the_inline_script_and_style_by_hash():
    page = dashboard.render(minimal("mac"))
    [script] = re.findall(r"<script>(.*?)</script>", page, re.S)
    [style] = re.findall(r"<style>(.*?)</style>", page, re.S)
    [policy] = re.findall(r'Content-Security-Policy" content="([^"]+)"', page)
    policy = policy.replace("&#x27;", "'")
    assert f"script-src {dashboard.csp_hash(script)};" in policy
    assert f"style-src {dashboard.csp_hash(style)};" in policy
    assert policy.startswith("default-src 'none';")
    assert "connect-src" not in policy and "unsafe" not in policy


def test_csp_hash_changes_with_the_code():
    assert dashboard.csp_hash("a") != dashboard.csp_hash("b")
    assert dashboard.csp_hash("a").startswith("'sha256-")


def test_script_never_parses_data_as_markup_or_reaches_the_network():
    found = [sink for sink in UNSAFE_SINKS if sink in SCRIPT]
    assert found == []
    assert "</script" not in SCRIPT.lower()
    # The SVG namespace is an identifier for createElementNS, never fetched.
    assert re.findall(r"https?://[^\s\"'`]+", SCRIPT) == ["http://www.w3.org/2000/svg"]
