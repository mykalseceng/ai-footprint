"""The Network page's data, its figure and its recount, and both renderings."""

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import capture, document, figurecheck, netview, report_html
from ai_footprint.audit import run_audit
from ai_footprint.model import AuditReport, Connection, Endpoint, NetworkCapture, ToolCapture
from tests.conftest import build_codex_home
from tests.test_audit import QuietFakeSystem


def connection(host: str, named_by: str = "TLS server name") -> Connection:
    return Connection(host, "104.18.32.47", 443, "tcp", named_by, ["codex (pid 9)"], 0.4, 9, 900)


@pytest.fixture
def audited() -> Iterator[tuple[AuditReport, list]]:
    home = Path(tempfile.mkdtemp(prefix="aifp-net-", dir="/tmp"))
    home.chmod(0o755)
    build_codex_home(home)
    audit, checklist = run_audit(system=QuietFakeSystem(), home=home, scan=False, workers=1)
    [codex] = [t for t in audit.tools if t.installed]
    codex.endpoints = [
        Endpoint("codex", "chatgpt.com", "Codex responses API", "binary"),
        Endpoint("codex", "auth.openai.com", "OAuth login", "binary"),
        Endpoint("codex", "docs.github.com", "mentioned", "logs", 3),
    ]
    yield audit, checklist
    shutil.rmtree(home)


def with_capture(audit: AuditReport, hosts: list[str]) -> AuditReport:
    tool = ToolCapture(
        "codex",
        "Codex CLI",
        "0.162.0",
        [f"{audit.host.home}/bin/codex"],
        60.0,
        connections=[connection(h) for h in hosts],
    )
    audit.network = NetworkCapture(capture.METHOD, "2026-10-17T20:00:00+00:00", "/x.pcapng", [tool])
    return audit


def test_uncaptured_tools_say_so_and_list_binary_hosts_as_named_only(audited):
    audit, _checklist = audited
    view = netview.view(audit)["tools"]["codex"]
    assert not view["captured"]
    assert view["summary"].startswith("Codex CLI was not captured. Run ai-footprint --capture")
    assert view["observed"] == []
    assert view["unobserved"] == [
        {"host": "chatgpt.com", "purpose": "Codex responses API"},
        {"host": "auth.openai.com", "purpose": "OAuth login"},
    ]


def test_captured_hosts_leave_the_unobserved_list_including_subdomains(audited):
    audit, _checklist = audited
    audit = with_capture(audit, ["edge.chatgpt.com", "models.dev", "models.dev"])
    view = netview.view(audit)["tools"]["codex"]
    assert view["captured"]
    assert [u["host"] for u in view["unobserved"]] == ["auth.openai.com"]
    assert view["summary"] == (
        "Started idle for 60s with no prompt, Codex CLI 0.162.0 reached 2 hosts: "
        "edge.chatgpt.com and models.dev."
    )
    assert view["command"] == ["~/bin/codex"]


def test_network_figure_is_recounted_and_a_wrong_count_fails(audited):
    audit, checklist = audited
    doc = json.loads(json.dumps(document.build(with_capture(audit, ["a.dev", "b.dev"]), checklist)))
    shown = {f["id"]: f for f in doc["views"]["figures"]["tools"]["codex"]}["network"]
    assert (shown["value"], shown["display"]) == (2, "2")
    assert all(c.passed for v in figurecheck.check_figures(doc) for c in v.checks)
    shown["value"], shown["display"] = 3, "3"
    failed = [c.name for v in figurecheck.check_figures(doc) for c in v.checks if not c.passed]
    assert failed == ["Hosts reached when started = 2"]


def test_static_report_has_a_network_page(audited):
    audit, checklist = audited
    audit = with_capture(audit, ["models.dev"])
    views = document.build(audit, checklist)["views"]
    page = report_html.render(audit, checklist, views)
    assert '<section class="view" id="network">' in page
    assert '<a href="#network">Network</a>' in page
    assert "<code>models.dev</code>" in page
