"""Every CLI option has a test proving it does what its help text says."""

import json
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import capture, cli, live, optioncheck
from ai_footprint.audit import TOOLS
from ai_footprint.model import (
    BinaryInfo,
    CommandValidation,
    Connection,
    NetworkCapture,
    ToolCapture,
    ToolPresence,
)
from tests.conftest import FakeSystem, build_claude_home, build_codex_home, jwks_for_test_key


class QuietFakeSystem(FakeSystem):
    def validate_probes(self) -> list[CommandValidation]:
        return []


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="aifp-cli-", dir="/tmp"))
    path.chmod(0o755)
    build_claude_home(path)
    build_codex_home(path)
    monkeypatch.setattr(cli, "System", QuietFakeSystem)
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    yield path
    shutil.rmtree(path)


def run(home: Path, *argv: str) -> int:
    return cli.main([*argv, "--home", str(home), "--workers", "1"])


# --- one behaviour test per option ------------------------------------------------------------


def test_tools_positional_audits_only_named_tools(home: Path, capsys):
    assert run(home, "codex", "--doctor") == 1
    out = capsys.readouterr().out
    assert "\nCodex CLI\n" in out
    assert "\nClaude Code\n" not in out


def test_list_shows_installed_and_missing_tools(home: Path, capsys):
    assert cli.main(["--list", "--home", str(home)]) == 0
    out = capsys.readouterr().out
    assert "claude" in out
    assert "codex" in out
    assert "OpenCode     not installed" in out


def test_doctor_marks_exposures_and_exits_one(home: Path, capsys):
    assert run(home, "all", "--doctor") == 1
    assert "REVIEW   Approval not turned off by a recorded setting" in capsys.readouterr().out


def test_validate_exit_code_matches_reported_failures(home: Path, capsys):
    code = run(home, "all", "--validate")
    out = capsys.readouterr().out
    assert "CLI options" in out
    assert code == int("FAIL" in out)


def test_dashboard_writes_private_file_at_given_path(home: Path):
    out = home / "nested" / "r.html"
    assert run(home, "claude", "--dashboard", str(out)) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert '"display_name":"Claude Code"' in out.read_text()


def test_html_writes_the_static_report_alongside_the_dashboard(home: Path):
    dashboard, report = home / "d.html", home / "r.html"
    assert run(home, "claude", "--dashboard", str(dashboard), "--html", str(report)) == 0
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    page = report.read_text()
    assert 'id="tool-claude"' in page and "<script" not in page
    assert 'id="audit-data"' in dashboard.read_text()


def test_html_is_not_written_unless_asked(home: Path):
    assert run(home, "claude", "--dashboard", str(home / "d.html")) == 0
    assert not list(home.glob("*report*.html"))


def test_json_writes_private_parseable_report(home: Path):
    out = home / "r.json"
    assert run(home, "codex", "--dashboard", str(home / "r.html"), "--json", str(out)) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    data = json.loads(out.read_text())
    assert [t["name"] for t in data["tools"]] == ["codex"]
    assert list(data["views"]["tools"]) == ["codex"]
    assert data["checklist"] and all("exposed" in c for c in data["checklist"])


def test_live_verifies_signatures_only_when_asked(home: Path, monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []

    def fake_jwks(issuer: str) -> dict:
        calls.append(issuer)
        return jwks_for_test_key()

    monkeypatch.setattr(live, "openid_jwks", fake_jwks)
    out = home / "r.json"
    assert run(home, "codex", "--dashboard", str(home / "a.html"), "--json", str(out)) == 0
    assert calls == []
    assert (
        run(home, "codex", "--live", "--dashboard", str(home / "b.html"), "--json", str(out)) == 0
    )
    assert calls == ["https://auth.example.com"]
    tokens = json.loads(out.read_text())["tools"][0]["credentials"][0]["tokens"]
    access = next(t for t in tokens if t["field"] == "access_token")
    assert access["signature"].startswith("valid RS256 signature")


def test_workers_reaches_the_scanner(home: Path, monkeypatch: pytest.MonkeyPatch):
    seen = {}
    real = cli.run_audit

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(cli, "run_audit", spy)
    cli.main(["claude", "--doctor", "--home", str(home), "--workers", "3"])
    assert seen["workers"] == 3


def test_home_selects_the_audited_home(home: Path, capsys):
    assert cli.main(["--list", "--home", str(home / "empty")]) == 0
    assert capsys.readouterr().out.count("not installed") == len(TOOLS)


def test_version_prints_package_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"ai-footprint {cli.__version__}"


def test_help_shows_every_example(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for example in optioncheck.help_examples(cli.DESCRIPTION):
        assert example in out


def saved_capture() -> NetworkCapture:
    seen = Connection(
        "models.dev", "104.18.32.47", 443, "tcp", "TLS server name", ["x"], 0.4, 9, 900
    )
    tool = ToolCapture("codex", "Codex CLI", "0.162.0", ["/bin/codex"], 60.0, connections=[seen])
    return NetworkCapture(capture.METHOD, "2026-10-17T20:00:00+00:00", "/tmp/c.pcapng", [tool])


def test_capture_records_the_selected_tools_and_saves_the_result(
    home: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[tuple[list[str], Path]] = []

    def fake_record(_system, presences, path):
        calls.append(([p.name for p in presences], path))
        return saved_capture()

    detect = cli.detect_tools

    def with_binary(**kwargs):
        found = detect(**kwargs)
        for presence in found:
            presence.binaries = [BinaryInfo("/bin/codex", "/bin/codex", "0.162.0")]
        return found

    assert run(home, "codex", "--dashboard", str(home / "d.html"), "--capture") == 2
    monkeypatch.setattr(cli, "detect_tools", with_binary)
    monkeypatch.setattr(capture, "record", fake_record)
    out = home / "r.json"
    assert (
        run(home, "codex", "--dashboard", str(home / "d.html"), "--json", str(out), "--capture")
        == 0
    )
    assert calls == [(["codex"], home / "ai-footprint-capture.pcapng")]
    saved = home / "ai-footprint-capture.json"
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert capture.load(saved) == saved_capture()
    assert json.loads(out.read_text())["network"]["tools"][0]["connections"][0]["host"] == (
        "models.dev"
    )


def test_network_shows_a_saved_capture_and_refuses_quick_modes(home: Path, capsys):
    saved = home / "c.json"
    saved.write_text(capture.dumps(saved_capture()))
    out = home / "r.json"
    assert (
        run(
            home,
            "codex",
            "--dashboard",
            str(home / "d.html"),
            "--json",
            str(out),
            "--network",
            str(saved),
        )
        == 0
    )
    assert json.loads(out.read_text())["network"]["method"] == capture.METHOD
    assert run(home, "codex", "--doctor", "--network", str(saved)) == 2
    assert "full audit only" in capsys.readouterr().err
    saved.write_text("{}")
    assert run(home, "codex", "--dashboard", str(home / "d.html"), "--network", str(saved)) == 2


OPTION_TESTS = {
    "tools": test_tools_positional_audits_only_named_tools,
    "list": test_list_shows_installed_and_missing_tools,
    "doctor": test_doctor_marks_exposures_and_exits_one,
    "validate": test_validate_exit_code_matches_reported_failures,
    "dashboard": test_dashboard_writes_private_file_at_given_path,
    "html": test_html_writes_the_static_report_alongside_the_dashboard,
    "json": test_json_writes_private_parseable_report,
    "live": test_live_verifies_signatures_only_when_asked,
    "workers": test_workers_reaches_the_scanner,
    "capture": test_capture_records_the_selected_tools_and_saves_the_result,
    "network": test_network_shows_a_saved_capture_and_refuses_quick_modes,
    "home": test_home_selects_the_audited_home,
    "version": test_version_prints_package_version,
    "help": test_help_shows_every_example,
}


def test_every_option_has_a_behaviour_test():
    dests = {action.dest for action in cli.build_parser()._actions}
    assert dests == set(OPTION_TESTS)


# --- the runtime validator catches broken documentation ----------------------------------------

PRESENT = [
    ToolPresence("claude", "Claude Code", installed=True),
    ToolPresence("codex", "Codex CLI", installed=False),
    ToolPresence("opencode", "OpenCode", installed=True),
]


def check(description: str) -> list[CommandValidation]:
    return optioncheck.validate(
        cli.build_parser(),
        description,
        PRESENT,
        select=lambda names, found: cli.select_tools(names, found, ask=None),
        tool_names=list(TOOLS),
    )


def test_shipped_help_passes_the_validator():
    assert all(v.ok for v in check(cli.DESCRIPTION))


def test_stale_flag_in_an_example_is_caught():
    results = check(cli.DESCRIPTION + "\n  ai-footprint --tools claude   old flag\n")
    bad = [v for v in results if not v.ok]
    assert [v.command for v in bad] == ["ai-footprint --tools claude"]
    assert "unrecognized arguments" in bad[0].checks[0].detail


def test_unknown_tool_in_an_example_is_caught():
    results = check(cli.DESCRIPTION + "\n  ai-footprint cursor\n")
    assert not next(v for v in results if v.command == "ai-footprint cursor").ok


def test_example_for_an_uninstalled_tool_is_valid_but_explained():
    results = check(cli.DESCRIPTION + "\n  ai-footprint codex\n")
    example = next(v for v in results if v.command == "ai-footprint codex")
    assert example.ok
    assert "depends on what is installed" in example.checks[-1].detail


def test_undocumented_tool_is_caught():
    stripped = cli.DESCRIPTION.replace("opencode", "oc").replace("OpenCode", "OC")
    names = next(v for v in check(stripped) if v.command == "help names every supported tool")
    assert [c.name for c in names.checks if not c.passed] == ["opencode"]


def test_examples_are_extracted_without_comments():
    text = "intro\n  ai-footprint codex opencode      audit only these\n  not a command\n"
    assert optioncheck.help_examples(text) == ["ai-footprint codex opencode"]
