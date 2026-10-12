"""Every CLI option has a test proving it does what its help text says."""

import json
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import cli, live, optioncheck
from ai_footprint.audit import TOOLS
from ai_footprint.model import CommandValidation, ToolPresence
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
    assert "EXPOSED  Commands require approval" in capsys.readouterr().out


def test_validate_exit_code_matches_reported_failures(home: Path, capsys):
    code = run(home, "all", "--validate")
    out = capsys.readouterr().out
    assert "CLI options" in out
    assert code == int("FAIL" in out)


def test_html_writes_private_report_at_given_path(home: Path):
    out = home / "nested" / "r.html"
    assert run(home, "claude", "--html", str(out)) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert 'id="tool-claude"' in out.read_text()


def test_json_writes_private_parseable_report(home: Path):
    out = home / "r.json"
    assert run(home, "codex", "--html", str(home / "r.html"), "--json", str(out)) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert [t["name"] for t in json.loads(out.read_text())["tools"]] == ["codex"]


def test_live_verifies_signatures_only_when_asked(home: Path, monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []

    def fake_jwks(issuer: str) -> dict:
        calls.append(issuer)
        return jwks_for_test_key()

    monkeypatch.setattr(live, "openid_jwks", fake_jwks)
    out = home / "r.json"
    assert run(home, "codex", "--html", str(home / "a.html"), "--json", str(out)) == 0
    assert calls == []
    assert run(home, "codex", "--live", "--html", str(home / "b.html"), "--json", str(out)) == 0
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


OPTION_TESTS = {
    "tools": test_tools_positional_audits_only_named_tools,
    "list": test_list_shows_installed_and_missing_tools,
    "doctor": test_doctor_marks_exposures_and_exits_one,
    "validate": test_validate_exit_code_matches_reported_failures,
    "html": test_html_writes_private_report_at_given_path,
    "json": test_json_writes_private_parseable_report,
    "live": test_live_verifies_signatures_only_when_asked,
    "workers": test_workers_reaches_the_scanner,
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
