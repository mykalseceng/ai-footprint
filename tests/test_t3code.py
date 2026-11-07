"""T3 Code: install, permission modes, paired clients, background work and account notes."""

from pathlib import Path

from ai_footprint import checks
from ai_footprint.checks import steering, stolen_token
from ai_footprint.harnesses import registry
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.t3code import collector as t3
from ai_footprint.model import HostReport, ToolReport
from tests.conftest import FakeSystem, build_t3code_home

T3 = registry()["t3code"]


def context(home: Path, env: dict[str, str] | None = None) -> Context:
    system = FakeSystem()
    system.env.update(env or {})
    return Context(home=home, system=system, now=1_790_000_000, scan=False)


def rule_ctx(home: Path) -> checks.RuleContext:
    host = HostReport(
        os="macOS",
        kernel="",
        arch="arm64",
        hostname="h",
        user="u",
        uid=501,
        home=str(home),
        home_mode="drwx------",
    )
    return checks.RuleContext(host=host, platform="darwin", home=home)


def settings(report: ToolReport) -> dict[str, str]:
    return {s.key: s.value for s in report.settings}


def test_the_app_bundle_is_the_binary_and_markers_are_read_from_its_archive(tmp_path: Path):
    asar = build_t3code_home(tmp_path)
    found = T3.detect(context(tmp_path))
    assert found.installed
    [binary] = found.binaries
    assert binary.version == "0.1.5"
    assert binary.resolved == str(asar)


def test_the_data_folder_alone_marks_it_installed(tmp_path: Path):
    (tmp_path / ".t3").mkdir()
    assert T3.detect(context(tmp_path)).installed
    assert not T3.detect(context(tmp_path / "empty")).installed


def test_t3codehome_moves_the_data_folder(tmp_path: Path):
    build_t3code_home(tmp_path)
    moved = tmp_path / "elsewhere"
    (tmp_path / ".t3").rename(moved)
    report = T3.collect(context(tmp_path, {"T3CODE_HOME": str(moved)}))
    assert any(a.path.startswith(str(moved)) for a in report.artifacts)


def test_full_access_threads_are_an_approval_exposure_with_the_t3_fix(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    assert settings(report)[t3.THREADS_FULL_ACCESS] == "2 of 3 threads"
    [exposure] = steering.rule_no_approval(report, rule_ctx(tmp_path))
    assert exposure.fix is not None
    assert "Supervised" in exposure.fix.commands[0].text


def test_supervised_threads_raise_nothing(tmp_path: Path):
    build_t3code_home(tmp_path, threads=("approval-required",))
    report = T3.collect(context(tmp_path))
    assert not steering.rule_no_approval(report, rule_ctx(tmp_path))


def test_a_paired_phone_is_a_signal_but_the_desktop_app_is_not(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    assert not stolen_token.rule_account_signals(report, rule_ctx(tmp_path))

    phone = tmp_path / "phone"
    scopes = '["terminal:operate", "filesystem:write", "relay:read"]'
    build_t3code_home(phone, sessions=(("desktop", "[]"), ("mobile", scopes)))
    report = T3.collect(context(phone))
    [signal] = stolen_token.rule_account_signals(report, rule_ctx(phone))
    assert "Paired mobile client" in signal.statement
    assert "terminal:operate and filesystem:write" in signal.statement


def test_the_account_token_is_plaintext_and_server_keys_are_one_credential(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    account, keys = report.credentials
    assert account.provider == "T3 account (Clerk)"
    assert [t.field for t in account.tokens] == ["__clerk_client_jwt"]
    assert keys.local_service and keys.location.endswith("secrets")
    assert "2 key files" in keys.protection


def test_the_background_service_and_enabled_tasks_run_unattended(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    [service] = [x for x in report.extensions if x.kind == "service"]
    assert service.autostart
    assert service.detail.endswith("/.t3/bin/t3 serve")


def test_driven_harnesses_are_named_by_their_display_name(tmp_path: Path):
    build_t3code_home(tmp_path)
    report = T3.collect(context(tmp_path))
    assert settings(report)["agents driven"] == "Claude Code (3 threads)"


def test_usage_events_are_a_concern_until_turned_off(tmp_path: Path):
    build_t3code_home(tmp_path)
    [on] = [n for n in T3.collect(context(tmp_path)).account if n.topic == "data"]
    assert on.concern
    (tmp_path / ".t3" / "service.env").write_text("T3CODE_TELEMETRY_ENABLED=false\n")
    [off] = [n for n in T3.collect(context(tmp_path)).account if n.topic == "data"]
    assert not off.concern
    assert "is false" in off.text


def test_an_unreadable_state_db_yields_no_settings_rows(tmp_path: Path):
    (tmp_path / ".t3" / "userdata").mkdir(parents=True)
    (tmp_path / ".t3" / "userdata" / "statev2.sqlite").write_text("not a database")
    report = T3.collect(context(tmp_path))
    assert t3.THREADS_FULL_ACCESS not in settings(report)
    assert report.installed
