"""pi collector: everything comes from ~/.pi/agent and the bundled code folder."""

import json
import time
from pathlib import Path

import pytest

from ai_footprint.collectors import pi
from ai_footprint.collectors.common import Context, search_file
from ai_footprint.model import AuditReport, HostReport
from ai_footprint.validate import validate_claims
from tests.conftest import FakeSystem, build_pi_home


def fake_install(home: Path, markers: list[str]) -> Path:
    """A ``pi`` launcher on a fake PATH whose bundle folder contains ``markers``."""
    package = home / "node_modules" / "@earendil-works" / "pi-coding-agent"
    bundle = package / "dist" / "bundle"
    (bundle / "chunks").mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"version": "1.2.0"}))
    (bundle / "cli.js").write_text("#!/usr/bin/env node\n")
    (bundle / "chunks" / "chunk-a.js").write_bytes(b"".join(m.encode() + b"\0" for m in markers))
    bin_dir = home / "bin"
    bin_dir.mkdir()
    launcher = bin_dir / "pi"
    launcher.symlink_to(bundle / "cli.js")
    (bundle / "cli.js").chmod(0o755)
    return bundle


def context(home: Path) -> Context:
    return Context(home=home, system=FakeSystem(path=str(home / "bin")), now=time.time())


def test_search_file_covers_every_file_under_a_directory(tmp_path: Path):
    (tmp_path / "a.js").write_text("alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.js").write_text("beta")
    assert search_file(tmp_path, ["alpha", "beta", "gamma"]) == {
        "alpha": True,
        "beta": True,
        "gamma": False,
    }


def test_launcher_resolves_to_the_bundle_folder_with_the_package_version(tmp_path: Path):
    bundle = fake_install(tmp_path, ["pi.dev"])
    [binary] = pi._binaries(context(tmp_path))
    assert binary.resolved == str(bundle)
    assert binary.version == "1.2.0"


def test_credentials_trust_sessions_and_extensions_come_from_the_agent_dir(tmp_path: Path):
    build_pi_home(tmp_path)
    fake_install(tmp_path, ["pi.dev"])
    ctx = context(tmp_path)
    report, facts = pi.collect(ctx)
    assert report.installed
    by_provider = {c.provider: c for c in report.credentials}
    assert set(by_provider) == {"DeepSeek", "OpenAI"}
    assert [t.field for t in by_provider["OpenAI"].tokens] == ["access", "refresh"]
    assert by_provider["OpenAI"].tokens[0].expired is True
    assert report.trusted_folders == [str(tmp_path / "work")]
    paths = {Path(i.path).name for i in report.instructions}
    assert paths == {"AGENTS.md"}
    kinds = sorted((x.kind, x.name) for x in report.extensions)
    assert kinds == [("mcp", "docs"), ("mcp", "local"), ("plugin", "npm:@demo/pi-tool")]
    plugin = next(x for x in report.extensions if x.kind == "plugin")
    assert plugin.description == "Searches the web. Twice."
    local = next(x for x in report.extensions if x.name == "local")
    assert local.dangling and local.source.startswith("project ")
    assert report.stats["sessions"] == "1" and report.stats["first session"] == "2026-04-28"
    assert facts["settings"]["enableAnalytics"] is True
    settings = {s.key: s.value for s in report.settings}
    assert settings["packages"] == "npm:@demo/pi-tool"
    assert settings["trusted projects"].startswith("1 in ")


def test_unset_settings_are_dropped_without_the_binary(tmp_path: Path):
    build_pi_home(tmp_path)
    report, _facts = pi.collect(context(tmp_path))
    keys = {s.key for s in report.settings}
    assert "enableAnalytics" in keys and "packages" in keys
    assert "shellCommandPrefix" not in keys and "env.PI_OFFLINE" not in keys


def test_every_pi_claim_is_searched_in_the_bundle_folder(tmp_path: Path):
    bundle = fake_install(tmp_path, [c.marker for c in pi.CLAIMS])
    report, _facts = pi.collect(context(tmp_path))
    host = HostReport(
        os="macOS",
        kernel="",
        arch="arm64",
        hostname="mac",
        user="me",
        uid=501,
        home=str(tmp_path),
        home_mode="drwx------",
    )
    audit = AuditReport(generated_at="", auditor_version="0", host=host, tools=[report])
    [validation] = validate_claims(audit, {"pi": pi.CLAIMS})
    assert validation.ok
    assert str(bundle) == report.binaries[0].resolved
    assert [f.label for f in report.fingerprint] == [label for label, _v, _m in pi.FINGERPRINT]
    assert {e.host for e in report.endpoints if e.source == "binary"} == {"pi.dev", "radius.pi.dev"}


@pytest.mark.parametrize(
    ("base_url", "key", "placeholder"),
    [
        ("http://127.0.0.1:11434/v1", "ollama", True),
        ("http://localhost:11434/v1", "OLLAMA", True),
        ("http://[::1]:11434/v1", "ollama", True),
        ("http://127.0.0.1:4000/v1", "sk-" + "k" * 30, False),
        ("https://ollama.example.com/v1", "ollama", False),
        ("", "ollama", False),
    ],
)
def test_only_a_provider_name_on_loopback_is_a_placeholder(
    base_url: str, key: str, placeholder: bool
):
    assert pi.is_placeholder("ollama", {"baseUrl": base_url, "apiKey": key}) is placeholder


def test_a_real_key_for_a_local_server_is_still_a_credential(tmp_path: Path):
    build_pi_home(tmp_path)
    models = tmp_path / ".pi" / "agent" / "models.json"
    proxy = {"apiKey": "sk-" + "k" * 30, "baseUrl": "http://127.0.0.1:4000"}
    models.write_text(json.dumps({"providers": {"proxy": proxy}}))
    report, _facts = pi.collect(context(tmp_path))
    assert "proxy" in {c.provider for c in report.credentials}


def test_openai_and_chatgpt_logins_map_to_their_own_hosts(tmp_path: Path):
    build_pi_home(tmp_path)
    auth = tmp_path / ".pi" / "agent" / "auth.json"
    entries = json.loads(auth.read_text())
    entries["openai"] = {"type": "api", "key": "sk-" + "o" * 40}
    auth.write_text(json.dumps(entries))
    report, _facts = pi.collect(context(tmp_path))
    hosts = {e.host for e in report.endpoints if e.source == "credentials"}
    assert {"api.openai.com", "chatgpt.com", "api.deepseek.com"} <= hosts


def _shared_skill(home: Path) -> None:
    skill = home / ".agents" / "skills" / "grill-me"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\ndescription: Asks questions.\n---\n")


def test_shared_agent_skills_are_skipped_when_the_bundle_does_not_read_them(tmp_path: Path):
    build_pi_home(tmp_path)
    _shared_skill(tmp_path)
    fake_install(tmp_path, ["pi.dev"])
    report, _facts = pi.collect(context(tmp_path))
    assert "grill-me" not in {x.name for x in report.extensions}


def test_shared_agent_skills_are_listed_when_the_bundle_reads_them(tmp_path: Path):
    build_pi_home(tmp_path)
    _shared_skill(tmp_path)
    fake_install(tmp_path, ["pi.dev", pi.SHARED_SKILLS_MARKER])
    report, _facts = pi.collect(context(tmp_path))
    assert ("skill", "grill-me") in {(x.kind, x.name) for x in report.extensions}


def test_an_unreadable_credential_store_is_named_not_silently_skipped(tmp_path: Path):
    build_pi_home(tmp_path)
    store = tmp_path / ".pi" / "agent" / "models-store.json"
    store.write_text("{}")
    store.chmod(0o000)
    fake_install(tmp_path, ["pi.dev", "models-store.json"])
    try:
        report, _facts = pi.collect(context(tmp_path))
    finally:
        store.chmod(0o600)
    [setting] = [s for s in report.settings if s.key == "models-store.json"]
    assert setting.value.startswith("could not read ~/.pi/agent/models-store.json (owned by ")
    assert setting.value.endswith("mode 0)")


def test_a_readable_credential_store_adds_no_caveat(tmp_path: Path):
    build_pi_home(tmp_path)
    (tmp_path / ".pi" / "agent" / "models-store.json").write_text("{}")
    fake_install(tmp_path, ["pi.dev", "models-store.json"])
    report, _facts = pi.collect(context(tmp_path))
    assert "models-store.json" not in {s.key for s in report.settings}


def test_a_package_another_account_owns_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    build_pi_home(tmp_path)
    monkeypatch.setattr(pi.os, "getuid", lambda: -1)
    report, _facts = pi.collect(context(tmp_path))
    [plugin] = [x for x in report.extensions if x.kind == "plugin"]
    assert plugin.notes.startswith("Loaded in-process; files owned by ")


def test_a_package_you_own_has_no_owner_note(tmp_path: Path):
    build_pi_home(tmp_path)
    report, _facts = pi.collect(context(tmp_path))
    [plugin] = [x for x in report.extensions if x.kind == "plugin"]
    assert plugin.notes == "Loaded in-process"
