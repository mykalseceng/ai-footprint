"""pi collector: everything comes from ~/.pi/agent and the bundled code folder."""

import json
import time
from pathlib import Path

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
    assert set(by_provider) == {"DeepSeek", "OpenAI", "ollama"}
    assert [t.field for t in by_provider["OpenAI"].tokens] == ["access", "refresh"]
    assert by_provider["OpenAI"].tokens[0].expired is True
    assert "baseUrl http://127.0.0.1:11434/v1" in by_provider["ollama"].protection
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
