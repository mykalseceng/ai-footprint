"""--profile: documented features mapped onto this machine, and what the profile misses."""

import json
import tomllib
from pathlib import Path

import pytest

from ai_footprint import profiling
from ai_footprint.harnesses import registry
from ai_footprint.harnesses.base import Harness
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.profile import parse
from ai_footprint.model import BinaryInfo, ToolPresence, ToolReport
from ai_footprint.profiling import discover, render
from tests.conftest import FakeSystem

PROFILE = """
name = "demo"
display_name = "Demo"
binaries = []
process = "demo"
presence = ["{home}"]
env_prefixes = ["DEMO_"]
env = ["DEMO_HOME"]
settings = ["theme"]
roots = { home = { default = "~/.demo" } }

[[artifacts]]
label = "Config"
path = "{home}/config.json"
category = "config"

[[artifacts]]
label = "Sessions"
path = "{home}/data/sessions"
category = "session"

[[features]]
kind = "env"
name = "DEMO_TOKEN"
summary = "API token"
marker = "DEMO_TOKEN"
checks = ["creds-plaintext"]

[[features]]
kind = "setting"
name = "sandbox"
summary = "Sandbox mode"
marker = "sandbox_mode"

[[features]]
kind = "path"
name = "~/.demo/data"
summary = "Data folder"
"""


def demo(binary: Path | None = None) -> Harness:
    profile = parse("demo/profile.toml", tomllib.loads(PROFILE))

    def collect(ctx: Context, found: ToolPresence) -> ToolReport:
        del ctx
        return ToolReport("demo", "Demo", installed=found.installed)

    def binaries(ctx: Context) -> list:
        del ctx

        return [BinaryInfo(str(binary), str(binary), "1.0")] if binary else []

    return Harness(profile=profile, collect_fn=collect, binaries_fn=binaries)


def context(home: Path, env: dict[str, str] | None = None) -> Context:
    system = FakeSystem()
    system.env.update(env or {})
    return Context(home=home, system=system, now=0, scan=False)


def build(home: Path) -> Path:
    root = home / ".demo"
    (root / "data" / "sessions").mkdir(parents=True)
    (root / "data" / "cache").mkdir()
    (root / "data" / "cache" / "deep.bin").write_text("x")
    (root / "plugins" / "p1").mkdir(parents=True)
    (root / "config.json").write_text(json.dumps({"theme": "dark", "telemetry": True}))
    binary = home / "demo-bin"
    binary.write_bytes(b"\0DEMO_TOKEN\0DEMO_HOME\0DEMO_NEW_FLAG\0xDEMO_NOT\0sandbox_mode")
    return binary


def test_unmapped_entries_are_listed_once_at_their_shallowest_level(tmp_path: Path):
    build(tmp_path)
    found = discover.names(discover.unmapped_paths(context(tmp_path), demo()), context(tmp_path))
    assert found == ["~/.demo/data/cache/", "~/.demo/plugins/"]


def test_config_keys_no_setting_names_are_candidates(tmp_path: Path):
    build(tmp_path)
    keys = discover.unknown_config_keys(context(tmp_path), demo())
    assert keys == {"~/.demo/config.json": ["telemetry"]}


def test_binary_variables_the_profile_does_not_list_are_candidates(tmp_path: Path):
    binary = build(tmp_path)
    assert discover.unknown_env(str(binary), demo()) == ["DEMO_NEW_FLAG"]


def test_a_variable_split_across_read_chunks_is_found_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    binary = tmp_path / "bin"
    binary.write_bytes(b"." * 13 + b"\0DEMO_SPLIT_ACROSS\0" + b"." * 40)
    monkeypatch.setattr(discover, "CHUNK_BYTES", 20)
    assert discover.unknown_env(str(binary), demo()) == ["DEMO_SPLIT_ACROSS"]


def test_features_show_binary_presence_local_state_and_coverage(tmp_path: Path):
    binary = build(tmp_path)
    result = profiling.profile(context(tmp_path, {"DEMO_TOKEN": "x"}), demo(binary))
    by_id = {f.id: f for f in result.features}
    assert by_id["env:DEMO_TOKEN"].in_binary is True
    assert by_id["env:DEMO_TOKEN"].configured == "set in this environment"
    assert by_id["path:~/.demo/data"].in_binary is None
    assert by_id["path:~/.demo/data"].configured == "exists"
    assert [f.id for f in result.uncovered] == ["setting:sandbox", "path:~/.demo/data"]


def test_without_a_binary_no_feature_claims_presence(tmp_path: Path):
    build(tmp_path)
    result = profiling.profile(context(tmp_path), demo())
    assert {f.in_binary for f in result.features} == {None}
    assert result.unknown_env == []


def test_text_and_json_outputs_carry_the_same_findings(tmp_path: Path):
    binary = build(tmp_path)
    result = profiling.profile(context(tmp_path), demo(binary))
    text = render.to_text([result])
    data = render.to_json([result])
    assert "DEMO_NEW_FLAG" in text
    assert data["tools"][0]["unknown_env"] == ["DEMO_NEW_FLAG"]
    assert data["tools"][0]["uncovered"] == ["setting:sandbox", "path:~/.demo/data"]
    assert "creds-plaintext" in data["check_ids"]


def test_every_feature_names_only_real_checks():
    ids = profiling.check_ids()
    for harness in registry().values():
        for feature in harness.profile.features:
            assert set(feature.checks) <= ids, (harness.name, feature.id)
