from pathlib import Path

import pytest

from ai_footprint import system as system_module
from ai_footprint.system import CommandRefusedError, ProbeSpec, System
from tests.conftest import FakeSystem


def test_unregistered_probe_is_refused():
    with pytest.raises(CommandRefusedError, match="not a registered probe"):
        FakeSystem().run("curl", ["https://example.com"])


def test_probe_for_other_platform_is_refused():
    with pytest.raises(CommandRefusedError, match="does not apply"):
        FakeSystem(platform="linux").run("security", ["list-keychains"])


@pytest.mark.parametrize(
    "args",
    [["mcp", "remove", "x"], ["--version", "extra"], ["mcp", "--version"], ["-c", "--help"], []],
)
def test_tool_binaries_only_run_help_or_version(args: list[str]):
    with pytest.raises(CommandRefusedError):
        FakeSystem().run_tool("/bin/tool", args)


def test_allowed_tool_forms_run_and_are_logged():
    fake = FakeSystem()
    fake.run_tool("/bin/tool", ["--version"])
    fake.run_tool("/bin/tool", ["mcp", "remove", "--help"])
    assert [r.argv for r in fake.executed] == [
        ["/bin/tool", "--version"],
        ["/bin/tool", "mcp", "remove", "--help"],
    ]


def test_execution_log_truncates_syntax_check_scripts():
    fake = FakeSystem()
    fake.run("sh", ["-n", "-c", "echo " + "x" * 200])
    assert len(fake.executed[0].argv[3]) <= 61


def test_real_runner_uses_absolute_path_and_fixed_path(monkeypatch: pytest.MonkeyPatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["env"] = argv, kwargs["env"]

        class Done:
            returncode, stdout, stderr = 0, "", ""

        return Done()

    monkeypatch.setattr(system_module.subprocess, "run", fake_run)
    real = System(platform="linux", env={"PATH": "/evil", "HOME": "/h"})
    real.run("sh", ["-n", "-c", "true"])
    assert seen["argv"][0] == "/bin/sh"
    assert seen["env"]["PATH"] == system_module.SAFE_PATH


def test_probe_validation_flags_group_writable_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    binary = tmp_path / "probe"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o775)
    spec = ProbeSpec("probe", (str(binary),), "test", frozenset({"linux"}))
    monkeypatch.setattr(system_module, "PROBES", {"probe": spec})
    results = System(platform="linux", env={}).validate_probes()
    checks = {c.name: c.passed for c in results[0].checks}
    assert checks == {
        "absolute binary present": True,
        "executable": True,
        "not group/other writable": False,
    }
