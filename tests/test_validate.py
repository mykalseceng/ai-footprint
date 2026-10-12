from pathlib import Path

import pytest

from ai_footprint.model import FixCommand
from ai_footprint.system import ProbeResult
from ai_footprint.validate import program_of, split_simple_commands, validate_command
from tests.conftest import FakeSystem


def failed(validation) -> list[str]:
    return [c.name for c in validation.checks if not c.passed]


@pytest.fixture
def tool_dir(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("chmod", "claude"):
        exe = bin_dir / name
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    return bin_dir


def test_split_handles_operators_quotes_and_comments():
    words = split_simple_commands("cd '/a b' && echo x | tee y; ls # trailing comment")
    assert words == [["cd", "/a b"], ["echo", "x"], ["tee", "y"], ["ls"]]


@pytest.mark.parametrize(
    ("words", "program"),
    [
        (["sudo", "-n", "tee", "f"], "tee"),
        (["FOO=1", "BAR=2", "make"], "make"),
        (["env", "X=1", "python"], "python"),
        (["chmod", "600", "f"], "chmod"),
    ],
)
def test_program_of_skips_prefixes(words: list[str], program: str):
    assert program_of(words)[0] == program


def test_valid_chmod_passes(tool_dir: Path, tmp_path: Path):
    target = tmp_path / "file"
    target.write_text("")
    system = FakeSystem(path=str(tool_dir))
    result = validate_command(FixCommand(f"chmod 600 {target}"), system, {})
    assert result.ok, failed(result)


def test_missing_target_and_unknown_program_fail(tool_dir: Path, tmp_path: Path):
    system = FakeSystem(path=str(tool_dir))
    result = validate_command(FixCommand(f"chmod 600 {tmp_path}/missing && frobnicate"), system, {})
    assert failed(result) == [f"target {tmp_path}/missing", "program 'frobnicate'"]


def test_cd_into_missing_directory_fails(tool_dir: Path, tmp_path: Path):
    system = FakeSystem(path=str(tool_dir))
    result = validate_command(FixCommand(f"cd {tmp_path}/gone && claude mcp list"), system, {})
    assert f"target {tmp_path}/gone" in failed(result)


def test_syntax_error_fails(tool_dir: Path):
    system = FakeSystem(path=str(tool_dir))
    system.responders.append(
        lambda argv: ProbeResult(2, "", "syntax error") if argv[1:3] == ["-n", "-c"] else None
    )
    result = validate_command(FixCommand("echo 'unterminated"), system, {})
    assert failed(result) == ["shell syntax (sh -n)", "split into words"]


def test_help_probe_requires_subcommand_listed_and_exit_zero(tool_dir: Path):
    system = FakeSystem(path=str(tool_dir))
    claude = str(tool_dir / "claude")

    def respond(argv: list[str]) -> ProbeResult | None:
        if argv == [claude, "mcp", "--help"]:
            return ProbeResult(0, "Commands:\n  add\n  remove [options] <name>\n", "")
        if argv == [claude, "mcp", "remove", "--help"]:
            return ProbeResult(0, "usage", "")
        return None

    system.responders.append(respond)
    cmd = FixCommand("claude mcp remove x -s user", help_probe=("claude", "mcp", "remove"))
    assert validate_command(cmd, system, {"claude": claude}).ok
    missing = FixCommand("claude mcp purge x", help_probe=("claude", "mcp", "purge"))
    assert failed(validate_command(missing, system, {"claude": claude})) == [
        "'claude mcp --help' lists 'purge'",
        "'claude mcp purge --help' exits 0",
    ]


def test_markers_must_exist_in_binary(tmp_path: Path):
    binary = tmp_path / "tool"
    binary.write_bytes(b"\x00cli_auth_credentials_store\x00keyring\x00")
    cmd = FixCommand("set it", manual=True, markers=("keyring", "no_such_key"), marker_tool="codex")
    result = validate_command(cmd, FakeSystem(), {"codex": str(binary)})
    assert failed(result) == ["'no_such_key' known to installed codex"]


def test_manual_steps_skip_shell_checks():
    result = validate_command(FixCommand("Open the web settings", manual=True), FakeSystem(), {})
    assert result.ok
    assert [c.name for c in result.checks] == ["manual step"]
