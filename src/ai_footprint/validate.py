"""Validate every fix command before it is shown to the user.

For a shell command:
  1. ``sh -n`` parses it (syntax only, nothing executes).
  2. Every program it invokes resolves: a shell builtin, an existing absolute path, or a
     match on the user's PATH.
  3. Every file it targets with chmod/chown exists.
  4. When it names a tool subcommand, ``<tool> <parent> --help`` lists that subcommand and
     ``<tool> <subcommand> --help`` exits 0 in the installed version.
For any command (shell or manual):
  5. Config keys and values it recommends appear in the installed tool's binary.

Separately, every claim a collector registers about a tool (endpoints, signature traits,
config keys, log markers, behaviour markers) is searched for in the installed binary, so a
constant that is wrong or that a newer version removed fails ``--validate``.
"""

import glob
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path

from ai_footprint.collectors.common import Claim, search_file
from ai_footprint.model import AuditReport, CheckResult, CommandValidation, FixCommand
from ai_footprint.system import CommandRefusedError, System

BUILTINS = frozenset(
    {
        "cd",
        "echo",
        "export",
        "kill",
        "test",
        "[",
        "true",
        "false",
        "printf",
        "set",
        "unset",
        "source",
        ".",
        "exit",
        "command",
        "type",
        "read",
        "wait",
        "umask",
    }
)
PREFIX_WORDS = frozenset({"sudo", "env", "nohup", "time"})
SEPARATORS = frozenset({";", "&&", "||", "|", "(", ")", "&", "\n"})
PATH_TARGET_COMMANDS = frozenset({"chmod", "chown", "chgrp"})


def split_simple_commands(text: str) -> list[list[str]]:
    """Split shell text into simple commands (word lists) at ; && || | ( ) & and newlines."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    commands: list[list[str]] = [[]]
    for token in lexer:
        if token in SEPARATORS or set(token) <= set(";&|()"):
            commands.append([])
        else:
            commands[-1].append(token)
    return [c for c in commands if c]


def program_of(words: list[str]) -> tuple[str, list[str]]:
    """The program a simple command runs and its arguments, skipping env vars and sudo/env."""
    index = 0
    while index < len(words):
        word = words[index]
        if "=" in word and not word.startswith(("-", "/")) and word.split("=", 1)[0].isidentifier():
            index += 1
        elif word in PREFIX_WORDS:
            index += 1
            while index < len(words) and words[index].startswith("-"):
                index += 1
        else:
            return word, words[index + 1 :]
    return "", []


def _check_programs(cmd: FixCommand, system: System) -> list[CheckResult]:
    try:
        commands = split_simple_commands(cmd.text)
    except ValueError as exc:
        return [CheckResult("split into words", passed=False, detail=str(exc))]
    results = []
    for words in commands:
        program, args = program_of(words)
        if not program:
            continue
        results.append(_resolve_program(program, system))
        if Path(program).name in PATH_TARGET_COMMANDS:
            results.extend(_check_targets(args))
        elif program == "cd":
            results.extend(_check_targets(["cd", *args]))
    return results


def _resolve_program(program: str, system: System) -> CheckResult:
    if program in BUILTINS:
        return CheckResult(f"program '{program}'", passed=True, detail="shell builtin")
    if program.startswith("/"):
        exists = Path(program).is_file()
        return CheckResult(f"program '{program}'", exists, "exists" if exists else "missing")
    found = system.which(program)
    return CheckResult(f"program '{program}'", found is not None, found or "not found on PATH")


def _check_targets(args: list[str]) -> list[CheckResult]:
    operands = [a for a in args if not a.startswith("-")][1:]
    results = []
    for operand in operands:
        # Operands may be shell globs; Path.glob cannot take absolute patterns.
        expanded = glob.glob(str(Path(operand).expanduser()))  # noqa: PTH207
        results.append(
            CheckResult(
                f"target {operand}", bool(expanded), "exists" if expanded else "no such file"
            )
        )
    return results


def _check_help(cmd: FixCommand, system: System, binaries: Mapping[str, str]) -> list[CheckResult]:
    tool, *subcommand = cmd.help_probe
    binary = binaries.get(tool)
    if binary is None:
        return [
            CheckResult(
                f"{tool} installed", passed=False, detail="binary not found; cannot confirm"
            )
        ]
    results = []
    try:
        if subcommand:
            parent = subcommand[:-1]
            listing = system.run_tool(binary, [*parent, "--help"])
            text = listing.stdout + listing.stderr
            listed = subcommand[-1] in text.split() or f" {subcommand[-1]} " in text
            results.append(
                CheckResult(
                    f"'{' '.join([tool, *parent])} --help' lists '{subcommand[-1]}'",
                    listed,
                    "listed" if listed else "not listed in help output",
                )
            )
        own = system.run_tool(binary, [*subcommand, "--help"])
        results.append(
            CheckResult(
                f"'{' '.join(cmd.help_probe)} --help' exits 0",
                own.returncode == 0,
                f"exit {own.returncode}",
            )
        )
    except CommandRefusedError as exc:
        results.append(CheckResult("help probe", passed=False, detail=str(exc)))
    return results


def _check_markers(cmd: FixCommand, binaries: Mapping[str, str]) -> list[CheckResult]:
    binary = binaries.get(cmd.marker_tool)
    if binary is None:
        return [
            CheckResult(
                f"{cmd.marker_tool} binary", passed=False, detail="not installed; cannot confirm"
            )
        ]
    found = search_file(Path(binary), cmd.markers)
    return [
        CheckResult(
            f"'{marker}' known to installed {cmd.marker_tool}",
            ok,
            "found in binary" if ok else "absent from binary",
        )
        for marker, ok in found.items()
    ]


def validate_command(
    cmd: FixCommand, system: System, binaries: Mapping[str, str]
) -> CommandValidation:
    """Run every applicable check against one fix command."""
    validation = CommandValidation(command=cmd.text)
    if cmd.manual:
        validation.checks.append(
            CheckResult("manual step", passed=True, detail="instruction, not a command")
        )
    else:
        syntax = system.run("sh", ["-n", "-c", cmd.text])
        validation.checks.append(
            CheckResult(
                "shell syntax (sh -n)", syntax.returncode == 0, syntax.stderr.strip() or "parses"
            )
        )
        validation.checks.extend(_check_programs(cmd, system))
    if cmd.help_probe:
        validation.checks.extend(_check_help(cmd, system, binaries))
    if cmd.markers:
        validation.checks.extend(_check_markers(cmd, binaries))
    return validation


def tool_binaries(audit: AuditReport) -> dict[str, str]:
    """Map tool name to its resolved native binary (used for help probes and marker search)."""
    return {tool.name: tool.binaries[0].resolved for tool in audit.tools if tool.binaries}


def validate_all(audit: AuditReport, system: System) -> None:
    """Validate every fix command in the audit, storing results on each fix."""
    binaries = tool_binaries(audit)
    cache: dict[FixCommand, CommandValidation] = {}
    for exposure in audit.all_exposures():
        if exposure.fix is None:
            continue
        exposure.fix.validations = []
        for cmd in exposure.fix.commands:
            if cmd not in cache:
                cache[cmd] = validate_command(cmd, system, binaries)
            exposure.fix.validations.append(cache[cmd])


def validate_claims(
    audit: AuditReport, claims: Mapping[str, Sequence[Claim]]
) -> list[CommandValidation]:
    """One validation per installed tool: every registered claim marker is in its binary."""
    binaries = tool_binaries(audit)
    out = []
    for tool in audit.tools:
        if not tool.installed:
            continue
        version = tool.binaries[0].version if tool.binaries else "?"
        validation = CommandValidation(command=f"claims about {tool.display_name} {version}")
        binary = binaries.get(tool.name)
        registered = claims.get(tool.name, ())
        if binary is None:
            validation.checks.append(
                CheckResult("binary on PATH", passed=False, detail="not found; claims unchecked")
            )
        else:
            found = search_file(Path(binary), [c.marker for c in registered])
            validation.checks.extend(
                CheckResult(
                    f"{claim.label}: '{claim.marker}'",
                    found.get(claim.marker, False),
                    "found in binary" if found.get(claim.marker) else "absent from binary",
                )
                for claim in registered
            )
        out.append(validation)
    return out
