"""Validate that the command-line options work and that their documentation is accurate.

Checks run against the live parser, so a renamed flag, a stale help example, or a tool added
to the registry but not documented is caught by ``ai-footprint --validate``:

* every example command shown in ``--help`` parses and selects tools that exist;
* each example resolves to a concrete tool list on this machine (or says why it cannot);
* every option has help text, and the documented defaults match the real defaults;
* mutually exclusive modes reject being combined;
* every registered tool is named in the help text.
"""

import argparse
import contextlib
import io
import re
import shlex
from collections.abc import Callable, Sequence

from ai_footprint.model import CheckResult, CommandValidation, ToolPresence

Selector = Callable[[Sequence[str], list[ToolPresence]], list[str]]
MODES = ("--list", "--doctor", "--validate")


def help_examples(description: str) -> list[str]:
    """Example command lines in the help text (lines that start with ``ai-footprint``)."""
    examples = []
    for line in description.splitlines():
        stripped = line.strip()
        if stripped.startswith("ai-footprint"):
            examples.append(re.split(r"\s{2,}", stripped, maxsplit=1)[0])
    return examples


def _parse(parser: argparse.ArgumentParser, argv: list[str]) -> argparse.Namespace | str:
    """Parse without exiting the process; returns the namespace or argparse's error text."""
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            return parser.parse_args(argv)
    except SystemExit:
        lines = stderr.getvalue().strip().splitlines()
        return lines[-1] if lines else "exited"


def _example(
    parser: argparse.ArgumentParser,
    command: str,
    presences: list[ToolPresence],
    select: Selector,
) -> CommandValidation:
    validation = CommandValidation(command=command)
    argv = shlex.split(command)[1:]
    parsed = _parse(parser, argv)
    if isinstance(parsed, str):
        validation.checks.append(
            CheckResult("parses with the real parser", passed=False, detail=parsed)
        )
        return validation
    validation.checks.append(CheckResult("parses with the real parser", passed=True, detail="ok"))
    if getattr(parsed, "list", False):
        validation.checks.append(
            CheckResult("selects tools", passed=True, detail="--list audits nothing")
        )
        return validation
    try:
        chosen = select(parsed.tools, presences)
    except SystemExit as exc:
        message = str(exc.code)
        depends = "not installed" in message or "none of the supported" in message
        note = " (the example is valid; it depends on what is installed)" if depends else ""
        validation.checks.append(
            CheckResult("selects tools", passed=depends, detail=message + note)
        )
        return validation
    validation.checks.append(
        CheckResult("selects tools", passed=True, detail=", ".join(chosen) or "none")
    )
    return validation


def _options(parser: argparse.ArgumentParser) -> CommandValidation:
    validation = CommandValidation(command="every option has help text")
    for action in parser._actions:
        if action.help == argparse.SUPPRESS or isinstance(action, argparse._HelpAction):
            continue
        name = "/".join(action.option_strings) or action.dest
        validation.checks.append(
            CheckResult(name, passed=bool(action.help), detail=action.help or "missing help")
        )
    return validation


def _defaults(parser: argparse.ArgumentParser) -> CommandValidation:
    validation = CommandValidation(command="documented defaults match the parser")
    text = parser.format_help()
    for action in parser._actions:
        if action.help and "%(default)s" in action.help:
            shown = str(action.default)
            validation.checks.append(
                CheckResult(
                    "/".join(action.option_strings), passed=shown in text, detail=f"default {shown}"
                )
            )
    return validation


def _modes(parser: argparse.ArgumentParser) -> CommandValidation:
    validation = CommandValidation(command="modes cannot be combined")
    for i, first in enumerate(MODES):
        for second in MODES[i + 1 :]:
            parsed = _parse(parser, [first, second])
            validation.checks.append(
                CheckResult(
                    f"{first} {second} rejected",
                    passed=isinstance(parsed, str),
                    detail=parsed if isinstance(parsed, str) else "accepted",
                )
            )
    return validation


def _tool_names(description: str, tool_names: Sequence[str]) -> CommandValidation:
    validation = CommandValidation(command="help names every supported tool")
    for name in tool_names:
        validation.checks.append(
            CheckResult(
                name,
                passed=name in description,
                detail="named" if name in description else "missing from help",
            )
        )
    return validation


def validate(
    parser: argparse.ArgumentParser,
    description: str,
    presences: list[ToolPresence],
    *,
    select: Selector,
    tool_names: Sequence[str],
) -> list[CommandValidation]:
    """Run every option check.

    Args:
        parser: The real CLI parser.
        description: The help text shown to users (source of examples).
        presences: Detection results, so examples resolve against this machine.
        select: Non-interactive tool selector (the CLI's own logic).
        tool_names: Names in the tool registry.

    Returns:
        One validation per example plus the structural checks.
    """
    results = [_example(parser, cmd, presences, select) for cmd in help_examples(description)]
    if not results:
        results.append(
            CommandValidation(
                command="help examples",
                checks=[
                    CheckResult("examples present", passed=False, detail="no examples in help")
                ],
            )
        )
    return [
        *results,
        _options(parser),
        _defaults(parser),
        _modes(parser),
        _tool_names(description, tool_names),
    ]
