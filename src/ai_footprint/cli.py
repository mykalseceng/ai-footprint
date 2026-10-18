"""Command-line entry point for ai-footprint."""

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from ai_footprint import (
    __version__,
    capture,
    dashboard,
    document,
    figurecheck,
    optioncheck,
    report_html,
    reportcheck,
)
from ai_footprint.audit import TOOLS, detect_tools, run_audit
from ai_footprint.model import NetworkCapture, ToolPresence
from ai_footprint.report_text import (
    Style,
    render_doctor,
    render_list,
    render_summary,
    render_validation,
)
from ai_footprint.system import System

DESCRIPTION = f"""\
Audit the local footprint of AI coding tools ({", ".join(s.display_name for s in TOOLS.values())}):
where they store credentials, sessions and logs, who can read them, what runs automatically,
where they connect, and what a stolen token or account unlocks.

Pick tools by name ({", ".join(TOOLS)}) or "all". With no names, an interactive terminal asks
which installed tools to audit; otherwise every installed tool is audited.

  ai-footprint --list              show supported tools and which are installed
  ai-footprint                     audit installed tools (asks first in a terminal)
  ai-footprint codex opencode      audit only these
  ai-footprint all --html r.html   also write the static report (no scripts)
  ai-footprint all --doctor        each check: review, clear or not checked
  ai-footprint all --capture       also record where each tool connects when started (sudo)
"""


CAPTURE_NAME = "ai-footprint-capture"


class SelectionError(SystemExit):
    """Tool selection could not be satisfied; carries the message as the exit status."""


def build_parser() -> argparse.ArgumentParser:
    """Argument parser for the ``ai-footprint`` command."""
    parser = argparse.ArgumentParser(
        prog="ai-footprint",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "tools",
        nargs="*",
        metavar="TOOL",
        help=f"tools to audit: {', '.join(TOOLS)}, or all (default: installed tools)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="list supported tools and exit")
    mode.add_argument(
        "--doctor",
        action="store_true",
        help="mark each check review, clear or not checked, with validated fixes (no secret scan)",
    )
    mode.add_argument(
        "--validate",
        action="store_true",
        help="verify probe binaries and every fix command; exit 1 on any failure",
    )
    parser.add_argument(
        "--dashboard",
        type=Path,
        default=Path("ai-footprint-dashboard.html"),
        help="dashboard path (default: %(default)s)",
    )
    parser.add_argument(
        "--html", type=Path, help="also write the static report (no scripts) to this path"
    )
    parser.add_argument("--json", type=Path, help="also write the data the dashboard shows as JSON")
    parser.add_argument(
        "--live",
        action="store_true",
        help="allow network checks: Anthropic token liveness (token sent to "
        "Anthropic only) and OpenAI JWT signature verification (public JWKS)",
    )
    network = parser.add_mutually_exclusive_group()
    network.add_argument(
        "--capture",
        action="store_true",
        help=f"launch each selected tool idle for {capture.SECONDS:.0f}s, with no prompt, under a "
        "sudo packet capture, and show every host it reached; saves "
        f"{CAPTURE_NAME}.pcapng and .json next to the dashboard",
    )
    network.add_argument(
        "--network", type=Path, help="show a capture saved earlier by --capture (its .json)"
    )
    parser.add_argument("--workers", type=int, help="secret-scan processes (default: CPU count)")
    parser.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"ai-footprint {__version__}")
    return parser


def _parse_choice(answer: str, installed: list[ToolPresence]) -> list[str]:
    """Turn a prompt answer ("", "all", "1 3", "codex,claude") into tool names."""
    words = answer.replace(",", " ").split()
    if not words or words == ["all"]:
        return [p.name for p in installed]
    chosen = []
    for word in words:
        if word.isdigit() and 1 <= int(word) <= len(installed):
            chosen.append(installed[int(word) - 1].name)
        elif word in {p.name for p in installed}:
            chosen.append(word)
        else:
            raise SelectionError(f"ai-footprint: '{word}' is not one of the listed choices")
    return list(dict.fromkeys(chosen))


def select_tools(
    requested: Sequence[str],
    presences: list[ToolPresence],
    *,
    ask: Callable[[str], str] | None,
) -> list[str]:
    """Resolve which tools to audit.

    Args:
        requested: Names given on the command line (may include "all").
        presences: Detection results for every supported tool.
        ask: Prompt function for interactive choice, or None when not interactive.

    Returns:
        Tool names to audit, in registry order.

    Raises:
        SelectionError: A name is unknown, a named tool is not installed, or nothing is installed.
    """
    installed = [p for p in presences if p.installed]
    unknown = sorted(set(requested) - set(TOOLS) - {"all"})
    if unknown:
        raise SelectionError(
            f"ai-footprint: unknown tool(s) {', '.join(unknown)}; choose from "
            f"{', '.join(TOOLS)} or all"
        )
    if not installed:
        raise SelectionError(
            f"ai-footprint: none of the supported tools ({', '.join(TOOLS)}) are installed"
        )
    if "all" in requested:
        return [p.name for p in installed]
    if requested:
        missing = [name for name in requested if name not in {p.name for p in installed}]
        if missing:
            raise SelectionError(
                f"ai-footprint: {', '.join(missing)} not installed; installed: "
                f"{', '.join(p.name for p in installed)}"
            )
        return [name for name in TOOLS if name in requested]
    if ask is None:
        return [p.name for p in installed]
    menu = "\n".join(
        f"  {i}) {p.display_name} ({p.name})" for i, p in enumerate(installed, start=1)
    )
    answer = ask(f"Installed AI tools:\n{menu}\nAudit which? [Enter = all, or numbers/names]: ")
    return _parse_choice(answer, installed)


def write_private(path: Path, text: str) -> None:
    """Write a report readable only by the current user (mode 600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    path.chmod(0o600)


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _network(
    args: argparse.Namespace, system: System, selected: list[ToolPresence]
) -> NetworkCapture | None:
    """Run the packet capture, or load a saved one, when asked to.

    Raises:
        capture.CaptureError: The capture could not run, or the saved file is unreadable.
    """
    if (args.capture or args.network) and (args.doctor or args.validate):
        raise capture.CaptureError("--capture and --network go with a full audit only")
    if args.network:
        return capture.load(args.network)
    if not args.capture:
        return None
    launchable = [p for p in selected if p.binaries]
    if not launchable:
        raise capture.CaptureError("none of the selected tools has a binary on PATH to launch")
    names = ", ".join(p.display_name for p in launchable)
    print(
        f"Capturing network traffic while {names} each start idle for {capture.SECONDS:.0f}s; "
        "sudo asks for your password to start tcpdump…",
        file=sys.stderr,
    )
    path = args.dashboard.with_name(f"{CAPTURE_NAME}.pcapng")
    found = capture.record(system, launchable, path)
    write_private(path.with_suffix(".json"), capture.dumps(found))
    return found


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = build_parser().parse_args(argv)
    style = Style.for_stream(isatty=sys.stdout.isatty())
    system = System()
    presences = detect_tools(system=system, home=args.home)
    if args.list:
        print(render_list(presences, style, home=str(args.home)))
        return 0
    tools = select_tools(args.tools, presences, ask=input if _interactive() else None)
    quick = args.doctor or args.validate
    try:
        network = _network(args, system, [p for p in presences if p.name in tools])
    except capture.CaptureError as exc:
        print(f"ai-footprint: {exc}", file=sys.stderr)
        return 2
    if not quick:
        names = ", ".join(TOOLS[name].display_name for name in tools)
        print(f"Auditing {names} (full secret scan)…", file=sys.stderr)
    audit, checklist = run_audit(
        system=system,
        home=args.home,
        tools=tools,
        live=args.live,
        scan=not quick,
        workers=args.workers,
        presences=presences,
    )
    audit.network = network
    if args.validate:
        audit.option_validation = optioncheck.validate(
            build_parser(),
            DESCRIPTION,
            presences,
            select=lambda names, found: select_tools(names, found, ask=None),
            tool_names=list(TOOLS),
        )
        data = document.build(audit, checklist)
        audit.report_validation = [
            *reportcheck.check_report(report_html.render(audit, checklist, data["views"])),
            *reportcheck.check_document(data),
            reportcheck.check_wording(data, dashboard.script()),
        ]
        audit.figure_validation = figurecheck.check_figures(data)
        text, code = render_validation(audit, style)
        print(text)
        return code
    if args.doctor:
        text, code = render_doctor(audit, checklist, style)
        print(text)
        return code
    data = document.build(audit, checklist)
    write_private(args.dashboard, dashboard.render(data))
    outputs = [("Dashboard", str(args.dashboard.resolve()))]
    if args.html:
        write_private(args.html, report_html.render(audit, checklist, data["views"]))
        outputs.append(("Report", str(args.html.resolve())))
    if args.json:
        write_private(args.json, json.dumps(data, indent=2, ensure_ascii=False))
        outputs.append(("Data", str(args.json.resolve())))
    print(render_summary(audit, style, outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
