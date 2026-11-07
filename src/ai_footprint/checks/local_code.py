"""Checks for what any program running as you on this machine can take or run."""

import re
from pathlib import Path

from ai_footprint import daemons
from ai_footprint.checks.base import RuleContext, exposure, quote
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import (
    BinaryInfo,
    Daemon,
    Exposure,
    Extension,
    Fix,
    FixCommand,
    Lens,
    StoreKind,
    ToolReport,
)
from ai_footprint.text import join, plural


def rule_keychain_silent(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Keychain items any same-user process can read without a prompt."""
    del ctx
    silent = [
        c
        for c in report.credentials
        if c.store is StoreKind.KEYCHAIN and c.silent_read_seconds is not None
    ]
    if not silent:
        return []
    return [
        exposure(
            report,
            "keychain-silent",
            Lens.CODE,
            f"Any program running as you can read the {report.display_name} token from the "
            "Keychain with one `security find-generic-password -w` call and no prompt. This "
            "audit did exactly that.",
            evidence=[c.protection for c in silent],
            fix=Fix(
                "Stop the model from running the read; detect it everywhere else",
                [
                    FixCommand(
                        'Add "Bash(security find-generic-password*)" and '
                        '"Bash(security dump-keychain*)" to permissions.deny',
                        manual=True,
                    ),
                    FixCommand(
                        "Alert in EDR when anything but the tool reads its Keychain item",
                        manual=True,
                    ),
                ],
            ),
        )
    ]


def rule_plaintext_credentials(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Credentials stored without OS protection."""
    plain = [c for c in report.credentials if c.store in {StoreKind.FILE, StoreKind.SQLITE}]
    if not plain:
        return []
    providers = sorted({c.provider for c in plain})
    stores = sorted({ctx.display(c.location) for c in plain})
    return [
        exposure(
            report,
            "creds-plaintext",
            Lens.CODE,
            f"{report.display_name} keeps credentials for {', '.join(providers)} in plaintext "
            f"({', '.join(stores)}). Any program running as you can copy them.",
            evidence=[f"{c.provider}: {ctx.display(c.location)} [{c.store}]" for c in plain],
            fix=ctx.remedy(report, Remedy.PROTECT_CREDENTIALS)
            or Fix(
                "Keep credentials in the OS credential store",
                [
                    FixCommand(
                        "Prefer OAuth login stored in the Keychain over keys in files", manual=True
                    )
                ],
            ),
        )
    ]


def rule_secrets(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Secrets kept in transcripts, history and logs."""
    del ctx
    scan = report.secret_scan
    if scan is None or not scan.kinds:
        return []
    out = []
    current = scan.current_credential_values
    if current:
        out.append(
            exposure(
                report,
                "live-token-on-disk",
                Lens.CODE,
                f"{plural(current, f'current {report.display_name} credential')} "
                f"{'is' if current == 1 else 'are'} copied into data files outside "
                f"{'its' if current == 1 else 'their'} credential store.",
                evidence=scan.current_credential_hits[:10],
                fix=Fix(
                    "Rotate the credential and delete the copies",
                    [
                        FixCommand(
                            "Rotate API keys in the provider's console and log out and back in "
                            "for logins, then delete the listed files",
                            manual=True,
                        )
                    ],
                ),
            )
        )
    total = sum(k.unique for k in scan.kinds)
    ranked = sorted(scan.kinds, key=lambda k: k.unique, reverse=True)
    kinds = ", ".join(f"{k.unique} {k.label}" for k in ranked[:4])
    if len(ranked) > 4:
        kinds += f" and {len(ranked) - 4} more types"
    others = "" if total > current else " Each is a current credential of this tool."
    out.append(
        exposure(
            report,
            "secrets-at-rest",
            Lens.CODE,
            f"{report.display_name} data files hold {total} distinct secret-shaped values: "
            f"{kinds}.{others}",
            evidence=[
                f"{k.label}: e.g. {k.locations[0] if k.locations else '?'}" for k in scan.kinds
            ],
            fix=Fix(
                "Rotate real secrets, then delete or redact the files",
                [
                    FixCommand(
                        "Rotate each real key at its provider; delete the transcripts holding it",
                        manual=True,
                    )
                ],
            ),
        )
    )
    return out


def rule_autostart(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Code that runs automatically: persistence points."""
    del ctx
    auto = [e for e in report.extensions if e.autostart and e.kind != "connector"]
    if not auto:
        return []
    return [
        exposure(
            report,
            "autostart",
            Lens.CODE,
            f"{report.display_name} is set up to run local code automatically from "
            f"{plural(len(auto), 'place')} ({join(_kind_counts(auto))}). Whoever can change "
            "those commands, or the files they run, controls code that runs as you.",
            evidence=[f"{e.kind}: {e.name} → {e.detail[:120]}" for e in auto[:12]],
            fix=Fix(
                "Monitor these files for changes",
                [
                    FixCommand(
                        "Add the listed scripts and config files to file-integrity monitoring",
                        manual=True,
                    )
                ],
            ),
        )
    ]


def _kind_counts(extensions: list[Extension]) -> list[str]:
    names = {
        "mcp": "MCP server",
        "hook": "hook",
        "native-host": "browser native host",
        "statusline": "status line",
        "plugin": "plugin",
    }
    counts: dict[str, int] = {}
    for ext in extensions:
        counts[ext.kind] = counts.get(ext.kind, 0) + 1
    return [f"{n} {names.get(k, k)}{'s' if n > 1 else ''}" for k, n in counts.items()]


def _daemon_line(daemon: Daemon, home: Path) -> str:
    what, listens, notes = daemons.describe(daemon, str(home))
    facts = [daemons.running(daemon), *listens, *notes]
    return f"pid {daemon.pid} `{what}` ({'; '.join(facts)})"


def _daemon_fix(report: ToolReport, ctx: RuleContext, daemons: list[Daemon]) -> Fix:
    pids = " ".join(str(d.pid) for d in daemons)
    return ctx.remedy(report, Remedy.STOP_DAEMONS) or Fix(
        "Stop the processes you did not mean to leave running", [FixCommand(f"kill {pids}")]
    )


def _open_to_others(mode: str) -> bool:
    """An octal mode whose group or other bits are set, so other accounts can connect."""
    return bool(mode) and mode[-2:] != "00"


def rule_daemons(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Processes launchd started for the tool, and session processes that accept connections."""
    detached = [d for d in report.daemons if d.detached]
    servers = [
        d
        for d in report.daemons
        if not d.detached
        and any(ln.kind == "tcp" or _open_to_others(ln.mode) for ln in d.listeners)
    ]
    if not detached and not servers:
        return []
    parts = []
    if detached:
        count = f"{len(detached)} background process{'es' if len(detached) != 1 else ''}"
        parts.append(
            f"{report.display_name} keeps {count} running outside any session (started by "
            f"launchd): {join([_daemon_line(d, ctx.home) for d in detached])}."
        )
    if servers:
        parts.append(
            f"{report.display_name} sessions accept connections: "
            f"{join([_server_line(d, ctx.home) for d in servers])}."
        )
    fix = _daemon_fix(report, ctx, detached) if detached else Fix("Stop servers you no longer use")
    fix.commands += [
        FixCommand(
            f"Stop pid {d.pid} (started by session pid {d.ppid}) when you no longer need it",
            manual=True,
        )
        for d in servers
    ]
    return [
        exposure(
            report,
            "daemons",
            Lens.CODE,
            " ".join(parts),
            evidence=[
                f"pid {d.pid} (parent {d.ppid}) started {d.started}: {d.command}"
                for d in detached + servers
            ],
            fix=fix,
        )
    ]


def _server_line(daemon: Daemon, home: Path) -> str:
    what, listens, _notes = daemons.describe(daemon, str(home))
    where = "; ".join(listens)
    return f"pid {daemon.pid} `{what}`, started by session pid {daemon.ppid}, on {where}"


def rule_dangling(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Autostart commands pointing at missing files, one statement per missing target."""
    by_target: dict[str, list[tuple[str, str]]] = {}
    for ext in report.extensions:
        if ext.dangling:
            by_target.setdefault(ext.detail, []).append((ext.name, ext.source))
    out = []
    for index, (target, entries) in enumerate(by_target.items()):
        scopes = join([source for _name, source in entries])
        commands = [
            c for name, source in entries for c in _dangling_fix(report, ctx, name, source).commands
        ]
        out.append(
            exposure(
                report,
                f"dangling-{index}",
                Lens.CODE,
                f"{report.display_name} starts `{target}` at launch ({scopes}), but that file is "
                "missing. Whoever creates it runs code every time the tool starts.",
                evidence=[f"{name} ({source})" for name, source in entries],
                fix=Fix("Remove the entries that point at the missing file", commands),
            )
        )
    return out


def _dangling_fix(report: ToolReport, ctx: RuleContext, name: str, source: str) -> Fix:
    return ctx.remedy(report, Remedy.REMOVE_MCP, name=name, source=source) or Fix(
        "Remove the server entry",
        [FixCommand(f"Delete the {name} server entry from the tool's config", manual=True)],
    )


def rule_duplicate_installs(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Several installs of one tool, where PATH order decides which runs."""
    if len(report.binaries) < 2 or len({b.version for b in report.binaries}) < 2:
        return []
    first = report.binaries[0]
    newest = max(report.binaries, key=lambda b: _version_key(b.version))
    older = [b for b in report.binaries if _version_key(b.version) < _version_key(newest.version)]
    running = {p.command.split()[0] for p in report.processes if p.command}
    commands = [_remove_install(b) for b in older]
    if first in older:
        commands.append(
            FixCommand(
                f"Or put {Path(newest.path).parent} ahead of {Path(first.path).parent} on PATH",
                manual=True,
            )
        )
    copies = join(
        [f"{b.version or 'unknown version'} at `{ctx.display(b.path)}`" for b in report.binaries]
    )
    statement = (
        f"{len(report.binaries)} copies of {report.display_name} are installed: {copies}. "
        f"A shell runs the first on PATH, {first.version or 'of unknown version'}"
    )
    statement += f", which is older than {newest.version}." if first in older else ", the newest."
    return [
        exposure(
            report,
            "duplicate-installs",
            Lens.CODE,
            statement,
            evidence=[
                f"{'first on PATH' if b is first else 'later on PATH'}: {b.path} → {b.resolved} "
                f"v{b.version or '?'}"
                + ("; a running process uses it" if b.resolved in running else "")
                for b in report.binaries
            ],
            fix=Fix("Remove the older install", commands),
        )
    ]


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric parts of a version for ordering; an unknown version sorts first."""
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _remove_install(binary: BinaryInfo) -> FixCommand:
    package = _npm_package(binary.resolved)
    if package:
        return FixCommand(f"npm uninstall -g {quote(package)}")
    return FixCommand(f"Remove {binary.path} ({binary.resolved}) v{binary.version}", manual=True)


def _npm_package(resolved: str) -> str:
    parts = Path(resolved).parts
    if "node_modules" not in parts:
        return ""
    index = parts.index("node_modules")
    name = parts[index + 1] if index + 1 < len(parts) else ""
    if name.startswith("@") and index + 2 < len(parts):
        return f"{name}/{parts[index + 2]}"
    return name
