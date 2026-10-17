"""Turn collected facts into plain statements of exposure, each with a validated fix.

There are no severity ratings. Each exposure is filed under the attacker position it serves
(``Lens``): a stolen token, code running as you, text steering the model, or another local
account. Each rule also has a checklist title, so ``--doctor`` can say which checks are clear.
Fix commands carry the hints the validator needs: ``--help`` probes that prove a subcommand
exists, and binary markers that prove a recommended config key is real.
"""

import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from ai_footprint import daemons
from ai_footprint.fsinfo import tilde
from ai_footprint.host import first_system_index
from ai_footprint.model import (
    AuditReport,
    Category,
    Daemon,
    Exposure,
    Extension,
    Fix,
    FixCommand,
    HostFact,
    HostReport,
    Lens,
    ToolReport,
)
from ai_footprint.surface import join, plural


@dataclass
class RuleContext:
    """Inputs shared by all rules."""

    host: HostReport
    platform: str
    home: Path
    facts: dict[str, dict[str, Any]] = field(default_factory=dict)

    def display(self, path: str) -> str:
        """Path with home shown as ~."""
        return tilde(path, str(self.home))


ToolRuleFn = Callable[[ToolReport, RuleContext], list[Exposure]]
HostRuleFn = Callable[[AuditReport, RuleContext], list[Exposure]]


def _always(report: ToolReport, ctx: RuleContext) -> str:
    del report, ctx
    return ""


@dataclass(frozen=True)
class Rule:
    """A check with a checklist title and the function that states exposures.

    Attributes:
        needs: Why this check cannot run on this tool's data ("" when it can). A check whose
            input was never recorded is reported as not checked, never as clear.
    """

    id: str
    check: str
    fn: ToolRuleFn
    needs: Callable[[ToolReport, RuleContext], str] = _always


@dataclass(frozen=True)
class HostRule:
    """A check spanning tools or the host."""

    id: str
    check: str
    fn: HostRuleFn


class Check(NamedTuple):
    """One checklist line: a finding list, or why the check could not run."""

    scope: str
    check: str
    found: list[Exposure]
    unchecked: str = ""


Checklist = list[Check]

LABELS = {
    "no-approval": "Approval prompts skipped",
    "instructions": "Instruction file steers the model",
    "token-reach": "Token carries connector scopes",
    "shared": "Sessions on public share links",
    "keychain-silent": "Keychain token readable without a prompt",
    "creds-plaintext": "Credentials in plaintext",
    "live-token-on-disk": "Live credentials copied into data files",
    "secrets-at-rest": "Secret-shaped values in history and logs",
    "secrets": "Secret-shaped values in history and logs",
    "autostart": "Code that runs automatically",
    "daemons": "Background processes outlive sessions",
    "dangling": "Autostart command points at a missing file",
    "duplicate-installs": "Stale second install",
    "creds-readable": "Credentials readable by other accounts",
    "data-readable": "Data readable by other accounts",
    "open-server": "Local server without a password",
    "path-hijack": "Writable folders ahead of /usr/bin",
    "binary-dirs": "Tool launchers in writable folders",
    "other-accounts": "Other local accounts",
    "shared-surfaces": "One folder steers several tools",
    "duplicate-creds": "Same credentials stored twice",
    "trust": "Trusted folders",
    "account-data": "Work shared with provider services",
    "account-signals": "Signs of use elsewhere",
    "inherited-creds": "Other credentials an agent inherits",
    "computer-control": "Software that can drive the computer",
    "backups": "History copied into backups",
    "unattended": "Processes running without a session",
    "other-tools": "Other AI tools on this machine",
}


def _label(rule_id: str) -> str:
    for key, label in sorted(LABELS.items(), key=lambda item: len(item[0]), reverse=True):
        if rule_id.startswith(key):
            return label
    return rule_id


def _q(path: str) -> str:
    return shlex.quote(path)


def _exposure(
    report: ToolReport,
    rule_id: str,
    lens: Lens,
    statement: str,
    *,
    evidence: list[str] | None = None,
    fix: Fix | None = None,
) -> Exposure:
    return Exposure(
        id=f"{report.name}:{rule_id}",
        tool=report.name,
        lens=lens,
        statement=statement,
        label=_label(rule_id),
        evidence=evidence or [],
        fix=fix,
    )


# --- through the model --------------------------------------------------------------------------

NO_APPROVAL = {
    "permissions.defaultMode": "bypassPermissions",
    "approval_policy": "never",
    "sandbox_mode": "danger-full-access",
}
RUNNING_BYPASS = "running with --dangerously-skip-permissions"
THREADS_WITHOUT_APPROVAL = "threads with approval_mode=never"
"""Setting values that turn approval off, the setting that lists sessions started that way, and
the setting that counts recorded threads that ran with approval off."""
APPROVAL_KEYS = frozenset({*NO_APPROVAL, RUNNING_BYPASS, THREADS_WITHOUT_APPROVAL})
"""Every setting the no-approval check reads."""


def rule_no_approval(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Commands run without approval or sandbox: a config value, or sessions started that way."""
    configured = [s for s in report.settings if NO_APPROVAL.get(s.key) == s.value]
    running = [s for s in report.settings if s.key == RUNNING_BYPASS]
    threads = [s for s in report.settings if s.key == THREADS_WITHOUT_APPROVAL and s.concern]
    if not configured and not running and not threads:
        return []
    observed = [f"{s.key} = {s.value}" for s in configured]
    observed += [
        f"{plural(len(s.value.split(', ')), 'running session')} started with "
        "--dangerously-skip-permissions"
        for s in running
    ]
    observed += [f"{s.key}: {s.value}" for s in threads]
    return [
        _exposure(
            report,
            "no-approval",
            Lens.MODEL,
            f"{report.display_name} skips approval prompts in some sessions "
            f"({join(observed)}). In those sessions, text that reaches the model (a web page, a "
            "repo file, an MCP result, an instruction file) can become commands running as you, "
            "limited only by the deny rules and hooks that still apply.",
            evidence=[f"{s.key} = {s.value}" for s in configured + running + threads],
            fix=_no_approval_fix(report, ctx),
        )
    ]


def _no_approval_fix(report: ToolReport, ctx: RuleContext) -> Fix:
    if report.name == "claude":
        policy = (
            "/Library/Application Support/ClaudeCode"
            if ctx.platform == "darwin"
            else "/etc/claude-code"
        )
        target = _q(f"{policy}/managed-settings.json")
        payload = '{"permissions":{"disableBypassPermissionsMode":"disable"}}'
        return Fix(
            "Block bypass mode with a root-owned managed policy, then drop the alias",
            [
                FixCommand(f"sudo mkdir -p {_q(policy)}"),
                FixCommand(
                    f"echo {_q(payload)} | sudo tee {target}",
                    markers=("disableBypassPermissionsMode", "managed-settings.json"),
                    marker_tool="claude",
                ),
                FixCommand(
                    "Remove shell aliases that add --dangerously-skip-permissions", manual=True
                ),
            ],
        )
    if report.name == "codex":
        return Fix(
            "Require approval and restore the sandbox in ~/.codex/config.toml",
            [
                FixCommand(
                    'Set approval_policy = "on-request" and sandbox_mode = "workspace-write"',
                    manual=True,
                    markers=("on-request", "workspace-write"),
                    marker_tool="codex",
                )
            ],
        )
    return Fix(
        "Require approval for shell and edit tools",
        [
            FixCommand(
                'Add "permission": {"bash": "ask", "edit": "ask"} to the opencode config',
                manual=True,
                markers=('"ask"',),
                marker_tool=report.name,
            )
        ],
    )


_LOADED_AS = {
    "global": "is read as your instructions every session",
    "project": "is read as your instructions in that project",
    "memory": "is the auto-memory index loaded every session in that project",
    "agent": "defines a subagent",
    "command": "defines a slash command",
}


def rule_instructions(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Instruction files whose content steers the model."""
    flagged = [f for f in report.instructions if f.markers and f.loaded_by[0] == report.name]
    return [
        _exposure(
            report,
            f"instructions-{index}",
            Lens.MODEL,
            f"{ctx.display(f.path)} {_LOADED_AS.get(f.scope, 'is loaded')} and contains "
            f"{'; '.join(f.markers)}.",
            evidence=[f"loaded by {', '.join(f.loaded_by)}; mode {f.mode}"],
            fix=Fix(
                "Review and remove the flagged lines",
                [
                    FixCommand(
                        f"Edit {ctx.display(f.path)} and delete what you did not write or "
                        "no longer need",
                        manual=True,
                    )
                ],
            ),
        )
        for index, f in enumerate(flagged)
    ]


# --- from anywhere, with a stolen token ---------------------------------------------------------


CONNECTOR_SCOPES = ("user:mcp_servers", "api.connectors.read", "api.connectors.invoke")


def rule_token_reach(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Tokens whose scopes name the provider's connectors."""
    del ctx
    scopes = sorted(
        {
            scope
            for c in report.credentials
            for t in c.tokens
            for scope in t.scopes
            if scope in CONNECTOR_SCOPES
        }
    )
    if not scopes:
        return []
    connectors = [e.name for e in report.extensions if e.kind == "connector"]
    used = (
        f" This CLI has connected to {join(connectors)} (recorded in ~/.claude.json)."
        if connectors
        else ""
    )
    return [
        _exposure(
            report,
            "token-reach",
            Lens.REMOTE,
            f"The {report.display_name} token carries {plural(len(scopes), 'connector scope')}: "
            f"{', '.join(scopes)}.{used}",
            evidence=scopes + connectors,
            fix=Fix(
                "Disconnect connectors you do not use (the token keeps its scopes)",
                [
                    FixCommand(
                        "Remove unused connectors in the provider's web settings", manual=True
                    )
                ],
            ),
        )
    ]


def rule_shared_sessions(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Sessions published to share links."""
    del ctx
    shared = [s for s in report.settings if s.key == "shared sessions" and s.value not in {"0", ""}]
    auto = [s for s in report.settings if s.key == "share" and s.value == "auto"]
    if not shared and not auto:
        return []
    return [
        _exposure(
            report,
            "shared",
            Lens.REMOTE,
            "Sessions are published to share links; anyone with a link can read them.",
            evidence=[f"{s.key} = {s.value}" for s in shared + auto],
            fix=Fix(
                "Unshare and turn off auto-share",
                [
                    FixCommand(
                        'Set "share": "disabled" in the opencode config',
                        manual=True,
                        markers=("disabled",),
                        marker_tool="opencode",
                    )
                ],
            ),
        )
    ]


# --- running as you on this machine -------------------------------------------------------------


def rule_keychain_silent(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Keychain items any same-user process can read without a prompt."""
    del ctx
    silent = [
        c
        for c in report.credentials
        if c.store == "macOS Keychain" and "without a prompt" in c.protection
    ]
    if not silent:
        return []
    return [
        _exposure(
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
    plain = [c for c in report.credentials if "plaintext" in c.store or "SQLite" in c.store]
    if not plain:
        return []
    providers = sorted({c.provider for c in plain})
    stores = sorted({ctx.display(c.location) for c in plain})
    return [
        _exposure(
            report,
            "creds-plaintext",
            Lens.CODE,
            f"{report.display_name} keeps credentials for {', '.join(providers)} in plaintext "
            f"({', '.join(stores)}). Any program running as you can copy them.",
            evidence=[f"{c.provider}: {ctx.display(c.location)} [{c.store}]" for c in plain],
            fix=_plaintext_fix(report),
        )
    ]


def _plaintext_fix(report: ToolReport) -> Fix:
    if report.name == "codex":
        return Fix(
            "Move Codex tokens into the OS keyring",
            [
                FixCommand(
                    'Add cli_auth_credentials_store = "keyring" to ~/.codex/config.toml',
                    manual=True,
                    markers=("cli_auth_credentials_store", "keyring"),
                    marker_tool="codex",
                ),
                FixCommand("codex logout", help_probe=("codex", "logout")),
                FixCommand("codex login", help_probe=("codex", "login")),
            ],
        )
    if report.name == "opencode":
        return Fix(
            "Remove provider credentials you no longer use",
            [
                FixCommand("opencode auth list", help_probe=("opencode", "auth", "list")),
                FixCommand("opencode auth logout", help_probe=("opencode", "auth", "logout")),
            ],
        )
    if report.name == "pi":
        return Fix(
            "Remove provider credentials you no longer use",
            [
                FixCommand(
                    "Run /logout for the provider in pi, or delete its entry from "
                    "~/.pi/agent/auth.json",
                    manual=True,
                    markers=('"auth.json"',),
                    marker_tool="pi",
                )
            ],
        )
    return Fix(
        "Keep credentials in the OS credential store",
        [FixCommand("Prefer OAuth login stored in the Keychain over keys in files", manual=True)],
    )


def rule_secrets(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Secrets kept in transcripts, history and logs."""
    del ctx
    scan = report.secret_scan
    if scan is None or not scan.kinds:
        return []
    out = []
    if scan.current_credential_hits:
        out.append(
            _exposure(
                report,
                "live-token-on-disk",
                Lens.CODE,
                f"Current {report.display_name} credentials are copied into data files outside "
                "their credential store.",
                evidence=scan.current_credential_hits[:10],
                fix=Fix(
                    "Rotate the credential and delete the copies",
                    [FixCommand("Log out and back in, then delete the listed files", manual=True)],
                ),
            )
        )
    total = sum(k.unique for k in scan.kinds)
    ranked = sorted(scan.kinds, key=lambda k: k.unique, reverse=True)
    kinds = ", ".join(f"{k.unique} {k.label}" for k in ranked[:4])
    if len(ranked) > 4:
        kinds += f" and {len(ranked) - 4} more types"
    out.append(
        _exposure(
            report,
            "secrets-at-rest",
            Lens.CODE,
            f"{report.display_name} data files hold {total} distinct secret-shaped values: "
            f"{kinds}. "
            "Some may be test data from targets you worked on.",
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
        _exposure(
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


def _daemon_fix(report: ToolReport, daemons: list[Daemon]) -> Fix:
    if report.name == "codex":
        return Fix(
            "Stop the managed daemon and its updater, and turn auto-start off",
            [
                FixCommand(
                    "codex app-server daemon stop",
                    help_probe=("codex", "app-server", "daemon", "stop"),
                ),
                FixCommand("pkill -f 'app-server daemon pid-update-loop'"),
                FixCommand(
                    "codex features disable daemon_auto_start",
                    help_probe=("codex", "features", "disable"),
                    markers=("daemon_auto_start",),
                    marker_tool="codex",
                ),
            ],
        )
    pids = " ".join(str(d.pid) for d in daemons)
    return Fix("Stop the processes you did not mean to leave running", [FixCommand(f"kill {pids}")])


def _open_to_others(mode: str) -> bool:
    """An octal mode whose group or other bits are set, so other accounts can connect."""
    return bool(mode) and mode[-2:] != "00"


def rule_daemons(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Processes launchd started for the tool, or that listen beyond a session's own socket."""
    found = [
        d
        for d in report.daemons
        if d.detached or any(ln.kind == "tcp" or _open_to_others(ln.mode) for ln in d.listeners)
    ]
    if not found:
        return []
    count = f"{len(found)} background process{'es' if len(found) != 1 else ''}"
    return [
        _exposure(
            report,
            "daemons",
            Lens.CODE,
            f"{report.display_name} keeps {count} running outside any session: "
            f"{join([_daemon_line(d, ctx.home) for d in found])}.",
            evidence=[f"pid {d.pid} started {d.started}: {d.command}" for d in found],
            fix=_daemon_fix(report, found),
        )
    ]


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
            c
            for name, source in entries
            for c in _dangling_fix(report, name, source, ctx.home).commands
        ]
        out.append(
            _exposure(
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


def _claude_dangling_fix(name: str, source: str, home: Path) -> Fix:
    if source.startswith("plugin "):
        plugin = source.removeprefix("plugin ")
        return Fix(
            "Disable the plugin that ships the server",
            [
                FixCommand(
                    f"claude plugin disable {_q(plugin)}",
                    help_probe=("claude", "plugin", "disable"),
                )
            ],
        )
    if source == "user":
        return Fix(
            "Remove the server entry",
            [
                FixCommand(
                    f"claude mcp remove {_q(name)} -s user",
                    help_probe=("claude", "mcp", "remove"),
                )
            ],
        )
    project = source.removeprefix("project ")
    project = str(home) + project[1:] if project.startswith("~") else project
    if not Path(project).is_dir():
        return Fix(
            "Remove the server entry",
            [
                FixCommand(
                    f'Delete projects["{project}"].mcpServers.{name} from ~/.claude.json '
                    "(the project folder is gone, so `claude mcp remove` cannot target it)",
                    manual=True,
                )
            ],
        )
    return Fix(
        "Remove the server entry",
        [
            FixCommand(
                f"cd {_q(project)} && claude mcp remove {_q(name)} -s local",
                help_probe=("claude", "mcp", "remove"),
            )
        ],
    )


def _dangling_fix(report: ToolReport, name: str, source: str, home: Path) -> Fix:
    if report.name == "claude":
        return _claude_dangling_fix(name, source, home)
    if report.name == "codex":
        return Fix(
            "Remove the server entry",
            [FixCommand(f"codex mcp remove {_q(name)}", help_probe=("codex", "mcp", "remove"))],
        )
    if report.name == "pi":
        return Fix(
            "Remove the server entry",
            [FixCommand(f"pi mcp remove {_q(name)}", help_probe=("pi", "mcp", "remove"))],
        )
    return Fix(
        "Remove the server entry",
        [FixCommand(f"Delete mcp.{name} from the opencode config", manual=True)],
    )


def rule_duplicate_installs(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Several installs of one tool, where PATH order decides which runs."""
    del ctx
    if len(report.binaries) < 2 or len({b.version for b in report.binaries}) < 2:
        return []
    active, *shadowed = report.binaries
    commands = []
    for binary in shadowed:
        package = _npm_package(binary.resolved)
        if package:
            commands.append(FixCommand(f"npm uninstall -g {_q(package)}"))
        else:
            commands.append(FixCommand(f"Remove {binary.path} ({binary.resolved})", manual=True))
    return [
        _exposure(
            report,
            "duplicate-installs",
            Lens.CODE,
            f"{len(report.binaries)} copies of {report.display_name} are installed with different "
            "versions. PATH order decides which runs; the stale copy gets no updates.",
            evidence=[
                f"{'active' if b is active else 'shadowed'}: {b.path} → {b.resolved} "
                f"v{b.version or '?'}"
                for b in report.binaries
            ],
            fix=Fix("Remove the stale install", commands),
        )
    ]


def _npm_package(resolved: str) -> str:
    parts = Path(resolved).parts
    if "node_modules" not in parts:
        return ""
    index = parts.index("node_modules")
    name = parts[index + 1] if index + 1 < len(parts) else ""
    if name.startswith("@") and index + 2 < len(parts):
        return f"{name}/{parts[index + 2]}"
    return name


# --- from another account on this machine -------------------------------------------------------


def rule_credentials_exposed(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Credential stores readable by other local accounts."""
    exposed = [c for c in report.credentials if c.readable_by_others]
    if not exposed:
        return []
    others = ", ".join(ctx.host.other_users) or "any future local account"
    paths = sorted({c.location for c in exposed})
    commands = [FixCommand(f"chmod 600 {_q(p)}") for p in paths if Path(p).is_file()]
    commands += [
        FixCommand(f"chmod 700 {_q(str(Path(p).parent))}") for p in paths if Path(p).is_file()
    ]
    commands.append(FixCommand("Rotate every credential listed: assume it was copied", manual=True))
    providers = sorted({c.provider for c in exposed})
    return [
        _exposure(
            report,
            "creds-readable",
            Lens.ACCOUNT,
            f"{others} can read {len(exposed)} {report.display_name} credential(s) "
            f"({', '.join(providers)}) straight from {', '.join(ctx.display(p) for p in paths)}.",
            evidence=[f"{c.provider}: {c.protection}" for c in exposed],
            fix=Fix("Restrict the files, then rotate the credentials", commands),
        )
    ]


def rule_exposed_data(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Session, config and log data readable by other accounts, directly or through a group."""
    shared_groups = {g for groups in ctx.host.other_user_groups.values() for g in groups}
    exposed = [
        a
        for a in report.artifacts
        if (a.other_readable or a.group_readable in shared_groups)
        and a.category in {Category.SESSION, Category.CONFIG, Category.LOG, Category.INSTRUCTIONS}
    ]
    if not exposed or not ctx.host.other_users:
        return []
    return [
        _exposure(
            report,
            "data-readable",
            Lens.ACCOUNT,
            f"{', '.join(ctx.host.other_users)} can read {len(exposed)} {report.display_name} "
            f"data stores, including {', '.join(a.label.lower() for a in exposed[:4])}.",
            evidence=[f"{ctx.display(a.path)} ({a.mode}): {a.description}" for a in exposed[:12]],
            fix=Fix(
                "Restrict permissions (re-check after updates)",
                [FixCommand(f"chmod {'700' if a.is_dir else '600'} {_q(a.path)}") for a in exposed],
            ),
        )
    ]


def rule_open_server(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Local agent servers without authentication."""
    del ctx
    open_servers = [s for s in report.settings if s.key.startswith("local server") and s.concern]
    if not open_servers:
        return []
    pids = [str(p.pid) for p in report.processes if "serve" in p.command]
    return [
        _exposure(
            report,
            "open-server",
            Lens.ACCOUNT,
            f"The local {report.display_name} server accepts requests without a password, so "
            "any local process or account can run prompts and tools as you.",
            evidence=[f"{s.key}: {s.value}" for s in open_servers],
            fix=Fix("Stop the server", [FixCommand(f"kill {' '.join(pids) or '<pid>'}")]),
        )
    ]


# --- trust, account data, account signals -------------------------------------------------------

BROAD_TRUST = ("Downloads", "Desktop", "tmp", "Library/Application Support", "node_modules")
"""Folder names whose contents come from many sources, not one project."""


def _broad(folder: Path, home: Path) -> bool:
    path = f"{folder}/"
    return folder == home or any(f"/{name}/" in path for name in BROAD_TRUST)


def _carried_instructions(report: ToolReport, folder: Path) -> list[str]:
    """Project instruction files this tool loads from inside a trusted folder."""
    return [
        i.path
        for i in report.instructions
        if i.scope == "project" and Path(i.path).parent in {folder, folder / ".claude"}
    ]


def rule_trust(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Trusted folders: broad ones, writable ones, and those holding instruction files."""
    folders = [Path(f) for f in report.trusted_folders]
    if not folders:
        return []
    broad = [f for f in folders if _broad(f, ctx.home)]
    carried = {f: _carried_instructions(report, f) for f in folders}
    carriers = [f for f in folders if carried[f]]
    if not broad and not carriers:
        return []
    statement = f"{report.display_name} trusts {plural(len(folders), 'folder')}."
    if carriers:
        statement += (
            f" {len(carriers)} of them {'holds' if len(carriers) == 1 else 'hold'} "
            f"instruction files {report.display_name} loads."
        )
    if broad:
        named = join([ctx.display(str(f)) for f in broad[:5]])
        statement += f" Broad folders on the list: {named}."
    return [
        _exposure(
            report,
            "trust",
            Lens.MODEL,
            statement,
            evidence=[ctx.display(p) for f in carriers for p in carried[f]][:10],
            fix=Fix(
                "Withdraw trust from folders you do not own or no longer use",
                [_trust_fix(report)],
            ),
        )
    ]


def _trust_fix(report: ToolReport) -> FixCommand:
    if report.name == "pi":
        return FixCommand(
            "Set those projects' decision to false in ~/.pi/agent/trust.json, or delete the entry",
            manual=True,
            markers=("trust.json",),
            marker_tool="pi",
        )
    if report.name == "codex":
        return FixCommand(
            'Set trust_level = "untrusted" for those [projects."…"] entries in '
            "~/.codex/config.toml",
            manual=True,
            markers=("trust_level",),
            marker_tool="codex",
        )
    return FixCommand(
        "Set hasTrustDialogAccepted to false for those projects in ~/.claude.json",
        manual=True,
        markers=("hasTrustDialogAccepted",),
        marker_tool="claude",
    )


def rule_account_data(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Copies of your work kept by the provider: training, cloud tasks, connectors."""
    del ctx
    notes = [n for n in report.account if n.topic == "data" and n.concern]
    if not notes:
        return []
    return [
        _exposure(
            report,
            "account-data",
            Lens.COPIES,
            " ".join(n.text for n in notes),
            evidence=[n.source for n in notes],
            fix=Fix(
                "Review the provider's data settings",
                [FixCommand(_settings_page(report), manual=True)],
            ),
        )
    ]


def _settings_page(report: ToolReport) -> str:
    return {
        "claude": "Turn off model training at claude.ai/settings/data-privacy-controls and "
        "disconnect unused connectors",
        "codex": "Review Data controls at platform.openai.com and chatgpt.com, and remove cloud "
        "repos you do not need",
        "opencode": 'Set "share": "disabled" and review each provider\'s data settings',
    }.get(report.name, "Review the provider's data settings")


def rule_account_signals(report: ToolReport, ctx: RuleContext) -> list[Exposure]:
    """Local signs that a credential was used elsewhere or can be driven remotely."""
    del ctx
    notes = [n for n in report.account if n.topic == "detect" and n.concern]
    if not notes:
        return []
    return [
        _exposure(
            report,
            "account-signals",
            Lens.REMOTE,
            " ".join(n.text for n in notes),
            evidence=[n.source for n in notes],
            fix=Fix(
                "Check active sessions and devices, then revoke what you do not recognise",
                [
                    FixCommand(
                        "Review signed-in sessions and paired devices in the provider's "
                        "security settings",
                        manual=True,
                    )
                ],
            ),
        )
    ]


# --- what each check needs from the collected data -----------------------------------------------
# Each returns "" when the input the check reads was recorded for this tool, else the reason
# the check could not run. A check that ran and found nothing is clear; one that could not
# run says so.

SIGNAL_SOURCES = frozenset({"codex", "opencode", "pi"})
"""Tools whose collectors can mark a sign of use elsewhere as a concern (accounts.py)."""


def _needs_approval_setting(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(s.key in APPROVAL_KEYS for s in report.settings):
        return ""
    return f"this audit records no approval setting for {report.display_name}"


def _needs_scopes(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(t.scopes for c in report.credentials for t in c.tokens):
        return ""
    return "no stored token records its scopes"


def _needs_share_setting(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(s.key in {"shared sessions", "share"} for s in report.settings):
        return ""
    return f"this audit records no share setting for {report.display_name}"


def _needs_keychain(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(c.store == "macOS Keychain" for c in report.credentials):
        return ""
    return "no credential is stored in the Keychain"


def _needs_credentials(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    return "" if report.credentials else "no stored credentials were found"


def _needs_scan(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    return "" if report.secret_scan else "the secret scan runs only in the full audit"


def _needs_local_mcp(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(x.kind == "mcp" and x.access == "stdio" for x in report.extensions):
        return ""
    return "no local MCP server command to check"


def _needs_other_accounts(report: ToolReport, ctx: RuleContext) -> str:
    del report
    return "" if ctx.host.other_users else "there are no other local accounts"


def _needs_local_server(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(s.key.startswith("local server") for s in report.settings):
        return ""
    return f"this audit records no local server for {report.display_name}"


def _needs_trusted_folders(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    return "" if report.trusted_folders else "no trusted folders are recorded"


def _needs_data_notes(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if any(n.topic == "data" for n in report.account):
        return ""
    return "no data-use setting is recorded"


def _needs_signal_source(report: ToolReport, ctx: RuleContext) -> str:
    del ctx
    if report.name in SIGNAL_SOURCES:
        return ""
    return f"nothing on disk records where else the {report.display_name} token is used"


TOOL_RULES: tuple[Rule, ...] = (
    Rule(
        "no-approval",
        "Approval not turned off by a recorded setting",
        rule_no_approval,
        _needs_approval_setting,
    ),
    Rule(
        "instructions", "Instruction files contain nothing that steers the model", rule_instructions
    ),
    Rule("token-reach", "Token carries no connector scopes", rule_token_reach, _needs_scopes),
    Rule(
        "shared", "No sessions published to share links", rule_shared_sessions, _needs_share_setting
    ),
    Rule(
        "keychain-silent", "Keychain item requires a prompt", rule_keychain_silent, _needs_keychain
    ),
    Rule(
        "creds-plaintext",
        "Credentials in an OS-protected store",
        rule_plaintext_credentials,
        _needs_credentials,
    ),
    Rule("secrets", "No secrets in history or logs (full audit only)", rule_secrets, _needs_scan),
    Rule(
        "dangling",
        "No MCP server command points at a missing file",
        rule_dangling,
        _needs_local_mcp,
    ),
    Rule("autostart", "No automatic code execution points", rule_autostart),
    Rule("daemons", "No background process outlives its session", rule_daemons),
    Rule("duplicate-installs", "One install per tool", rule_duplicate_installs),
    Rule(
        "creds-readable",
        "Credentials not readable by other accounts",
        rule_credentials_exposed,
        _needs_credentials,
    ),
    Rule(
        "data-readable",
        "Data stores not readable by other accounts",
        rule_exposed_data,
        _needs_other_accounts,
    ),
    Rule(
        "open-server",
        "Local server requires authentication",
        rule_open_server,
        _needs_local_server,
    ),
    Rule("trust", "Trusted folders are few and owned by you", rule_trust, _needs_trusted_folders),
    Rule(
        "account-data",
        "Provider keeps no extra copies (training, cloud tasks)",
        rule_account_data,
        _needs_data_notes,
    ),
    Rule(
        "account-signals",
        "No local signs of use elsewhere",
        rule_account_signals,
        _needs_signal_source,
    ),
)


# --- host -------------------------------------------------------------------------------------


def _host(
    rule_id: str,
    lens: Lens,
    statement: str,
    *,
    evidence: list[str] | None = None,
    fix: Fix | None = None,
) -> Exposure:
    return Exposure(
        id=f"host:{rule_id}",
        tool="host",
        lens=lens,
        statement=statement,
        label=_label(rule_id),
        evidence=evidence or [],
        fix=fix,
    )


def rule_path_hijack(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """PATH directories ahead of system dirs that other accounts can write."""
    host = ctx.host
    cutoff = first_system_index(host.path_entries)
    shared_groups = {g for groups in host.other_user_groups.values() for g in groups}
    risky = [
        e
        for e in host.path_entries
        if e.exists
        and e.index < cutoff
        and (e.other_writable or (e.group_writable and e.group in shared_groups))
    ]
    if not risky:
        return []
    bare = [
        f"{t.display_name}: {f.value}"
        for t in audit.tools
        for f in t.fingerprint
        if "bare name" in f.value
    ]
    folders = ", ".join(e.path for e in risky)
    consequence = (
        " Claude Code looks up `security` through PATH when it reads its token, so a planted "
        "`security` would receive it."
        if bare
        else ""
    )
    return [
        _host(
            "path-hijack",
            Lens.ACCOUNT,
            f"Other accounts can write to {folders}, which comes before /usr/bin in your PATH. "
            f"A program planted there replaces system commands for you and your AI tools."
            + consequence,
            evidence=[
                f"PATH #{e.index} {e.path} ({e.mode} {e.owner}:{e.group}); system dirs start "
                f"at #{cutoff}"
                for e in risky
            ]
            + bare,
            fix=Fix(
                "Remove group/other write access",
                [FixCommand(f"chmod g-w,o-w {_q(e.path)}") for e in risky],
            ),
        )
    ]


def rule_binary_dirs(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """Tool binaries or launchers in folders others can write."""
    del ctx
    risky = [(t, b) for t in audit.tools for b in t.binaries if b.writable_dirs]
    if not risky:
        return []
    dirs = sorted({d for _t, b in risky for d in b.writable_dirs})
    tools = sorted({t.display_name for t, _b in risky})
    return [
        _host(
            "binary-dirs",
            Lens.ACCOUNT,
            f"{', '.join(tools)} launch from folders other accounts can write "
            f"({', '.join(dirs)}), so another account can swap the program you run.",
            evidence=[f"{t.display_name}: {b.path} → {b.resolved}" for t, b in risky],
            fix=Fix(
                "Remove group/other write access from those folders",
                [FixCommand(f"chmod g-w,o-w {_q(d)}") for d in dirs],
            ),
        )
    ]


def rule_other_accounts(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """Other local accounts that can read world-readable files."""
    del audit
    others = ctx.host.other_users
    if not others:
        return []
    remove = (
        "sudo sysadminctl -deleteUser {name}" if ctx.platform == "darwin" else "sudo userdel {name}"
    )
    return [
        _host(
            "other-accounts",
            Lens.ACCOUNT,
            f"This machine has {len(others)} other local account(s): {', '.join(others)}. "
            "Every world-readable AI-tool file is readable by them.",
            evidence=[
                f"{name}: groups {' '.join(ctx.host.other_user_groups.get(name, []))}"
                for name in others
            ],
            fix=Fix(
                "Remove accounts that are not needed",
                [FixCommand(remove.format(name=_q(name))) for name in others],
            ),
        )
    ]


def rule_shared_surfaces(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """Skill folders and instruction files loaded by more than one tool."""
    by_path: dict[str, set[str]] = {}
    for tool in audit.tools:
        for ext in tool.extensions:
            if ext.kind == "skill":
                by_path.setdefault(ext.detail.rsplit("/", 1)[0], set()).add(tool.display_name)
        for instr in tool.instructions:
            by_path.setdefault(ctx.display(instr.path), set()).add(tool.display_name)
    shared = {p: tools for p, tools in by_path.items() if len(tools) > 1}
    if not shared:
        return []
    return [
        _host(
            "shared-surfaces",
            Lens.MODEL,
            f"{', '.join(sorted(shared))} are loaded by more than one tool, so one planted skill "
            "or instruction steers all of them.",
            evidence=[f"{p}: {', '.join(sorted(t))}" for p, t in sorted(shared.items())],
        )
    ]


def rule_duplicate_providers(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """The same provider account stored by several tools."""
    del ctx
    stores: dict[str, set[str]] = {}
    names: dict[str, str] = {}
    for tool in audit.tools:
        for cred in tool.credentials:
            names.setdefault(cred.provider.lower(), cred.provider)
            stores.setdefault(cred.provider.lower(), set()).add(
                f"{tool.display_name} ({cred.store})"
            )
    dupes = {p: s for p, s in stores.items() if len(s) > 1}
    if not dupes:
        return []
    return [
        _host(
            "duplicate-creds",
            Lens.CODE,
            f"Credentials for {join(sorted(names[p] for p in dupes))} are stored in more "
            "than one place; each "
            "copy is another place to take them from, often with weaker protection.",
            evidence=[f"{names[p]}: {', '.join(sorted(s))}" for p, s in sorted(dupes.items())],
        )
    ]


def _facts(ctx: RuleContext, topic: str) -> list[HostFact]:
    return [f for f in ctx.host.facts if f.topic == topic]


def rule_inherited(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """Credentials an agent running as you can use besides its own token."""
    facts = [f for f in _facts(ctx, "reach") if f.concern]
    if not facts:
        return []
    unattended = [
        t.display_name
        for t in audit.tools
        if any(x.id == f"{t.name}:no-approval" for x in t.exposures)
    ]
    verb = "skips" if len(unattended) == 1 else "skip"
    tail = (
        f" {join(unattended)} {verb} approval prompts in some sessions, so text that steers "
        "the model in those sessions can use them too."
        if unattended
        else ""
    )
    items = join([f"{f.name} ({f.detail})" for f in facts[:8]])
    commands = [
        FixCommand(f"ssh-keygen -p -f {_q(f.path)}")
        for f in facts
        if f.name.startswith("SSH key") and "no passphrase" in f.detail
    ]
    commands.append(
        FixCommand(
            "Use short-lived cloud credentials (SSO) instead of stored keys, "
            "and run agents in a container or VM without your home folder",
            manual=True,
        )
    )
    return [
        _host(
            "inherited-creds",
            Lens.CODE,
            f"Anything running as you, including an agent, can also use {items}." + tail,
            evidence=[f"{f.name}: {ctx.display(f.path)}" for f in facts if f.path],
            fix=Fix("Shrink what an agent inherits", commands),
        )
    ]


def _brief(fact: HostFact) -> str:
    """Name plus detail, leaving out a detail that is a path or command (tables show those)."""
    return fact.name if "/" in fact.detail else f"{fact.name} ({fact.detail})"


def _unattended_statement(facts: list[HostFact]) -> str:
    procs = [f for f in facts if f.name.startswith("pid ")]
    orphans = [f for f in facts if "orphaned" in f.detail]
    logins = [f for f in facts if f.detail.startswith("starts at login")]
    parts = []
    if procs:
        parts.append(
            f"{len(procs)} AI-tool process{'' if len(procs) == 1 else 'es'} running "
            "for a day or more"
        )
    if orphans:
        parts.append(f"{plural(len(orphans), 'MCP server')} left running after the session ended")
    if logins:
        parts.append(plural(len(logins), "login item"))
    statement = f"These keep running as you when you are not there: {join(parts)}."
    unguarded = [f for f in procs if "--dangerously" in f.detail]
    if unguarded:
        verb = "was" if len(unguarded) == 1 else "were"
        statement += f" {len(unguarded)} of them {verb} started with approval prompts turned off."
    return statement


def rule_control(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """Software that can drive the browser, screen, keyboard or every file."""
    del audit
    facts = [f for f in _facts(ctx, "control") if f.concern]
    if not facts:
        return []
    browsers: dict[str, list[str]] = {}
    others = []
    for fact in facts:
        if " extension bridge to " in fact.detail:
            browsers.setdefault(fact.name, []).append(fact.detail.split(" extension bridge", 1)[0])
        else:
            others.append(_brief(fact))
    bridges = [f"{name} ({', '.join(b)})" for name, b in browsers.items()]
    parts = []
    if bridges:
        parts.append(f"browser bridges that let an extension run a local program: {join(bridges)}")
    parts.extend(others)
    return [
        _host(
            "computer-control",
            Lens.MODEL,
            f"Beyond the terminal, these can act on your computer: {'; '.join(parts)}.",
            evidence=sorted({ctx.display(f.path) for f in facts if f.path}),
            fix=Fix(
                "Remove bridges and permissions you do not use",
                [
                    FixCommand(
                        "Review System Settings > Privacy & Security for Full Disk "
                        "Access, Accessibility and Screen Recording",
                        manual=True,
                    )
                ],
            ),
        )
    ]


def rule_backups(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """AI-tool data copied into backups."""
    del audit
    included = [f for f in _facts(ctx, "backup") if f.concern]
    if not included:
        return []
    where = next((f.detail for f in _facts(ctx, "backup") if f.name.endswith("destinations")), "")
    return [
        _host(
            "backups",
            Lens.COPIES,
            f"Time Machine copies {join([ctx.display(f.path) for f in included])} "
            f"to {where}. Deleting a transcript locally leaves it, and any secret in it, in "
            "every backup.",
            evidence=[f.detail for f in included],
            fix=Fix(
                "Exclude AI-tool history from future backups",
                [FixCommand(f"tmutil addexclusion {_q(f.path)}") for f in included],
            ),
        )
    ]


def rule_unattended(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """Processes that keep running without a session, and login items for AI tools."""
    del audit
    facts = [f for f in _facts(ctx, "unattended") if f.concern]
    if not facts:
        return []
    commands = [
        FixCommand(f"pkill -P 1 -f {_q(f.path)}")
        for f in facts
        if "orphaned" in f.detail and f.path
    ]
    if not commands:
        commands = [FixCommand("Quit the listed processes and remove the login items", manual=True)]
    return [
        _host(
            "unattended",
            Lens.CODE,
            _unattended_statement(facts),
            evidence=[f"{f.name}: {f.detail}" for f in facts],
            fix=Fix("Stop processes that outlived their sessions", commands),
        )
    ]


def rule_other_tools(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """AI tools on this machine that the audit inventories but does not analyse in depth."""
    del audit
    facts = _facts(ctx, "other-tools")
    if not facts:
        return []
    return [
        _host(
            "other-tools",
            Lens.COPIES,
            "Other AI tools also keep data here and were only inventoried: "
            + join([f.name for f in facts])
            + ".",
            evidence=[ctx.display(f.path) for f in facts],
        )
    ]


HOST_RULES: tuple[HostRule, ...] = (
    HostRule(
        "path-hijack",
        "PATH folders ahead of system dirs are not writable by others",
        rule_path_hijack,
    ),
    HostRule("binary-dirs", "Tool binaries are in folders only you can write", rule_binary_dirs),
    HostRule("other-accounts", "No other local accounts", rule_other_accounts),
    HostRule(
        "shared-surfaces", "No skill or instruction file shared across tools", rule_shared_surfaces
    ),
    HostRule("duplicate-creds", "Each provider credential stored once", rule_duplicate_providers),
    HostRule("inherited-creds", "Agents inherit no other credentials", rule_inherited),
    HostRule("computer-control", "Nothing else can drive the computer", rule_control),
    HostRule("backups", "AI-tool history is not copied into backups", rule_backups),
    HostRule("unattended", "Nothing runs without a session", rule_unattended),
    HostRule("other-tools", "No other AI tools keep data here", rule_other_tools),
)


def evaluate(audit: AuditReport, ctx: RuleContext) -> Checklist:
    """Run every rule, attach exposures to the audit, and return the checklist.

    Every rule runs, so nothing it finds is hidden; a rule that finds nothing because its input
    was never recorded is marked not checked, with the reason.

    Returns:
        One ``Check`` per rule and tool, for the doctor view.
    """
    checklist: Checklist = []
    for tool in audit.tools:
        if not tool.installed:
            continue
        for rule in TOOL_RULES:
            found = rule.fn(tool, ctx)
            tool.exposures.extend(found)
            unchecked = "" if found else rule.needs(tool, ctx)
            checklist.append(Check(tool.display_name, rule.check, found, unchecked))
    for rule in HOST_RULES:
        found = rule.fn(audit, ctx)
        audit.host_exposures.extend(found)
        checklist.append(Check("Host", rule.check, found))
    return checklist
