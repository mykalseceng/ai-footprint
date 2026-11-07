"""Checks that span tools or concern the host itself."""

from ai_footprint.checks.base import RuleContext, label_for, quote
from ai_footprint.host import first_system_index
from ai_footprint.model import (
    BARE_SECURITY,
    AuditReport,
    Exposure,
    FactKind,
    Fix,
    FixCommand,
    HostFact,
    Lens,
)
from ai_footprint.text import join, plural


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
        label=label_for(rule_id),
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
        if f.value == BARE_SECURITY
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
                [FixCommand(f"chmod g-w,o-w {quote(e.path)}") for e in risky],
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
                [FixCommand(f"chmod g-w,o-w {quote(d)}") for d in dirs],
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
                [FixCommand(remove.format(name=quote(name))) for name in others],
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


def _provider_copies(
    audit: AuditReport, ctx: RuleContext
) -> dict[str, dict[frozenset[str], list[str]]]:
    """``{provider: {token fingerprints: [where each copy is stored]}}``."""
    found: dict[str, dict[frozenset[str], list[str]]] = {}
    for tool in audit.tools:
        for cred in tool.credentials:
            prints = frozenset(t.fingerprint for t in cred.tokens if t.fingerprint)
            where = f"{tool.display_name} ({cred.store}, {ctx.display(cred.location)})"
            found.setdefault(cred.provider, {}).setdefault(prints, []).append(where)
    return found


def rule_duplicate_providers(audit: AuditReport, ctx: RuleContext) -> list[Exposure]:
    """One provider's credentials held in several places: copies and separate logins."""
    copies = _provider_copies(audit, ctx)
    lines = []
    for provider, creds in sorted(copies.items()):
        places = sum(len(stores) for stores in creds.values())
        if places < 2:
            continue
        copied = [stores for stores in creds.values() if len(stores) > 1]
        text = f"{provider}: {plural(len(creds), 'separate credential')} in {places} places"
        if copied:
            text += f", including the same credential in {join(copied[0])}"
        lines.append(text)
    if not lines:
        return []
    return [
        _host(
            "duplicate-creds",
            Lens.CODE,
            f"Credentials for one provider are held in several places ({'; '.join(lines)}). "
            "Each place is another copy to take.",
            evidence=[
                f"{provider}: {', '.join(stores)}"
                for provider, creds in sorted(copies.items())
                for stores in creds.values()
            ],
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
        FixCommand(f"ssh-keygen -p -f {quote(f.path)}")
        for f in facts
        if f.kind is FactKind.SSH_KEY_OPEN
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
    procs = [f for f in facts if f.kind is FactKind.LONG_RUNNING]
    browsers = [f for f in facts if f.kind is FactKind.DEBUG_BROWSER]
    orphans = [f for f in facts if f.kind is FactKind.ORPHAN]
    logins = [f for f in facts if f.kind is FactKind.LOGIN_ITEM]
    parts = []
    if procs:
        parts.append(
            f"{len(procs)} AI-tool process{'' if len(procs) == 1 else 'es'} running "
            "for a day or more"
        )
    if orphans:
        parts.append(f"{plural(len(orphans), 'MCP server')} left running after the session ended")
    if browsers:
        parts.append(
            f"{plural(len(browsers), 'browser')} with a remote debugging port and no parent session"
        )
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
        if fact.kind is FactKind.BRIDGE:
            browsers.setdefault(fact.name, []).append(fact.detail.split(" extension bridge", 1)[0])
        else:
            others.append(_brief(fact))
    bridges = [f"{name} ({', '.join(b)})" for name, b in browsers.items()]
    parts = []
    if bridges:
        parts.append(
            f"browser bridges that let an allowed extension start a local program: {join(bridges)}"
        )
    parts.extend(others)
    return [
        _host(
            "computer-control",
            Lens.MODEL,
            "Beyond the terminal, these are set up to run local programs or hold privacy "
            f"grants: {'; '.join(parts)}.",
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
    where = next(
        (f.detail for f in _facts(ctx, "backup") if f.kind is FactKind.BACKUP_DESTINATIONS), ""
    )
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
                [FixCommand(f"tmutil addexclusion {quote(f.path)}") for f in included],
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
        FixCommand(f"pkill -P 1 -f {quote(f.path)}")
        for f in facts
        if f.kind is FactKind.ORPHAN and f.path
    ]
    if not commands:
        commands = [
            FixCommand(
                "Quit listed processes you no longer use; remove login items you do not want",
                manual=True,
            )
        ]
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
