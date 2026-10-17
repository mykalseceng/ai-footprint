"""Self-contained HTML report: an attack-surface narrative with a page per tool.

Layout follows a research-explainer format: sticky side navigation, a TL;DR box, collapsible
sections, and a FAQ. Pages switch with CSS ``:target`` so the document needs no scripts. It
makes no network requests (system fonts only) and ships a CSP that forbids scripts entirely,
so strings collected from the machine (MCP names, instruction text) cannot execute even if
they contain markup. Everything is escaped as well.
"""

import html
import re
from collections.abc import Iterable, Sequence

from ai_footprint import answers, document, figures, keys, surface
from ai_footprint.fsinfo import disk_bytes, human_size, tilde
from ai_footprint.model import (
    AuditReport,
    Category,
    Credential,
    Exposure,
    Extension,
    Fix,
    HostFact,
    HostReport,
    ToolReport,
)
from ai_footprint.report_text import validation_label
from ai_footprint.rules import Check, Checklist

LONG_RUN = re.compile(r"\S{24,}")
SEPARATOR = re.compile(r"([/._:=|,@])")


def e(value: object) -> str:
    """Escape any value for HTML text or attribute context."""
    return html.escape(str(value), quote=True)


def rich(text: str) -> str:
    """Escape text, then render `backtick` spans as code."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", e(text))


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def rich_breakable(text: str) -> str:
    """Escape text with break points, then render `backtick` spans as code."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", breakable(text))


def breakable(value: object) -> str:
    """Escape text and add line-break points after separators inside long runs (paths, ids).

    Table cells wrap only between words, so a name such as "OpenCode" is never split, and a
    long path wraps at its slashes instead of widening the table.
    """
    return LONG_RUN.sub(lambda m: SEPARATOR.sub(r"\1<wbr>", m.group()), e(value))


def pill(text: str, tone: str) -> str:
    """Small rounded status label."""
    return f'<span class="pill p-{e(tone)}">{e(text)}</span>'


def table(
    headers: Sequence[str], rows: Iterable[Sequence[str]], *, raw: bool = False, cls: str = ""
) -> str:
    """Bordered table in a horizontal scroller; cells are escaped unless ``raw``."""
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{c if raw else breakable(c)}</td>" for c in row) + "</tr>"
        for row in rows
    )
    if not body:
        return '<p class="muted">Nothing found.</p>'
    return (
        f'<div class="tbl {cls}"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody>'
        "</table></div>"
    )


def fold(title: str, body: str, *, where: str = "", is_open: bool = False) -> str:
    """Collapsible card with an optional mono annotation on the right."""
    annotation = f'<span class="where">{e(where)}</span>' if where else ""
    return (
        f"<details{' open' if is_open else ''}><summary>{e(title)}{annotation}</summary>"
        f'<div class="body">{body}</div></details>'
    )


# --- narrative pieces ---------------------------------------------------------------------------


def _header(eyebrow: str, title: str, tldr_html: str) -> str:
    return f"""<header>
  <div class="eyebrow">{e(eyebrow)}</div>
  <h1>{e(title)}</h1>
  <div class="tldr"><b>TL;DR</b> — {tldr_html}</div>
</header>"""


def _lens_folds(story: surface.Narrative, *, show_tool: bool) -> str:
    out = []
    for view in story.lenses:
        if not view.points:
            continue
        items = "".join(
            "<li>"
            + (f'<span class="who">{e(p.tool)}</span>' if show_tool else "")
            + f"<span>{rich(p.text)}</span></li>"
            for p in view.points
        )
        body = f'<p class="question">{e(view.lens.question)}</p><ul class="points">{items}</ul>'
        out.append(
            fold(
                view.lens.title, body, where=surface.plural(len(view.points), "path"), is_open=True
            )
        )
    return "".join(out) or '<p class="muted">Nothing found from any position.</p>'


def _fix_steps(fix: Fix) -> str:
    items = []
    for cmd, validation in zip(fix.commands, fix.validations, strict=False):
        label, tone = validation_label(validation)
        tone_class = {"PASS": "ok", "FAIL": "concern"}.get(tone, "neutral")
        checks = "".join(
            f"<li class='{'ok' if c.passed else 'bad'}'>{'✓' if c.passed else '✗'} "
            f"{e(c.name)}: {e(c.detail)}</li>"
            for c in validation.checks
        )
        text = f"<p>{e(cmd.text)}</p>" if cmd.manual else f"<pre>{e(cmd.text)}</pre>"
        items.append(
            f'<div class="step">{text}<details class="checks"><summary>'
            f"{pill(label.lstrip('✓✗ ').split(':')[0], tone_class)}</summary>"
            f"<ul>{checks}</ul></details></div>"
        )
    return f'<div class="fix"><p class="fix-title">{e(fix.summary)}</p>{"".join(items)}</div>'


def _close_folds(exposures: list[Exposure]) -> str:
    out = []
    for exposure in exposures:
        if not exposure.fix:
            continue
        evidence = "".join(f"<li>{rich(x)}</li>" for x in exposure.evidence[:8])
        body = (
            f"<p>{rich(exposure.statement)}</p>"
            + (f'<ul class="ev">{evidence}</ul>' if evidence else "")
            + _fix_steps(exposure.fix)
        )
        out.append(
            f'<div id="{e(exposure.id)}" class="anchor">'
            + fold(exposure.label, body, where=exposure.lens.title.lower())
            + "</div>"
        )
    if not out:
        return ""
    return (
        "<h2>How to close it</h2><p>Each fix command was checked against this machine before "
        "it was printed (shell syntax, programs, targets, subcommands and config keys); manual "
        "steps cannot be checked. Open a badge to see the checks.</p>" + "".join(out)
    )


def _faq(tool: ToolReport, host: HostReport) -> str:
    items = []
    for answer in answers.for_tool(tool, host):
        body = f"<p>{rich(answer.text)}</p>" if answer.text else ""
        if answer.rows:
            rows = [[rich_breakable(cell) for cell in row] for row in answer.rows]
            body += table(list(answer.headers), rows, raw=True)
        if answer.links:
            body += (
                "<p>"
                + " · ".join(f'<a href="#{e(page)}">{e(label)}</a>' for page, label in answer.links)
                + "</p>"
            )
        items.append(f"<dt>{e(answer.question)}</dt><dd>{body}</dd>")
    return f'<h2>Your questions</h2><dl class="faq">{"".join(items)}</dl>'


# --- inventory ---------------------------------------------------------------------------------


def _credential_card(cred: Credential) -> str:
    rows = [
        [
            t.field,
            t.description,
            f"{t.prefix}{t.last4} · {t.length} chars",
            (surface.when(t.expires_at) if t.expires_at else "—")
            + (" (expired)" if t.expired else ""),
            ", ".join(t.scopes) or "—",
            t.signature,
        ]
        for t in cred.tokens
    ]
    claims = "".join(
        f"<p class='sub'>{e(t.field)} claims</p>"
        + table(["Claim", "Value"], [[k, surface.when(v)] for k, v in sorted(t.claims.items())])
        for t in cred.tokens
        if t.claims
    )
    readable = pill("readable by other accounts", "concern") if cred.readable_by_others else ""
    live = f"<p class='sub'>Live check</p><p>{e(cred.live_check)}</p>" if cred.live_check else ""
    return (
        f'<div class="cred"><p class="cred-title"><b>{e(cred.provider)}</b> · {e(cred.store)} '
        f"{readable}</p><p class='mono small'>{e(cred.location)}</p><p class='small'>"
        f"{e(cred.protection)}</p>"
        + table(["Field", "Type", "Shape", "Expires", "Scopes", "Signature"], rows)
        + f"{claims}{live}</div>"
    )


def _settings_table(tool: ToolReport) -> str:
    rows = [
        [
            f"<code>{breakable(s.key)}</code>",
            breakable(s.value),
            e(s.note),
            pill("widens exposure", "concern") if s.concern else "",
        ]
        for s in tool.settings
    ]
    return table(["Setting", "Value", "Why it matters", ""], rows, raw=True)


KIND_TITLES = (
    ("mcp", "MCP servers"),
    ("connector", "claude.ai connectors"),
    ("plugin", "Plugins"),
    ("skill", "Skills"),
    ("hook", "Hooks"),
    ("native-host", "Browser native hosts"),
    ("statusline", "Status line"),
)


def _extensions_table(tool: ToolReport) -> str:
    """One table per kind, so no single table runs to a hundred rows."""
    out = []
    for kind, title in KIND_TITLES:
        rows = [
            [
                breakable(x.name),
                breakable(x.source),
                f"<code>{breakable(x.detail[:200])}</code>",
                "yes" if x.autostart else "no",
                (pill("target missing", "concern") + " " if x.dangling else "")
                + breakable(x.notes),
            ]
            for x in tool.extensions
            if x.kind == kind
        ]
        if rows:
            out.append(f"<p class='sub'>{e(title)} · {len(rows)}</p>")
            out.append(table(["Name", "Source", "Runs", "Auto", "Notes"], rows, raw=True))
    return "".join(out) or "<p class='muted'>None.</p>"


def _files_table(tool: ToolReport, home: str) -> str:
    rows = [
        [
            e(a.label),
            f"<code>{breakable(tilde(a.path, home))}</code>",
            e(human_size(a.size_bytes)),
            e(f"{a.file_count:,}"),
            e(a.mode),
            pill("readable", "concern") if a.other_readable else "no",
            e(a.oldest),
            e(a.newest),
            e(a.description),
        ]
        for a in tool.artifacts
    ]
    headers = [
        "What",
        "Path",
        "Size",
        "Files",
        "Mode",
        "Other accounts",
        "Oldest",
        "Newest",
        "Holds",
    ]
    return table(headers, rows, raw=True)


def _network_tables(tool: ToolReport) -> str:
    endpoints = table(
        ["Host", "Purpose", "Evidence", "Count"],
        [[x.host, x.purpose, x.source, str(x.count or "")] for x in tool.endpoints],
    )
    traits = table(
        ["Trait", "Value"],
        [[e(f.label), f"<code>{breakable(f.value)}</code>"] for f in tool.fingerprint],
        raw=True,
    )
    return (
        f"{endpoints}<p class='sub'>Signature</p><p class='small muted'>Each trait below was "
        f"found in the installed binary.</p>{traits}"
    )


def _scan_table(tool: ToolReport) -> str:
    scan = tool.secret_scan
    if scan is None:
        return "<p class='muted'>Not scanned (doctor mode).</p>"
    head = (
        f"<p>Scanned {scan.files_scanned:,} files ({human_size(scan.bytes_scanned)}) in "
        f"{scan.seconds}s. Only kinds, counts, last four characters and paths were kept.</p>"
    )
    rows = [
        [k.label, str(k.unique), str(k.files), ", ".join(k.last4), "\n".join(k.locations[:4])]
        for k in sorted(scan.kinds, key=lambda k: k.unique, reverse=True)
    ]
    return head + table(["Type", "Unique", "Files", "Last 4", "Example locations"], rows, cls="pre")


def _install_table(tool: ToolReport) -> str:
    bins = table(
        ["Path", "Resolves to", "Version", "Signed by", "Writable folders"],
        [
            [
                b.path,
                b.resolved,
                b.version,
                f"{b.signer} {b.team_id}".strip(),
                ", ".join(b.writable_dirs) or "none",
            ]
            for b in tool.binaries
        ],
    )
    stats = table(["Measure", "Value"], list(tool.stats.items()))
    procs = table(
        ["PID", "Started", "Command"],
        [[str(p.pid), p.started, _clip(p.command, 200)] for p in tool.processes],
    )
    return f"{bins}<p class='sub'>Activity</p>{stats}<p class='sub'>Running now</p>{procs}"


def _inventory(tool: ToolReport, home: str) -> str:
    creds = "".join(_credential_card(c) for c in tool.credentials)
    plural = surface.plural
    return "<h2>Inventory</h2>" + "".join(
        [
            fold(
                "Credentials",
                creds or "<p class='muted'>None.</p>",
                where=plural(len(tool.credentials), "store"),
            ),
            fold(
                "Settings that matter",
                _settings_table(tool),
                where=plural(len(tool.settings), "setting"),
            ),
            fold(
                "Skills, plugins, MCP servers, hooks",
                _extensions_table(tool),
                where=plural(len(tool.extensions), "entry"),
            ),
            fold(
                "Files and logs",
                _files_table(tool, home),
                where=plural(len(tool.artifacts), "location"),
            ),
            fold(
                "Where it connects and how it looks",
                _network_tables(tool),
                where=plural(len(tool.endpoints), "endpoint"),
            ),
            fold("Secrets at rest", _scan_table(tool)),
            fold(
                "Install and activity",
                _install_table(tool),
                where=plural(len(tool.binaries), "binary"),
            ),
        ]
    )


# --- pages -------------------------------------------------------------------------------------


def _tool_rows(tools: list[ToolReport]) -> list[list[str]]:
    rows = []
    for t in tools:
        approval = figures.approval(t)
        tone = {"found": "concern", "not checked": "neutral"}.get(str(approval.value), "ok")
        rows.append(
            [
                f"<a href='#tool-{e(t.name)}'>{e(t.display_name)}</a>",
                e(t.binaries[0].version if t.binaries else "?"),
                e(human_size(disk_bytes(t.artifacts, Category.SESSION))),
                e(str(len(t.credentials))),
                pill(approval.display, tone)
                + f" <span class='small'>{breakable(approval.detail)}</span>",
            ]
        )
    return rows


def _credential_rows(tools: list[ToolReport]) -> list[list[str]]:
    return [
        [
            f"<a href='#tool-{e(t.name)}'>{e(t.display_name)}</a>",
            e(group[0].provider),
            e(", ".join(sorted({c.store for c in group}))),
            pill("yes", "concern") if any(c.readable_by_others for c in group) else "no",
            e(surface.lifetime(group)),
        ]
        for t, group in surface.merged_credentials(tools)
    ]


def _summary(audit: AuditReport) -> str:
    host = audit.host
    story = surface.for_machine(audit)
    tools = [t for t in audit.tools if t.installed]
    mode = ("full scan" if audit.scanned else "no secret scan") + (
        " · live checks" if audit.live else " · offline"
    )
    eyebrow = (
        f"Defensive exposure audit · {host.user}@{host.hostname} · "
        f"{audit.generated_at[:10]} · {mode}"
    )
    tool_table = table(
        [
            "Tool",
            "Version",
            "Conversations and history",
            "Stored credentials",
            "Approval turned off",
        ],
        _tool_rows(tools),
        raw=True,
    )
    cred_table = table(
        ["Tool", "Provider", "Stored in", "Other accounts can read", "Keeps working"],
        _credential_rows(tools),
        raw=True,
    )
    return f"""<section class="view" id="summary">
{_header(eyebrow, "Attack surface of your AI coding tools", e(" ".join(story.headline)))}
<div class="callout"><span class="ico">★</span><div>{rich(document.proof(audit))}</div></div>
<h2>Ways in, by attacker position</h2>
<p>What an attacker gets from each position. Every line is something this audit observed on
this machine; nothing is rated.</p>
{_lens_folds(story, show_tool=True)}
<h2>Tools</h2>{tool_table}
<h2>Credentials</h2>{cred_table}
</section>"""


def _used_by(tools: list[str]) -> str:
    return e(", ".join(tools))


def _page(page_id: str, title: str, tldr: str, body: str) -> str:
    return f'<section class="view" id="{page_id}">{_header("Across tools", title, e(tldr))}{body}</section>'


OWN_WORDS = (
    "<p class='small muted'>\"Says it does\" is each item's own manifest text; a placeholder "
    "means nothing on disk describes it.</p>"
)


def _skill_folds(skills: list[tuple[Extension, list[str]]]) -> str:
    """Skills grouped by where they come from: one fold per plugin, one for user folders."""
    groups: dict[str, list[tuple[Extension, list[str]]]] = {}
    for x, t in skills:
        key = document.skill_group(x)
        groups.setdefault(key, []).append((x, t))
    out = []
    for key in sorted(groups, key=lambda k: (k != document.USER_SKILLS, k)):
        rows = [
            [
                breakable(x.name),
                _used_by(t),
                breakable(x.source),
                breakable(x.access or "none declared"),
                breakable(x.description),
            ]
            for x, t in groups[key]
        ]
        body = table(
            ["Name", "Used by", "Where", "Tools it declares", "Says it does"], rows, raw=True
        )
        out.append(
            fold(
                key,
                body,
                where=surface.plural(len(rows), "skill"),
                is_open=key == document.USER_SKILLS,
            )
        )
    return "".join(out) or "<p class='muted'>None.</p>"


def _extension_pages(audit: AuditReport) -> str:
    grouped = document.grouped_extensions(audit)
    summaries = document.page_summaries(grouped, audit)
    mcp = [(x, t) for x, t in grouped if x.kind in {"mcp", "connector"}]
    skills = [(x, t) for x, t in grouped if x.kind == "skill"]
    plugins = [(x, t) for x, t in grouped if x.kind == "plugin"]
    mcp_table = table(
        ["Name", "Used by", "Runs", "Says it does", "Notes"],
        [
            [
                breakable(x.name),
                _used_by(t),
                f"<code>{breakable(x.detail[:160])}</code>",
                breakable(x.description),
                breakable("; ".join(p for p in (x.source, x.notes) if p)),
            ]
            for x, t in mcp
        ],
        raw=True,
    )
    skill_table = _skill_folds(skills)
    plugin_table = table(
        ["Name", "Used by", "Contains", "Says it does"],
        [
            [breakable(x.name), _used_by(t), breakable(x.access), breakable(x.description)]
            for x, t in plugins
        ],
        raw=True,
    )
    return "".join(
        [
            _page("mcp", "MCP servers", summaries["mcp"], OWN_WORDS + mcp_table),
            _page("skills", "Skills", summaries["skills"], OWN_WORDS + skill_table),
            _page("plugins", "Plugins", summaries["plugins"], OWN_WORDS + plugin_table),
        ]
    )


def _tool_view(audit: AuditReport, tool: ToolReport) -> str:
    story = surface.for_tool(audit, tool)
    version = tool.binaries[0].version if tool.binaries else "?"
    roots = ", ".join((tool.secret_scan.roots if tool.secret_scan else [])[:2])
    eyebrow = f"Tool · v{version}" + (f" · {roots}" if roots else "")
    home = audit.host.home
    return f"""<section class="view" id="tool-{e(tool.name)}">
{_header(eyebrow, tool.display_name, e(" ".join(story.headline)))}
<h2>Ways in</h2>
{_lens_folds(story, show_tool=False)}
{_close_folds(tool.exposures)}
{_faq(tool, audit.host)}
{_inventory(tool, home)}
</section>"""


def _host_tldr(findings: list[Exposure]) -> str:
    if not findings:
        return f"{e(document.HOST_SCOPE)} Nothing found."
    links = "".join(f'<li><a href="#{e(x.id)}">{e(x.label)}</a></li>' for x in findings)
    return f"{e(document.HOST_SCOPE)} {e(surface.plural(len(findings), 'signal'))} to review:<ul>{links}</ul>"


def _facts_table(facts: list[HostFact], home: str) -> str:
    """Concerns first; the File column appears only when some fact has a file."""
    if not facts:
        return ""
    with_files = any(f.path for f in facts)
    rows = []
    for fact in sorted(facts, key=lambda f: not f.concern):
        row = [
            pill("review", "concern") if fact.concern else pill("info", "neutral"),
            breakable(fact.name),
            breakable(tilde(fact.detail, home)),
        ]
        if with_files:
            path = tilde(fact.path, home)
            row.append(f"<code>{breakable(path)}</code>" if path else "")
        rows.append(row)
    return table(["", "Item", "Found", *(["File"] if with_files else [])], rows, raw=True)


def _host_question(
    question: str, facts: list[HostFact], finding: Exposure | None, fallback: str, home: str
) -> str:
    status = pill("review", "concern") if finding else pill("clear", "ok")
    answer = finding.statement if finding else (fallback if not facts else "Nothing to review.")
    fix = _fix_steps(finding.fix) if finding and finding.fix else ""
    return _host_block(question, status, answer, _facts_table(facts, home) + fix)


def _host_finding(finding: Exposure) -> str:
    evidence = "".join(f"<li>{rich(x)}</li>" for x in finding.evidence[:8])
    body = (f'<ul class="ev">{evidence}</ul>' if evidence else "") + (
        _fix_steps(finding.fix) if finding.fix else ""
    )
    return _host_block(finding.label, pill("review", "concern"), finding.statement, body)


def _host_block(title: str, status: str, answer: str, body: str) -> str:
    return f'<div class="hq"><h3>{e(title)} {status}</h3><p>{rich(answer)}</p>{body}</div>'


def _host_view(audit: AuditReport) -> str:
    host = audit.host
    findings = {x.id: x for x in audit.host_exposures}
    asked = {finding_id for _topic, _question, finding_id, _fallback in answers.HOST_QUESTIONS}
    across = "".join(
        f'<div class="anchor" id="{e(x.id)}">{_host_finding(x)}</div>'
        for x in audit.host_exposures
        if x.id not in asked
    )
    questions = "".join(
        f'<div class="anchor" id="{e(finding_id)}">'
        + _host_question(
            question,
            [f for f in host.facts if f.topic == topic],
            findings.get(finding_id),
            fallback,
            host.home,
        )
        + "</div>"
        for topic, question, finding_id, fallback in answers.HOST_QUESTIONS
    )
    path_rows = [
        [
            str(p.index),
            tilde(p.path, host.home),
            f"{p.owner}:{p.group}",
            p.mode,
            "yes" if p.group_writable or p.other_writable else "no",
        ]
        for p in host.path_entries
    ]
    accounts = [[name, " ".join(groups)] for name, groups in host.other_user_groups.items()]
    path_table = table(["#", "Folder", "Owner", "Mode", "Group/other writable"], path_rows)
    return f"""<section class="view" id="host">
{_header(f"Host · {host.os} · {host.arch}", "This machine", _host_tldr(audit.host_exposures))}
{f"<h2>Across tools</h2>{across}" if across else ""}
<h2>Your questions</h2>{questions}
<h2>Other local accounts</h2>{table(["Account", "Groups"], accounts)}
{fold("PATH, in lookup order", path_table, where=f"{len(host.path_entries)} folders")}
</section>"""


def _check_status(check: Check) -> str:
    if check.found:
        return pill("review", "concern")
    return pill("not checked", "neutral") if check.unchecked else pill("clear", "ok")


def _key_locations(row: keys.KeyRow, home: str) -> str:
    return "<br>".join(
        f"{e(loc.tool)} · {e(loc.store)}"
        + (" " + pill("readable by other accounts", "concern") if loc.readable_by_others else "")
        + f"<br><code>{breakable(tilde(loc.location, home))}</code>"
        for loc in row.locations
    )


def _keys_view(audit: AuditReport) -> str:
    rows = keys.rows(audit)
    api = sum(1 for r in rows if r.kind == keys.API_KEY)
    table_rows = [
        [
            e(r.provider),
            e(r.kind),
            f"<code>{breakable(r.shown)}</code>"
            + (f"<br>{r.length} characters" if r.length else "")
            + f"<br><span class='small muted'>fingerprint {e(', '.join(r.fingerprints))}</span>",
            (f"{breakable(r.owner)}<br><span class='small muted'>from {e(r.owner_source)}</span>")
            if r.owner
            else "<span class='muted'>not recorded on disk</span>",
            _key_locations(r, audit.host.home),
            e(r.lifetime),
        ]
        for r in rows
    ]
    headers = ["Provider", "Type", "Key", "Belongs to", "Stored in", "Keeps working"]
    tldr = (
        f"{len(rows)} stored {'key or login' if len(rows) == 1 else 'keys and logins'} across "
        "the audited tools, "
        f"{api} of them API keys. Values are never kept: only the start, the last four "
        "characters of values 20 characters or longer, and a fingerprint that marks the same "
        "value stored in several places."
    )
    return f"""<section class="view" id="keys">
{_header("Across tools", "Keys", e(tldr))}
{table(headers, table_rows, raw=True)}
</section>"""


def _checklist_view(checklist: Checklist) -> str:
    rows = [
        [
            e(c.scope),
            _check_status(c),
            e(c.check),
            e(" ".join(x.statement for x in c.found)[:260] or c.unchecked),
        ]
        for c in checklist
    ]
    return f"""<section class="view" id="checklist">
<header><div class="eyebrow">Same checks as ai-footprint --doctor</div><h1>Checklist</h1></header>
{table(["Scope", "Status", "Check", "What was found, or why not checked"], rows, raw=True)}
</section>"""


def _method_view(audit: AuditReport) -> str:
    probes = table(
        ["Probe", "Checks"],
        [
            [
                breakable(v.command),
                "<br>".join(
                    f"{'✓' if c.passed else '✗'} {e(c.name)} ({e(c.detail)})" for c in v.checks
                ),
            ]
            for v in audit.probe_validation
        ],
        raw=True,
    )
    executed = table(
        ["#", "Command", "Exit", "Purpose"],
        [
            [str(i), " ".join(r.argv), str(r.returncode), r.purpose]
            for i, r in enumerate(audit.executed, start=1)
        ],
        cls="pre",
    )
    return f"""<section class="view" id="method">
<header><div class="eyebrow">Provenance</div><h1>How this was measured</h1>
<div class="tldr"><b>TL;DR</b> — {e(figures.method_summary(audit))}</div></header>
<h2>Probe registry</h2>{probes}
{fold("Every command executed", executed, where=f"{len(audit.executed)} commands")}
</section>"""


def _nav(audit: AuditReport) -> tuple[str, list[str]]:
    pages = [("summary", "Attack surface")]
    pages += [(f"tool-{t.name}", t.display_name) for t in audit.tools if t.installed]
    pages += [
        ("mcp", "MCP servers"),
        ("skills", "Skills"),
        ("plugins", "Plugins"),
        ("keys", "Keys"),
        ("host", "This machine"),
        ("checklist", "Checklist"),
        ("method", "How this was measured"),
    ]
    links = "".join(f'<a href="#{e(page)}">{e(label)}</a>' for page, label in pages)
    roots = [root for t in audit.tools if t.secret_scan for root in t.secret_scan.roots[:2]]
    scanned = sum(t.secret_scan.bytes_scanned for t in audit.tools if t.secret_scan)
    data = ""
    if roots:
        files = "".join(f"<code>{e(root)}</code>" for root in roots)
        data = (
            f'<div class="files"><div class="label">Data read · {e(human_size(scanned))}'
            f"</div>{files}</div>"
        )
    return f'<nav><div class="label">Report</div>{links}{data}</nav>', [p for p, _l in pages]


def _active_css(pages: list[str]) -> str:
    rules = [f'body:has(#{p}:target, #{p} :target) nav a[href="#{p}"]' for p in pages]
    rules.append('body:not(:has(.view:target, .view :target)) nav a[href="#summary"]')
    return ",\n".join(rules) + (
        " { color: var(--slate); border-color: var(--clay); font-weight: 600; }"
    )


def render(audit: AuditReport, checklist: Checklist) -> str:
    """The full HTML document."""
    nav, pages = _nav(audit)
    tools = "".join(_tool_view(audit, t) for t in audit.tools if t.installed)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>Attack surface · {e(audit.host.hostname)}</title>
<style>{CSS}
{_active_css(pages)}</style></head><body>
<div class="page">
{nav}
<main class="pages">
{_summary(audit)}
{tools}
{_extension_pages(audit)}
{_host_view(audit)}
{_keys_view(audit)}
{_checklist_view(checklist)}
{_method_view(audit)}
<footer>ai-footprint {e(audit.auditor_version)} · {e(audit.generated_at)} · Private: this file maps
your attack surface.</footer>
</main>
</div></body></html>"""


CSS = """
/* Layout: sticky side nav + main column; one view visible at a time (summary by default). */
:root {
  --ivory: #FAF9F5; --slate: #141413; --clay: #D97757; --oat: #E3DACC; --olive: #788C5D;
  --gray-150: #F0EEE6; --gray-300: #D1CFC5; --gray-500: #87867F; --gray-700: #3D3D3A;
  --clay-soft: #F6E3DA; --olive-soft: #E7ECDF;
  --serif: ui-serif, Georgia, "Times New Roman", serif;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  color-scheme: light;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--ivory); color: var(--gray-700); font-family: var(--sans); font-size: 15px;
  line-height: 1.65; -webkit-font-smoothing: antialiased; padding: 56px 24px 120px; }
.page { max-width: 1160px; margin: 0 auto; display: grid;
  grid-template-columns: 210px minmax(0, 1fr); gap: 48px; }
@media (max-width: 920px) {
  .page { grid-template-columns: 1fr; gap: 24px; }
  nav { position: static; }
}
nav { position: sticky; top: 32px; align-self: start; font-size: 13px; }
nav .label { font-family: var(--mono); font-size: 10px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--gray-500); margin-bottom: 12px; }
nav a { display: block; padding: 5px 0 5px 12px; border-left: 2px solid var(--gray-300);
  color: var(--gray-700); text-decoration: none; }
nav a:hover { color: var(--slate); border-color: var(--slate); }
nav .files { margin-top: 28px; border-top: 1px solid var(--gray-300); padding-top: 16px; }
nav .files code { display: block; font-family: var(--mono); font-size: 11px;
  color: var(--gray-500); padding: 3px 0; overflow-wrap: anywhere; }
.view { display: none; }
.view:target, .view:has(:target) { display: block; }
.pages:not(:has(:target)) > #summary { display: block; }
@supports not selector(:has(*)) { .view { display: block; margin-bottom: 80px; } }
header { margin-bottom: 12px; }
.eyebrow { font-family: var(--mono); font-size: 11px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--gray-500); margin-bottom: 10px; }
h1 { font-family: var(--serif); font-weight: 500; font-size: 32px; color: var(--slate);
  letter-spacing: -.01em; margin-bottom: 14px; text-wrap: balance; }
.tldr { border: 1.5px solid var(--gray-300); border-left: 3px solid var(--clay);
  border-radius: 10px; background: #fff; padding: 16px 18px; margin-bottom: 8px; }
.tldr b { color: var(--slate); }
.tldr ul { margin: 6px 0 0; padding-left: 18px; }
.hq { margin-top: 24px; }
.hq h3 { font-family: var(--serif); font-weight: 500; font-size: 17px; color: var(--slate);
  margin: 0 0 6px; }
.hq h3 .pill { margin-left: 6px; vertical-align: 2px; }
.hq > p { font-size: 14px; margin: 0 0 10px; max-width: 760px; }
h2 { font-family: var(--serif); font-weight: 500; font-size: 22px; color: var(--slate);
  margin: 40px 0 14px; text-wrap: balance; }
p { margin-bottom: 12px; max-width: 720px; }
a { color: var(--slate); text-decoration-color: var(--clay); text-underline-offset: 2px; }
code { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.muted { color: var(--gray-500); } .small { font-size: 13px; } .mono { font-family: var(--mono); }
details { border: 1.5px solid var(--gray-300); border-radius: 10px; background: #fff;
  margin: 14px 0; overflow: hidden; }
summary { list-style: none; cursor: pointer; padding: 14px 16px; font-family: var(--serif);
  font-size: 16px; color: var(--slate); display: flex; align-items: baseline; gap: 10px; }
summary::-webkit-details-marker { display: none; }
summary::before { content: "\\25B8"; color: var(--clay); font-family: var(--sans); font-size: 12px;
  transition: transform 120ms; }
details[open] > summary::before { transform: rotate(90deg); }
summary:focus-visible, a:focus-visible { outline: 2px solid var(--clay); outline-offset: 2px; }
summary .where { font-family: var(--mono); font-size: 11px; color: var(--gray-500);
  margin-left: auto; white-space: nowrap; }
details .body { padding: 0 16px 16px; }
details .body p { font-size: 14px; }
.question { color: var(--gray-500); font-style: italic; }
.points { list-style: none; display: grid; gap: 10px; }
.points li { display: grid; gap: 2px; font-size: 14px; padding-left: 12px;
  border-left: 2px solid var(--oat); }
.points .who { font-family: var(--mono); font-size: 10.5px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--clay); }
.tag { font-family: var(--mono); font-size: 10px; letter-spacing: .06em; text-transform: uppercase;
  color: var(--gray-500); border: 1px solid var(--gray-300); border-radius: 4px; padding: 0 5px;
  margin-left: 4px; }
.callout { display: flex; gap: 12px; border: 1.5px solid var(--oat);
  background: rgba(227, 218, 204, .35); border-radius: 10px; padding: 14px 16px; margin: 18px 0;
  font-size: 14px; }
.callout .ico { color: var(--clay); font-weight: 600; }
.anchor { scroll-margin-top: 24px; }
.ev { list-style: none; margin: 0 0 12px; display: grid; gap: 4px; }
.ev li { font-family: var(--mono); font-size: 12px; color: var(--gray-500);
  overflow-wrap: anywhere; padding-left: 10px; border-left: 2px solid var(--gray-150); }
.fix { border-top: 1px solid var(--gray-150); padding-top: 12px; display: grid; gap: 10px; }
.fix-title { font-weight: 600; color: var(--slate); margin: 0; }
.step pre { font-family: var(--mono); font-size: 12.5px; background: var(--gray-150);
  color: var(--slate); padding: 10px 12px; border-radius: 6px; overflow-x: auto;
  white-space: pre-wrap; overflow-wrap: anywhere; }
.step p { margin: 0; font-size: 14px; }
details.checks { border: 0; margin: 4px 0 0; background: none; }
details.checks > summary { padding: 0; font-size: 12px; }
details.checks > summary::before { content: none; }
details.checks ul { list-style: none; font-family: var(--mono); font-size: 11.5px;
  padding: 6px 0 0; }
details.checks li.ok { color: var(--olive); }
details.checks li.bad { color: var(--clay); }
dl.faq { margin-top: 8px; }
dl.faq dt { font-family: var(--serif); font-size: 16px; color: var(--slate); margin-top: 18px; }
dl.faq dd { font-size: 14px; margin: 4px 0 0; overflow-wrap: anywhere; }
dl.faq dd > p { max-width: 760px; }
.pill { display: inline-block; font-family: var(--mono); font-size: 10.5px;
  letter-spacing: .04em; padding: 1px 8px; border-radius: 999px; white-space: nowrap; }
.p-concern { background: var(--clay-soft); color: #9A4A2E; }
.p-ok { background: var(--olive-soft); color: #4F6239; }
.p-neutral { background: var(--gray-150); color: var(--gray-700); }
.tbl { overflow-x: auto; border: 1.5px solid var(--gray-300); border-radius: 10px;
  background: #fff; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--gray-150);
  vertical-align: top; }
td, td code { overflow-wrap: break-word; }
.pre td { white-space: pre-line; }
th { font-family: var(--mono); font-weight: 400; font-size: 10.5px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--gray-500); background: var(--gray-150);
  white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
.cred { border-top: 1px solid var(--gray-150); padding-top: 12px; margin-top: 12px; }
.cred:first-child { border-top: 0; margin-top: 0; padding-top: 0; }
.cred-title { color: var(--slate); margin-bottom: 2px; }
.sub { font-family: var(--mono); font-size: 10.5px; letter-spacing: .08em;
  text-transform: uppercase; color: var(--gray-500); margin: 14px 0 6px; }
.plain { padding-left: 18px; font-size: 14px; }
footer { margin-top: 64px; font-size: 12px; color: var(--gray-500); }
@media (prefers-reduced-motion: reduce) { summary::before { transition: none; } }
"""
