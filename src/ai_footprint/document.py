"""The run's output document: the full audit plus every view the dashboard shows.

``--json`` writes this document and the dashboard renders it, so what a reader sees and what
an agent reads are the same data. The top level is the audit itself
(``dataclasses.asdict``); ``checklist`` and ``views`` add what is derived from it: the
narratives, the answers, fix-validation labels, extensions grouped across tools, the
summary sentences and every figure (``figures.py``). Every sentence and number derived from
the data is written here, in Python; the dashboard only lays it out.
"""

import dataclasses
import re
from typing import Any

from ai_footprint import answers, figures, keys, surface
from ai_footprint.model import (
    AuditReport,
    Category,
    CommandValidation,
    Exposure,
    Extension,
    Lens,
    ToolReport,
)
from ai_footprint.report_text import validation_label
from ai_footprint.rules import Checklist

HOST_SCOPE = (
    "What the rest of this Mac adds to the AI tools' exposure: other logins an agent can use, "
    "software that can drive the computer, what keeps running when you are away, and setup "
    "shared across tools."
)
USER_SKILLS = "User skill folders"
Grouped = list[tuple[Extension, list[str]]]
_TONES = {"PASS": "ok", "FAIL": "concern"}


def build(audit: AuditReport, checklist: Checklist) -> dict[str, Any]:
    """The document for one run: the audit, the checklist and the derived views."""
    document = dataclasses.asdict(audit)
    document["checklist"] = [
        {
            "scope": c.scope,
            "check": c.check,
            "exposed": bool(c.found),
            "exposures": [x.id for x in c.found],
            "unchecked": c.unchecked,
        }
        for c in checklist
    ]
    document["views"] = _views(audit, checklist)
    return document


def _views(audit: AuditReport, checklist: Checklist) -> dict[str, Any]:
    tools = [t for t in audit.tools if t.installed]
    grouped = grouped_extensions(audit)
    return {
        "figures": {
            "machine": [
                dataclasses.asdict(f)
                for f in figures.machine(
                    audit, checklist, [(x.kind, x.autostart) for x, _t in grouped]
                )
            ],
            "tools": {
                t.name: [dataclasses.asdict(f) for f in figures.for_tool(t, checklist)]
                for t in tools
            },
        },
        "signals_matrix": figures.signals_matrix(audit),
        "keys": [dataclasses.asdict(row) for row in keys.rows(audit)],
        "disk": figures.disk_by_category(audit),
        "method": figures.method_summary(audit),
        "lenses": [
            {"id": lens.value, "title": lens.title, "question": lens.question} for lens in Lens
        ],
        "categories": [category.value for category in Category],
        "machine": {**_narrative(surface.for_machine(audit)), "proof": proof(audit)},
        "tools": {t.name: _tool_view(audit, t) for t in tools},
        "credentials": [
            {
                "tool": tool.name,
                "provider": group[0].provider,
                "stores": sorted({c.store for c in group}),
                "readable_by_others": any(c.readable_by_others for c in group),
                "lifetime": surface.lifetime(group),
            }
            for tool, group in surface.merged_credentials(tools)
        ],
        "extensions": [
            {**dataclasses.asdict(x), "used_by": used_by, "group": skill_group(x)}
            for x, used_by in grouped
        ],
        "pages": page_summaries(grouped, audit),
        "host": _host_view(audit),
        "fix_labels": {
            x.id: [_fix_label(v) for v in x.fix.validations] for x in audit.all_exposures() if x.fix
        },
    }


def _narrative(story: surface.Narrative) -> dict[str, Any]:
    return {
        "headline": story.headline,
        "lenses": [
            {"lens": view.lens.value, "points": [dataclasses.asdict(p) for p in view.points]}
            for view in story.lenses
        ],
    }


def proof(audit: AuditReport) -> str:
    """The callout: how fast this audit read a Keychain token without a prompt, if it did."""
    for tool in audit.tools:
        for cred in tool.credentials:
            match = re.search(r"read it via /usr/bin/security in ([\d.]+)s", cred.protection)
            if match:
                return (
                    f"This audit read your {cred.provider} token from the Keychain through "
                    f"`/usr/bin/security` in {match.group(1)} seconds, with no prompt. "
                    "Any program running as you can do the same."
                )
    return "This audit is read-only and never writes a secret value to this report."


def _fix_label(validation: CommandValidation) -> dict[str, str]:
    label, tone = validation_label(validation)
    return {
        "label": label,
        "badge": label.lstrip("✓✗ ").split(":")[0],
        "tone": _TONES.get(tone, "neutral"),
    }


def _tool_view(audit: AuditReport, tool: ToolReport) -> dict[str, Any]:
    return {
        **_narrative(surface.for_tool(audit, tool)),
        "answers": [dataclasses.asdict(a) for a in answers.for_tool(tool, audit.host)],
    }


def grouped_extensions(audit: AuditReport) -> Grouped:
    """Every extension across installed tools, one entry per identity, with the tools using it."""
    groups: dict[tuple[str, str], tuple[Extension, list[str]]] = {}
    for tool in audit.tools:
        if not tool.installed:
            continue
        for x in tool.extensions:
            key = (x.kind, x.identity or f"{x.name} {x.detail}")
            entry = groups.setdefault(key, (x, []))
            if tool.display_name not in entry[1]:
                entry[1].append(tool.display_name)
    return list(groups.values())


def skill_group(x: Extension) -> str:
    """The fold a row is listed under: its plugin, user skill folders, or none."""
    if x.source.startswith("plugin "):
        return x.source
    return USER_SKILLS if x.kind == "skill" else ""


def _verb(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def page_summaries(grouped: Grouped, audit: AuditReport) -> dict[str, str]:
    """The summary sentence for the MCP servers, Skills and Plugins pages."""
    return {
        "mcp": _mcp_tldr([(x, t) for x, t in grouped if x.kind in {"mcp", "connector"}]),
        "skills": _skills_tldr([(x, t) for x, t in grouped if x.kind == "skill"]),
        "plugins": _plugins_tldr([(x, t) for x, t in grouped if x.kind == "plugin"], audit),
    }


def _mcp_tldr(rows: Grouped) -> str:
    local = [x for x, _t in rows if x.kind == "mcp" and x.access == "stdio"]
    remote = [x for x, _t in rows if x.kind == "mcp" and x.access != "stdio"]
    connectors = [x for x, _t in rows if x.kind == "connector"]
    parts = []
    if local:
        parts.append(
            f"{surface.plural(len(local), 'server')} run as local processes with your permissions"
        )
    if remote:
        parts.append(f"{len(remote)} are remote servers that receive what the model sends")
    if connectors:
        parts.append(f"{len(connectors)} are claude.ai connectors reached with the OAuth token")
    first = surface.join(parts) + "." if parts else "No MCP servers are configured."
    auto = sum(1 for x, _t in rows if x.autostart and x.kind == "mcp")
    dangling = sum(1 for x, _t in rows if x.dangling)
    env = sum(1 for x, _t in rows if "env:" in x.notes)
    shared = sum(1 for _x, t in rows if len(t) > 1)
    facts = []
    if auto:
        facts.append(f"{auto} {_verb(auto, 'starts', 'start')} whenever a tool starts")
    if dangling:
        facts.append(
            f"{dangling} {_verb(dangling, 'points', 'point')} at a missing file, so whoever "
            "creates it runs code"
        )
    if env:
        facts.append(
            f"{env} {_verb(env, 'receives', 'receive')} environment variables from the config"
        )
    if shared:
        facts.append(f"{shared} {_verb(shared, 'is', 'are')} configured in more than one tool")
    return first + (f" {surface.join(facts)}." if facts else "")


def _links_outside_home(x: Extension) -> bool:
    return x.source.startswith("symlink → ") and not x.source.startswith("symlink → ~")


def _skills_tldr(rows: Grouped) -> str:
    if not rows:
        return "No skills are installed."
    from_plugins = sum(1 for x, _t in rows if x.source.startswith("plugin "))
    linked = sum(1 for x, _t in rows if _links_outside_home(x))
    shared = sum(1 for _x, t in rows if len(t) > 1)
    restricted = sum(1 for x, _t in rows if x.access)
    where = [f"{from_plugins} live in plugin caches"] if from_plugins else []
    if len(rows) - from_plugins:
        where.append(f"{len(rows) - from_plugins} in user folders")
    if linked:
        where.append(f"{linked} of those are symlinks to a folder outside your home")
    text = (
        "Skills are Markdown instructions loaded into the model's context; whoever can write "
        f"them steers every session that loads them. {surface.join(where)}."
    )
    if shared:
        text += (
            f" {shared} {_verb(shared, 'is', 'are')} loaded by more than one tool, so one edit "
            "reaches all of them."
        )
    plain = len(rows) - restricted
    return text + (
        f" {restricted} {_verb(restricted, 'declares', 'declare')} a tool restriction; "
        f"{plain} {_verb(plain, 'declares', 'declare')} none."
    )


def _plugins_tldr(rows: Grouped, audit: AuditReport) -> str:
    if not rows:
        return "No plugins are installed."
    shipped = [
        x
        for t in audit.tools
        if t.installed
        for x in t.extensions
        if x.source.startswith("plugin ") and x.kind in {"skill", "mcp", "hook"}
    ]
    counts = {kind: sum(1 for x in shipped if x.kind == kind) for kind in ("skill", "mcp", "hook")}
    markets = sorted(
        {
            x.source.removeprefix("marketplace ")
            if x.source.startswith("marketplace ")
            else x.name.partition("@")[2] or x.source
            for x, _t in rows
        }
    )
    ships = [
        f"{counts['skill']} skills" if counts["skill"] else "",
        surface.plural(counts["mcp"], "MCP server") if counts["mcp"] else "",
        f"{surface.plural(counts['hook'], 'hook')} that run shell commands automatically"
        if counts["hook"]
        else "",
    ]
    text = f"Plugins come from {surface.plural(len(markets), 'source')}: {', '.join(markets)}."
    if any(ships):
        text += f" Together they ship {surface.join([s for s in ships if s])}."
    return text + " Whoever can change a source or its cache folder changes what runs next session."


def _host_view(audit: AuditReport) -> dict[str, Any]:
    findings = {x.id: x for x in audit.host_exposures}
    asked = {finding_id for _topic, _question, finding_id, _fallback in answers.HOST_QUESTIONS}
    return {
        "scope": HOST_SCOPE,
        "questions": [
            _host_question(topic, question, findings.get(finding_id), fallback, audit)
            | {"finding_id": finding_id}
            for topic, question, finding_id, fallback in answers.HOST_QUESTIONS
        ],
        "across": [x.id for x in audit.host_exposures if x.id not in asked],
    }


def _host_question(
    topic: str, question: str, finding: Exposure | None, fallback: str, audit: AuditReport
) -> dict[str, Any]:
    has_facts = any(f.topic == topic for f in audit.host.facts)
    if finding:
        answer = finding.statement
    elif has_facts:
        answer = "Nothing to review."
    else:
        answer = fallback
    return {
        "topic": topic,
        "question": question,
        "status": "review" if finding else "clear",
        "answer": answer,
    }
