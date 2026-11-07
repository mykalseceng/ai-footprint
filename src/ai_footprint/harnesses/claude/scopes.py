"""Claude Code settings beyond the user's own: each project folder, and managed policy.

Claude Code merges settings from managed policy, the user, and each repo
(``.claude/settings.json``, ``.claude/settings.local.json``, ``.mcp.json``). A repo's files
can add hooks that run commands, MCP servers that start at launch, permission rules and
bypass mode, so they are read for every project folder ``~/.claude.json`` records.
"""

from pathlib import Path
from typing import Any

from ai_footprint import extensions, instructions
from ai_footprint.harnesses.common import Context, load_json
from ai_footprint.model import Extension, Setting

NAME = "claude"
BYPASS_MODE = "bypassPermissions"
PROJECTS_BYPASS = "projects with defaultMode=bypassPermissions"
PROJECT_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
MANAGED_SETTINGS = "managed-settings.json"
MANAGED_MCP = "managed-mcp.json"


def known_projects(config: dict[str, Any], home: Path) -> list[str]:
    """Project folders ``~/.claude.json`` records that still exist, in path order.

    The home folder is left out: its ``.claude`` folder is the user scope, read already.
    """
    return sorted(p for p in config.get("projects", {}) if Path(p).is_dir() and Path(p) != home)


def hook_rows(settings: dict[str, Any], source: str) -> list[Extension]:
    """One row per command hook in a settings document."""
    commands = [
        (event, group, hook)
        for event, groups in (settings.get("hooks") or {}).items()
        for group in (groups if isinstance(groups, list) else [])
        if isinstance(group, dict)
        for hook in group.get("hooks", [])
        if isinstance(hook, dict) and hook.get("type") == "command"
    ]
    return [
        Extension(
            NAME,
            "hook",
            f"{event} [{group.get('matcher', '*')}]",
            source,
            str(hook.get("command", ""))[:200],
            autostart=True,
            notes="Runs automatically on this event",
        )
        for event, group, hook in commands
    ]


def _project_documents(ctx: Context, projects: list[str]) -> list[tuple[str, str, dict]]:
    """``(project, shown source, parsed settings)`` for every project settings file."""
    out = []
    for project in projects:
        for rel in PROJECT_SETTINGS:
            data = load_json(Path(project) / rel)
            if isinstance(data, dict):
                out.append((project, f"{ctx.display(project)}/{rel}", data))
    return out


def project_settings(ctx: Context, projects: list[str]) -> list[Setting]:
    """Bypass mode, permission rules and blanket MCP approval set in repos."""
    documents = _project_documents(ctx, projects)
    if not documents:
        return []
    bypass = [
        shown
        for _project, shown, data in documents
        if (data.get("permissions") or {}).get("defaultMode") == BYPASS_MODE
    ]
    allow = sum(len((d.get("permissions") or {}).get("allow", [])) for _p, _s, d in documents)
    deny = sum(len((d.get("permissions") or {}).get("deny", [])) for _p, _s, d in documents)
    all_mcp = [shown for _p, shown, d in documents if d.get("enableAllProjectMcpServers")]
    rows = [
        Setting(
            "project permission rules",
            f"{deny} deny / {allow} allow in {len(documents)} project settings files",
            "Rules a repo adds; they apply whenever Claude Code runs there",
        )
    ]
    if bypass:
        rows.append(
            Setting(
                PROJECTS_BYPASS,
                ", ".join(bypass),
                f"{BYPASS_MODE} in a repo runs every tool without asking there",
                concern=True,
            )
        )
    if all_mcp:
        rows.append(
            Setting(
                "project enableAllProjectMcpServers",
                ", ".join(all_mcp),
                "Starts every server in that repo's .mcp.json without asking",
                concern=True,
            )
        )
    return rows


def project_extensions(ctx: Context, projects: list[str]) -> list[Extension]:
    """Hooks, MCP servers and skills each repo defines."""
    out = []
    for project, shown, data in _project_documents(ctx, projects):
        del project
        out += hook_rows(data, shown)
    for project in projects:
        shown = ctx.display(project)
        servers = (load_json(Path(project) / ".mcp.json") or {}).get("mcpServers", {})
        out += [
            extensions.mcp_row(NAME, name, spec, f"repo {shown}", cwd=Path(project))
            for name, spec in (servers.items() if isinstance(servers, dict) else [])
            if isinstance(spec, dict)
        ]
        out += extensions.skill_rows(
            Path(project) / ".claude" / "skills", NAME, ctx, source=f"project {shown}"
        )
    return out


def project_instructions(projects: list[str]) -> list[instructions.Candidate]:
    """Agent and command definitions each repo ships."""
    out = []
    for project in projects:
        folder = Path(project) / ".claude"
        out += [
            instructions.Candidate(path, "agent", NAME)
            for path in sorted((folder / "agents").glob("*.md"))
        ]
        out += [
            instructions.Candidate(path, "command", NAME)
            for path in sorted((folder / "commands").rglob("*.md"))
        ]
    return out


def managed(folder: Path) -> tuple[list[Setting], list[Extension]]:
    """What organization policy sets: bypass blocked or not, hooks, and MCP servers."""
    settings = load_json(folder / MANAGED_SETTINGS)
    servers = (load_json(folder / MANAGED_MCP) or {}).get("mcpServers", {})
    if not isinstance(settings, dict):
        return [
            Setting("managed policy", "none", f"No {MANAGED_SETTINGS} in {folder}")
        ], _managed_servers(servers)
    perms = settings.get("permissions") or {}
    rows = [
        Setting("managed policy", str(folder / MANAGED_SETTINGS), "Overrides user and repo"),
        Setting(
            "managed permissions.disableBypassPermissionsMode",
            str(perms.get("disableBypassPermissionsMode", "not set")),
            "'disable' blocks bypass mode for everyone on this machine",
        ),
        Setting(
            "managed allowManagedHooksOnly",
            str(settings.get("allowManagedHooksOnly", "not set")),
            "true runs only hooks from managed policy",
        ),
    ]
    return rows, hook_rows(settings, "managed settings") + _managed_servers(servers)


def _managed_servers(servers: Any) -> list[Extension]:  # noqa: ANN401 - raw JSON
    if not isinstance(servers, dict):
        return []
    return [
        extensions.mcp_row(NAME, name, spec, "managed")
        for name, spec in servers.items()
        if isinstance(spec, dict)
    ]
