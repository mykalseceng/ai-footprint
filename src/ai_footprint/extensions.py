"""What skills, plugins and MCP servers say about themselves, read from disk only.

A skill's SKILL.md frontmatter, a plugin's manifest and an npm package's package.json each
carry a description written by the author. Those are reported as-is, cut to two sentences.
Nothing here runs a server or guesses what a tool can do; when nothing on disk describes an
item, its description stays empty.
"""

import re
from pathlib import Path
from typing import Any

from ai_footprint.collectors.common import Context, is_dangling, load_json
from ai_footprint.model import Extension

MAX_DESCRIPTION = 160
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_MANIFESTS = (".claude-plugin/plugin.json", ".codex-plugin/plugin.json")
_COMPONENTS = ("skills", "commands", "agents")


def frontmatter(text: str) -> dict[str, str]:
    """Key/value pairs from a Markdown frontmatter block (plain scalars, blocks and lists).

    Handles the YAML subset skill files use: ``key: value``, quoted values, ``>`` / ``|``
    block scalars, and ``- item`` lists, which are joined with commas.
    """
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    out: dict[str, str] = {}
    key = ""
    for line in text[3:end].splitlines():
        match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if match:
            key = match.group(1)
            value = match.group(2).strip()
            out[key] = "" if value in {">", "|", ">-", "|-"} else value.strip("'\"")
        elif key and line.startswith((" ", "\t")):
            item = line.strip()
            if item.startswith("- "):
                item = item[2:].strip("'\"")
                out[key] = f"{out[key]}, {item}" if out[key] else item
            elif item:
                out[key] = f"{out[key]} {item}" if out[key] else item
    return out


def body_description(text: str) -> str:
    """The first paragraph of a Markdown file after its frontmatter and headings."""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        text = text[end + 4 :] if end != -1 else ""
    paragraph: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "<", "```", "|", "-", "*", "!")):
            if paragraph:
                break
            continue
        paragraph.append(stripped)
    return " ".join(paragraph)


def summarise_tools(declared: str) -> str:
    """Tool names from an ``allowed-tools`` list, with per-tool patterns counted, not listed."""
    counts: dict[str, int] = {}
    for item in (part.strip() for part in declared.split(",")):
        if not item:
            continue
        base, _, rest = item.partition("(")
        counts[base.strip()] = counts.get(base.strip(), 0) + (1 if rest else 0)
    return ", ".join(
        f"{base} ({count} pattern{'s' if count != 1 else ''})" if count else base
        for base, count in counts.items()
    )


_TRIGGER = re.compile(r"^(use (this |it )?when|use (this|it) (for|to)|trigger|invoke)", re.I)


def two_sentences(text: str) -> str:
    """At most two short sentences: the first, plus a second that still says what it does.

    A second sentence that only says when to use the item ("Use when…") is dropped, and the
    result is capped at ``MAX_DESCRIPTION`` characters at a word boundary.
    """
    sentences = [s for s in _SENTENCE_END.split(" ".join(text.split())) if s]
    if not sentences:
        return ""
    short = sentences[0]
    if (
        len(sentences) > 1
        and not _TRIGGER.match(sentences[1])
        and len(short) + len(sentences[1]) + 1 <= MAX_DESCRIPTION
    ):
        short = f"{short} {sentences[1]}"
    if len(short) <= MAX_DESCRIPTION:
        return short
    cut = short.rfind(" ", 0, MAX_DESCRIPTION - 1)
    return short[: cut if cut > MAX_DESCRIPTION // 2 else MAX_DESCRIPTION - 1] + "…"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:20000]
    except OSError:
        return ""


NO_SKILL_TEXT = "no description in its files"


def _skill_file(entry: Path) -> Path | None:
    """The file that defines a skill: a folder's SKILL.md, or a standalone Markdown skill."""
    if entry.is_dir():
        skill = entry / "SKILL.md"
        return skill if skill.is_file() else None
    if entry.suffix == ".md" and frontmatter(_read(entry)).get("description"):
        return entry
    return None


def _category(entry: Path) -> bool:
    return entry.is_dir() and any(_skill_file(child) for child in entry.iterdir())


def skill_rows(directory: Path, tool: str, ctx: Context, *, source: str = "") -> list[Extension]:
    """One row per skill in a folder, described by its own SKILL.md.

    A skill is a folder with a SKILL.md, or a Markdown file whose frontmatter has a
    description. A folder without a SKILL.md whose children are skills is a category folder,
    and its children are listed instead. Anything else is not a skill. The description is the
    frontmatter ``description``, else the file's first paragraph, else a fixed placeholder.
    """
    if not directory.is_dir():
        return []
    out = []
    for entry in sorted(directory.iterdir()):
        target = entry.resolve()
        if _category(target) and not (target / "SKILL.md").is_file():
            out += skill_rows(target, tool, ctx, source=source or ctx.display(str(entry)))
            continue
        skill = _skill_file(target)
        if skill is None:
            continue
        text = _read(skill)
        meta = frontmatter(text)
        linked = f"symlink → {ctx.display(str(target))}" if entry.is_symlink() else "local"
        description = meta.get("description") or body_description(text)
        out.append(
            Extension(
                tool,
                "skill",
                entry.name.removesuffix(".md"),
                source or linked,
                ctx.display(str(entry)),
                description=two_sentences(description) if description else NO_SKILL_TEXT,
                access=summarise_tools(meta.get("allowed-tools", "")),
                identity=str(target),
            )
        )
    return out


def count_skills(directory: Path) -> int:
    """Skills in a folder, counted the way ``skill_rows`` lists them."""
    if not directory.is_dir():
        return 0
    total = 0
    for entry in directory.iterdir():
        target = entry.resolve()
        if _category(target) and not (target / "SKILL.md").is_file():
            total += count_skills(target)
        elif _skill_file(target):
            total += 1
    return total


NO_MANIFEST = "no manifest on disk"


def plugin_manifest(install: Path) -> tuple[str, str]:
    """(description, components) from a plugin's manifest and the folders it ships."""
    data = next((load_json(install / rel) for rel in _MANIFESTS if (install / rel).is_file()), None)
    description = str((data or {}).get("description", "")) or NO_MANIFEST
    parts = []
    for name in _COMPONENTS:
        folder = install / name
        count = count_skills(folder) if name == "skills" else _visible_entries(folder)
        if count:
            parts.append(f"{count} {name.rstrip('s')}{'s' if count != 1 else ''}")
    servers = list((load_json(install / ".mcp.json") or {}).get("mcpServers", {}))
    if servers:
        parts.append(f"{len(servers)} MCP server{'s' if len(servers) != 1 else ''}")
    if (install / "hooks" / "hooks.json").is_file():
        parts.append("hooks")
    return two_sentences(description), ", ".join(parts) or "none found"


def _visible_entries(folder: Path) -> int:
    if not folder.is_dir():
        return 0
    return sum(1 for p in folder.iterdir() if not p.name.startswith("."))


def plugin_mcp_rows(install: Path, tool: str, plugin: str) -> list[Extension]:
    """MCP servers a plugin ships in its .mcp.json; ``"enabled": false`` marks one disabled."""
    servers = (load_json(install / ".mcp.json") or {}).get("mcpServers", {})
    return [
        mcp_row(
            tool,
            name,
            spec,
            f"plugin {plugin}",
            cwd=install,
            enabled=spec.get("enabled", True) is not False,
        )
        for name, spec in servers.items()
    ]


def mcp_row(
    tool: str,
    name: str,
    spec: dict[str, Any],
    source: str,
    *,
    cwd: Path | None = None,
    enabled: bool = True,
) -> Extension:
    """One MCP server row, described by its npm package when that package is cached locally."""
    url = spec.get("url")
    if url:
        return Extension(
            tool,
            "mcp",
            name,
            source,
            f"remote {url}",
            autostart=False,
            notes="" if enabled else "disabled",
            description=NO_MANIFEST,
            access=f"{spec.get('type', 'http')} {url}",
            identity=str(url),
        )
    command = str(spec.get("command", ""))
    args = [str(a) for a in spec.get("args", [])]
    dangling = enabled and is_dangling(command, args, cwd=cwd)
    env_keys = _env_summary(sorted((spec.get("env") or {}).keys()))
    notes = [
        "Target does not exist: whoever creates it gets code execution at startup"
        if dangling
        else "",
        "" if enabled else "disabled",
        f"env: {env_keys}" if env_keys else "",
    ]
    return Extension(
        tool,
        "mcp",
        name,
        source,
        " ".join([command, *args]),
        autostart=enabled,
        dangling=dangling,
        notes="; ".join(n for n in notes if n),
        description=npm_description(npx_package(command, args)) or NO_MANIFEST,
        access="stdio",
        identity=" ".join([command, *args]),
    )


def _env_summary(names: list[str]) -> str:
    if len(names) <= 3:
        return ", ".join(names)
    return f"{len(names)} variables ({', '.join(names[:3])}, …)"


def npx_package(command: str, args: list[str]) -> str:
    """The npm package an ``npx``/``bunx`` command runs, without its version suffix."""
    if Path(command).name not in {"npx", "bunx"}:
        return ""
    for arg in args:
        if arg.startswith("-"):
            continue
        name = arg
        if name.startswith("@"):
            scope, _, rest = name[1:].partition("/")
            return f"@{scope}/{rest.split('@', 1)[0]}"
        return name.split("@", 1)[0]
    return ""


def npm_description(package: str, home: Path | None = None) -> str:
    """The description in a cached copy of ``package``'s package.json, or empty."""
    if not package:
        return ""
    root = (home or Path.home()) / ".npm" / "_npx"
    for manifest in sorted(root.glob(f"*/node_modules/{package}/package.json")):
        data = load_json(manifest) or {}
        if data.get("description"):
            return two_sentences(str(data["description"]))
    return ""


def package_description(node_modules: Path, package: str) -> str:
    """The description of an installed npm package under ``node_modules``."""
    data = load_json(node_modules / package / "package.json") or {}
    return two_sentences(str(data.get("description", "")))


def dedupe(rows: list[Extension]) -> list[Extension]:
    """Collapse rows with the same kind and identity, keeping every source they were seen in."""
    seen: dict[tuple[str, str], Extension] = {}
    out = []
    for row in rows:
        key = (row.kind, row.identity or f"{row.name} {row.detail}")
        first = seen.get(key)
        if first is None:
            seen[key] = row
            out.append(row)
        else:
            if row.name not in first.name.split(" / "):
                first.name = f"{first.name} / {row.name}"
            if row.source not in first.source.split("; "):
                first.source = f"{first.source}; {row.source}"
    return out
