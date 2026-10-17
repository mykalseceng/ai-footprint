"""pi (``pi``, npm package ``@earendil-works/pi-coding-agent``) footprint collector.

pi keeps everything under one agent directory (``~/.pi/agent`` unless ``PI_CODING_AGENT_DIR``
is set): provider credentials and OAuth tokens in ``auth.json``, provider config in
``models.json``, settings, a project trust store, MCP servers, sessions as JSONL, and
extension packages installed with npm. Its installed code is a folder of bundled chunks,
so claims are searched for across that folder.
"""

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ai_footprint import extensions, instructions
from ai_footprint.collectors.common import (
    ArtifactSpec,
    Claim,
    Context,
    binary_info,
    binary_path,
    confirmed_settings,
    describe_all,
    endpoints,
    fingerprint_items,
    load_json,
    presence,
    provider_credential,
    value_or_unset,
)
from ai_footprint.fsinfo import mode_string, owner_name, readable_by_others
from ai_footprint.host import processes
from ai_footprint.model import (
    BinaryInfo,
    Category,
    Credential,
    Endpoint,
    Extension,
    Setting,
    StoreKind,
    ToolPresence,
    ToolReport,
)
from ai_footprint.secrets import scan_paths
from ai_footprint.tokens import inspect_token

NAME = "pi"
DISPLAY = "pi"
PACKAGE = "pi-coding-agent"
AGENT_DIR_VAR = "PI_CODING_AGENT_DIR"
SESSION_DIR_VAR = "PI_CODING_AGENT_SESSION_DIR"
C = Category

ARTIFACTS = (
    ArtifactSpec(
        "Provider credentials", "auth.json", C.CREDENTIAL, "Provider keys and OAuth tokens as JSON"
    ),
    ArtifactSpec(
        "Model config", "models.json", C.CONFIG, "Provider base URLs, API keys and model lists"
    ),
    ArtifactSpec(
        "Model catalog cache", "models-store.json", C.CACHE, "Provider model catalogs pi refreshes"
    ),
    ArtifactSpec("Settings", "settings.json", C.CONFIG, "Defaults, packages, trust, analytics"),
    ArtifactSpec("Project trust", "trust.json", C.CONFIG, "Trust decision per project folder"),
    ArtifactSpec("MCP servers", "mcp.json", C.EXTENSION, "Global MCP server config"),
    ArtifactSpec(
        "Sessions", "sessions", C.SESSION, "Session JSONL per project: messages and tool output"
    ),
    ArtifactSpec("Packages", "npm", C.EXTENSION, "Extension packages installed with npm"),
    ArtifactSpec("Extensions", "extensions", C.EXTENSION, "In-process extension code"),
    ArtifactSpec("Skills", "skills", C.EXTENSION, "User skills"),
    ArtifactSpec("Prompts", "prompts", C.EXTENSION, "Prompt templates"),
    ArtifactSpec("Tools", "tools", C.EXTENSION, "Custom tools"),
    ArtifactSpec("Themes", "themes", C.CACHE, "Custom themes"),
    ArtifactSpec("Managed binaries", "bin", C.BINARY, "fd and rg managed by pi"),
    ArtifactSpec("Debug log", "pi-debug.log", C.LOG, "Debug log"),
)

PROVIDER_HOSTS = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "openai-codex": "chatgpt.com",
    "deepseek": "api.deepseek.com",
    "google": "generativelanguage.googleapis.com",
    "openrouter": "openrouter.ai",
    "radius": "radius.pi.dev",
    "groq": "api.groq.com",
    "mistral": "api.mistral.ai",
    "xai": "api.x.ai",
    "zai": "api.z.ai",
    "github-copilot": "api.individual.githubcopilot.com",
}
PROVIDER_NAMES = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "openai-codex": "OpenAI",
    "deepseek": "DeepSeek",
    "google": "Google",
    "openrouter": "OpenRouter",
    "radius": "pi (radius)",
    "github-copilot": "GitHub Copilot",
}

ENDPOINTS = {
    "pi.dev": "Session share viewer",
    "radius.pi.dev": "pi model gateway",
}
ENDPOINT_MARKERS = {"pi.dev": "https://pi.dev/session/"}

FINGERPRINT = (
    ("User-Agent", "pi-coding-agent", '"User-Agent":"pi-coding-agent"'),
    ("Config dir", "~/.pi/agent, or PI_CODING_AGENT_DIR", "_CODING_AGENT_DIR"),
    ("Share viewer", "https://pi.dev/session/#<gist id>", "https://pi.dev/session/"),
    (
        "Context files",
        "AGENTS.override.md, AGENTS.md, CLAUDE.md, walking up from the working directory",
        '"AGENTS.override.md","AGENTS.md"',
    ),
    (
        "Trusted-project resources",
        ".pi/settings.json, mcp.json, extensions, skills, prompts, themes, SYSTEM.md, "
        "APPEND_SYSTEM.md",
        "APPEND_SYSTEM.md",
    ),
    ("Skills", "SKILL.md folders", "SKILL.md"),
)
SETTING_KEYS = (
    "defaultProjectTrust",
    "enableAnalytics",
    "enableInstallTelemetry",
    "shellCommandPrefix",
    "defaultProvider",
    '"packages"',
)
ENV_VARS = ("PI_TELEMETRY", "PI_OFFLINE", "PI_SHARE_VIEWER_URL", SESSION_DIR_VAR)
ENV_MARKERS = {SESSION_DIR_VAR: "_CODING_AGENT_SESSION_DIR"}
CONTEXT_FILES = ("AGENTS.override.md", "AGENTS.md", "CLAUDE.md")
SHARED_SKILLS_MARKER = '".agents","skills"'
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
DATED = re.compile(r"\d{4}-\d{2}-\d{2}")
PROJECT_PROMPTS = (".pi/SYSTEM.md", ".pi/APPEND_SYSTEM.md")
CLAIMS: tuple[Claim, ...] = (
    *(Claim(f"endpoint {host}", ENDPOINT_MARKERS.get(host, host)) for host in ENDPOINTS),
    *(Claim(f"signature: {label}", marker) for label, _value, marker in FINGERPRINT),
    *(Claim(f"setting {key}", key) for key in SETTING_KEYS),
    *(Claim(f"env {var}", ENV_MARKERS.get(var, var)) for var in ENV_VARS),
    Claim("trust store", "trust.json"),
    Claim("MCP config shape", "mcpServers"),
    Claim("credential file", '"auth.json"'),
    Claim("model catalog cache", "models-store.json"),
    Claim("shared skill dir ~/.agents/skills", SHARED_SKILLS_MARKER),
)


def agent_dir(ctx: Context) -> Path:
    """The agent directory, honouring ``PI_CODING_AGENT_DIR``."""
    custom = ctx.system.env.get(AGENT_DIR_VAR)
    return Path(custom).expanduser() if custom else ctx.home / ".pi" / "agent"


def collect(ctx: Context, found: ToolPresence | None = None) -> tuple[ToolReport, dict[str, Any]]:
    """Collect pi's footprint.

    Args:
        ctx: Collection context.
        found: This tool's presence when already detected, so binaries are probed once.

    Returns:
        The report and private facts for the rule engine.
    """
    report = ToolReport(name=NAME, display_name=DISPLAY)
    agent = agent_dir(ctx)
    settings = load_json(agent / "settings.json") or {}
    found = found or detect(ctx, sized=False)
    report.binaries = found.binaries
    report.installed = found.installed
    facts: dict[str, Any] = {"settings": settings, "agent": agent}
    if not report.installed:
        return report, facts
    report.artifacts = describe_all(agent, ARTIFACTS)
    report.credentials, facts["fingerprints"], providers = _credentials(ctx, agent)
    report.processes = processes(ctx.system, rf"(^|/)pi(\s|$)|{PACKAGE}")
    binary = binary_path(report)
    report.trusted_folders = _trusted(agent)
    report.settings = _settings(ctx, settings, agent, binary, len(report.trusted_folders))
    projects = sorted(set(report.trusted_folders) | _session_cwds(_sessions_dir(ctx, agent)))
    report.instructions = instructions.collect(_instruction_candidates(projects))
    report.extensions = _extensions(ctx, agent, settings, report.trusted_folders)
    if binary and ctx.binary_has(binary, [SHARED_SKILLS_MARKER])[SHARED_SKILLS_MARKER]:
        shared = extensions.skill_rows(ctx.home / ".agents" / "skills", NAME, ctx)
        report.extensions = extensions.dedupe(report.extensions + shared)
    report.endpoints = _endpoints(ctx, agent, report, providers)
    version = report.binaries[0].version if report.binaries else "?"
    rows = [(label, value.format(version=version), marker) for label, value, marker in FINGERPRINT]
    report.fingerprint = fingerprint_items(ctx, binary, rows)
    report.stats = _stats(_sessions_dir(ctx, agent), projects)
    if ctx.scan:
        report.secret_scan = scan_paths(
            [agent],
            workers=ctx.workers,
            display=ctx.display,
            known=facts["fingerprints"],
            stores=[agent / "auth.json", agent / "models.json"],
        )
    return report, facts


def detect(ctx: Context, *, sized: bool = True) -> ToolPresence:
    """Is pi installed, and where?"""
    return presence(NAME, DISPLAY, _binaries(ctx), [agent_dir(ctx)], sized=sized)


def _binaries(ctx: Context) -> list[BinaryInfo]:
    """The ``pi`` launchers on PATH, each resolved to the folder holding its bundled code."""
    found = []
    for path in ctx.system.which_all("pi"):
        resolved = Path(path).resolve()
        if PACKAGE not in resolved.parts:
            continue
        package_root = next(p for p in resolved.parents if p.name == PACKAGE)
        version = str((load_json(package_root / "package.json") or {}).get("version", ""))
        info = binary_info(ctx.system, path, version=version)
        info.resolved = str(resolved.parent)
        found.append(info)
    return found


def _sessions_dir(ctx: Context, agent: Path) -> Path:
    custom = ctx.system.env.get(SESSION_DIR_VAR)
    return Path(custom).expanduser() if custom else agent / "sessions"


def _credentials(ctx: Context, agent: Path) -> tuple[list[Credential], dict[str, str], set[str]]:
    """Stored credentials, their fingerprints, and the provider ids they belong to."""
    fingerprints: dict[str, str] = {}
    creds: list[Credential] = []
    providers: set[str] = set()
    path = agent / "auth.json"
    entries = load_json(path)
    if isinstance(entries, dict):
        for provider, entry in entries.items():
            if not isinstance(entry, dict) or not entry.get("type"):
                continue
            providers.add(provider)
            creds.append(
                provider_credential(
                    ctx,
                    entry,
                    tool=NAME,
                    provider=PROVIDER_NAMES.get(provider, provider),
                    store=StoreKind.FILE,
                    path=path,
                    fingerprints=fingerprints,
                    label=f"pi {provider}",
                )
            )
    models = agent / "models.json"
    for provider, spec in ((load_json(models) or {}).get("providers") or {}).items():
        key = spec.get("apiKey") if isinstance(spec, dict) else None
        if not isinstance(key, str) or not key or is_placeholder(provider, spec):
            continue
        providers.add(provider)
        info = inspect_token("key", key, now=ctx.now)
        fingerprints.setdefault(info.fingerprint, f"pi models.json apiKey for {provider}")
        creds.append(
            Credential(
                NAME,
                PROVIDER_NAMES.get(provider, provider),
                StoreKind.FILE,
                str(models),
                f"apiKey in provider config; baseUrl {spec.get('baseUrl', 'not set')}; "
                f"file mode {mode_string(models.stat().st_mode)}",
                readable_by_others=readable_by_others(models),
                tokens=[info],
            )
        )
    return creds, fingerprints, providers


def is_placeholder(provider: str, spec: dict[str, Any]) -> bool:
    """A models.json key that only fills the field: the provider's own name, on loopback.

    A provider served from this machine (Ollama, say) with ``apiKey`` equal to its name holds
    no secret, so it is not reported as a credential.
    """
    host = urlsplit(str(spec.get("baseUrl", ""))).hostname or ""
    return host in LOOPBACK and str(spec.get("apiKey", "")).lower() == provider.lower()


def _trusted(agent: Path) -> list[str]:
    """Project folders whose trust.json decision is true."""
    data = load_json(agent / "trust.json")
    if not isinstance(data, dict):
        return []
    out = []
    for path, entry in data.items():
        decision = entry.get("decision") if isinstance(entry, dict) else entry
        if decision is True:
            out.append(str(path))
    return out


def _session_cwds(sessions: Path) -> set[str]:
    """Working directories recorded in the first line of each session file."""
    cwds: set[str] = set()
    if not sessions.is_dir():
        return cwds
    for path in sessions.rglob("*.jsonl"):
        try:
            with path.open("rb") as handle:
                head = handle.readline(4096)
            cwd = json.loads(head).get("cwd")
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(cwd, str) and cwd:
            cwds.add(cwd)
    return cwds


def _settings(
    ctx: Context, settings: dict[str, Any], agent: Path, binary: str, trusted: int
) -> list[Setting]:
    packages = settings.get("packages") or []
    rows: list[tuple[Setting, str]] = [
        (
            Setting(
                "defaultProjectTrust",
                value_or_unset(settings, "defaultProjectTrust"),
                "Trust applied to projects without a decision in trust.json",
                concern=settings.get("defaultProjectTrust") == "trusted",
            ),
            "defaultProjectTrust",
        ),
        (
            Setting(
                "enableAnalytics",
                value_or_unset(settings, "enableAnalytics"),
                "Opt in to analytics data sharing (pi's own description)",
                concern=bool(settings.get("enableAnalytics")),
            ),
            "enableAnalytics",
        ),
        (
            Setting(
                "enableInstallTelemetry",
                value_or_unset(settings, "enableInstallTelemetry"),
                "Version and update ping after updates (pi's own description)",
            ),
            "enableInstallTelemetry",
        ),
        (
            Setting(
                "packages",
                ", ".join(map(str, packages)) or "not set",
                "Extension packages installed into the agent dir and loaded in-process",
                concern=bool(packages),
            ),
            '"packages"',
        ),
        (
            Setting(
                "shellCommandPrefix",
                value_or_unset(settings, "shellCommandPrefix"),
                "Prefix added to every shell command",
            ),
            "shellCommandPrefix",
        ),
        (
            Setting(
                "defaultProvider",
                f"{value_or_unset(settings, 'defaultProvider')} / "
                f"{value_or_unset(settings, 'defaultModel')}",
                "Provider and model used by default",
            ),
            "defaultProvider",
        ),
        (
            Setting(
                "trusted projects",
                f"{trusted} in {ctx.display(str(agent / 'trust.json'))}",
                "Trusted projects load .pi/ settings, MCP servers, extensions, skills and prompts",
            ),
            "",
        ),
    ]
    rows += [
        (
            Setting(f"env.{var}", value_or_unset(ctx.system.env, var), "Set in this environment"),
            ENV_MARKERS.get(var, var),
        )
        for var in ENV_VARS
    ]
    store = agent / "models-store.json"
    if store.is_file() and not os.access(store, os.R_OK):
        info = store.stat()
        rows.append(
            (
                Setting(
                    "models-store.json",
                    f"could not read {ctx.display(str(store))} (owned by "
                    f"{owner_name(info.st_uid)}, mode {mode_string(info.st_mode)})",
                    "pi's provider model catalog cache",
                ),
                "models-store.json",
            )
        )
    return confirmed_settings(ctx, binary, rows)


def _instruction_candidates(projects: list[str]) -> list[instructions.Candidate]:
    return instructions.project_candidates(projects, CONTEXT_FILES, NAME) + [
        instructions.Candidate(Path(project) / rel, "project", NAME)
        for project in projects
        for rel in PROJECT_PROMPTS
    ]


def _extensions(
    ctx: Context, agent: Path, settings: dict[str, Any], trusted: list[str]
) -> list[Extension]:
    out = _mcp_rows(agent / "mcp.json", "mcp.json")
    for project in trusted:
        out += _mcp_rows(Path(project) / ".pi" / "mcp.json", f"project {ctx.display(project)}")
    node_modules = agent / "npm" / "node_modules"
    for package in settings.get("packages") or []:
        name = str(package).removeprefix("npm:")
        out.append(
            Extension(
                NAME,
                "plugin",
                str(package),
                "settings.packages",
                ctx.display(str(node_modules / name)),
                autostart=True,
                notes="Loaded in-process" + _foreign_owner(node_modules / name),
                description=extensions.package_description(node_modules, name)
                or extensions.NO_MANIFEST,
                access="npm package",
                identity=str(node_modules / name),
            )
        )
    out += extensions.skill_rows(agent / "skills", NAME, ctx)
    for folder, kind in (("extensions", "plugin"), ("prompts", "command")):
        for row in extensions.skill_rows(agent / folder, NAME, ctx):
            row.kind = kind
            out.append(row)
    for project in trusted:
        out += extensions.skill_rows(
            Path(project) / ".pi" / "skills", NAME, ctx, source=f"project {ctx.display(project)}"
        )
    return extensions.dedupe(out)


def _foreign_owner(path: Path) -> str:
    """``; files owned by root`` when another account owns an installed package."""
    try:
        uid = path.stat().st_uid
    except OSError:
        return ""
    return "" if uid == os.getuid() else f"; files owned by {owner_name(uid)}"


def _mcp_rows(path: Path, source: str) -> list[Extension]:
    servers = (load_json(path) or {}).get("mcpServers") or {}
    return [
        extensions.mcp_row(NAME, name, spec, source, cwd=path.parent)
        for name, spec in servers.items()
        if isinstance(spec, dict)
    ]


def _endpoints(
    ctx: Context, agent: Path, report: ToolReport, providers: set[str]
) -> list[Endpoint]:
    hosts = [
        Endpoint(NAME, PROVIDER_HOSTS[p], f"{p} provider API", "credentials")
        for p in sorted(providers & set(PROVIDER_HOSTS))
    ]
    logs = [agent / "pi-debug.log"]
    return endpoints(ctx, report, ENDPOINTS, logs, markers=ENDPOINT_MARKERS, extra=hosts)


def _stats(sessions: Path, projects: list[str]) -> dict[str, str]:
    stats = {"project folders": str(len(projects))}
    if sessions.is_dir():
        files = list(sessions.rglob("*.jsonl"))
        stats["sessions"] = str(len(files))
        dated = sorted(f.name[:10] for f in files if DATED.match(f.name))
        if dated:
            stats["first session"], stats["last session"] = dated[0], dated[-1]
    return stats
