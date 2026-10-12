"""What surrounds the AI tools: reach, control, backups, unattended work, other AI tools.

Covers credentials an agent inherits, software that can drive the computer, backup copies,
processes that outlive their sessions, and AI tools this audit does not analyse in depth.

Every check reports presence and protection, never secret values. SSH keys are opened only
far enough to read the cipher name (``none`` means no passphrase).
"""

import base64
import binascii
import plistlib
import re
import shlex
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from ai_footprint.collectors.common import command_target, load_json
from ai_footprint.fsinfo import human_size, mode_string, readable_by_others, tree_stats
from ai_footprint.host import all_processes, started_at
from ai_footprint.model import HostFact, ProcessInfo, ToolReport
from ai_footprint.system import System

SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE)
TOOL_WORDS = ("claude", "codex", "opencode", "anthropic", "openai", "cursor")
TCC_SERVICES = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceAccessibility": "Accessibility (control the computer)",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServicePostEvent": "Send keystrokes and clicks",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServiceAppleEvents": "Automation of other apps",
}
TERMINALS = (
    "com.apple.Terminal",
    "com.googlecode.iterm2",
    "com.mitchellh.ghostty",
    "dev.warp.Warp-Stable",
    "net.kovidgoyal.kitty",
    "io.alacritty",
    "com.microsoft.VSCode",
    "com.todesktop.230313mzl4w4u92",
)


def _fact(
    topic: str, name: str, detail: str, path: Path | str = "", *, concern: bool = False
) -> HostFact:
    return HostFact(topic=topic, name=name, detail=detail, path=str(path), concern=concern)


def _clip(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters, ending in an ellipsis when anything was cut."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- what an agent running as you inherits -----------------------------------------------------


def ssh_key_cipher(path: Path) -> str | None:
    """Cipher name of a private key ("none" = no passphrase), or None if not a private key."""
    try:
        text = path.read_text(errors="replace")[:20000]
    except OSError:
        return None
    if "PRIVATE KEY-----" not in text:
        return None
    if "Proc-Type: 4,ENCRYPTED" in text:
        return "encrypted (PEM)"
    match = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----\s*(.+?)-----END", text, re.S)
    return _openssh_cipher(match.group(1)) if match else "none"


def _openssh_cipher(body: str) -> str:
    try:
        blob = base64.b64decode("".join(body.split())[:200] + "==", validate=False)
    except (binascii.Error, ValueError):
        return "unknown"
    if not blob.startswith(b"openssh-key-v1\x00"):
        return "unknown"
    length = int.from_bytes(blob[15:19], "big")
    return blob[19 : 19 + length].decode(errors="replace") or "unknown"


def _ssh_facts(home: Path, system: System) -> list[HostFact]:
    facts = []
    ssh = home / ".ssh"
    for path in sorted(ssh.glob("*")) if ssh.is_dir() else []:
        if path.suffix == ".pub" or not path.is_file():
            continue
        cipher = ssh_key_cipher(path)
        if cipher is None:
            continue
        open_key = cipher == "none"
        facts.append(
            _fact(
                "reach",
                f"SSH key {path.name}",
                "no passphrase" if open_key else f"passphrase-protected ({cipher})",
                path,
                concern=open_key,
            )
        )
    if system.has_probe("ssh-add") and system.env.get("SSH_AUTH_SOCK"):
        result = system.run("ssh-add", ["-l"])
        loaded = sum("SHA256:" in line or "MD5:" in line for line in result.stdout.splitlines())
        if loaded:
            facts.append(
                _fact(
                    "reach",
                    "ssh-agent",
                    f"{loaded} key(s) loaded and usable without a passphrase",
                    system.env.get("SSH_AUTH_SOCK", ""),
                    concern=True,
                )
            )
    return facts


def _count(path: Path, pattern: str) -> int:
    try:
        return len(re.findall(pattern, path.read_text(errors="replace"), re.MULTILINE))
    except OSError:
        return 0


def _cloud_facts(home: Path) -> list[HostFact]:
    checks = [
        (
            "AWS credentials",
            home / ".aws/credentials",
            r"^\s*aws_access_key_id\s*=",
            "access key(s) in plaintext",
        ),
        ("Kubernetes config", home / ".kube/config", r"^\s*- context:", "context(s)"),
        ("npm auth token", home / ".npmrc", r"_authToken\s*=", "registry token(s) in plaintext"),
        ("netrc", home / ".netrc", r"^\s*machine\s", "host login(s) in plaintext"),
        ("git credentials", home / ".git-credentials", r"^https?://", "stored git login(s)"),
        ("PyPI", home / ".pypirc", r"^\s*password\s*=", "upload password(s) in plaintext"),
    ]
    facts = []
    for name, path, pattern, label in checks:
        if path.is_file():
            count = _count(path, pattern)
            facts.append(_fact("reach", name, f"{count} {label}", path, concern=count > 0))
    facts.extend(_gh_docker_gcloud(home))
    return facts


def _gh_docker_gcloud(home: Path) -> list[HostFact]:
    facts = []
    gh = home / ".config/gh/hosts.yml"
    if gh.is_file():
        in_file = _count(gh, r"^\s*oauth_token:") > 0
        facts.append(
            _fact(
                "reach",
                "GitHub CLI",
                "token in plaintext hosts.yml"
                if in_file
                else "logged in; token kept in the OS keychain",
                gh,
                concern=True,
            )
        )
    docker = load_json(home / ".docker/config.json") or {}
    if docker:
        store = docker.get("credsStore", "")
        facts.append(
            _fact(
                "reach",
                "Docker registries",
                f"{len(docker.get('auths', {}))} registr(y/ies); "
                + (f"secrets in {store}" if store else "secrets in config.json"),
                home / ".docker/config.json",
                concern=bool(docker.get("auths")),
            )
        )
    gcloud = home / ".config/gcloud"
    if (gcloud / "credentials.db").is_file():
        config = gcloud / "configurations/config_default"
        account = (
            re.search(r"^account\s*=\s*(\S+)", config.read_text(errors="replace"), re.MULTILINE)
            if config.is_file()
            else None
        )
        facts.append(
            _fact(
                "reach",
                "Google Cloud SDK",
                f"logged in{' as ' + account.group(1) if account else ''}",
                gcloud / "credentials.db",
                concern=True,
            )
        )
    return facts


def _env_facts(system: System) -> list[HostFact]:
    names = sorted(k for k in system.env if SECRET_ENV.search(k) and system.env[k])
    if not names:
        return []
    return [
        _fact(
            "reach",
            "Secret-looking environment variables",
            ", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else ""),
            concern=True,
        )
    ]


def reach(home: Path, system: System) -> list[HostFact]:
    """Credentials any process running as you (including an agent) can use."""
    return _ssh_facts(home, system) + _cloud_facts(home) + _env_facts(system)


# --- what can drive this computer --------------------------------------------------------------

BROWSER_HOSTS = {
    "Chrome": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "Brave": "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
    "Edge": "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "Chromium": "Library/Application Support/Chromium/NativeMessagingHosts",
    "Firefox": "Library/Application Support/Mozilla/NativeMessagingHosts",
    "Chrome (Linux)": ".config/google-chrome/NativeMessagingHosts",
}


def _native_hosts(home: Path) -> list[HostFact]:
    facts = []
    for browser, rel in BROWSER_HOSTS.items():
        folder = home / rel
        for manifest in sorted(folder.glob("*.json")) if folder.is_dir() else []:
            data = load_json(manifest) or {}
            program = Path(str(data.get("path", "")))
            missing = bool(data.get("path")) and not program.exists()
            origins = len(data.get("allowed_origins", data.get("allowed_extensions", [])))
            detail = f"{browser} extension bridge to {program} ({origins} extension(s) allowed)" + (
                "; program missing" if missing else ""
            )
            facts.append(
                _fact(
                    "control",
                    str(data.get("name", manifest.stem)),
                    detail,
                    manifest,
                    concern=missing or any(w in manifest.name for w in TOOL_WORDS),
                )
            )
    return facts


def _desktop_mcp(home: Path) -> list[HostFact]:
    config = home / "Library/Application Support/Claude/claude_desktop_config.json"
    servers = (load_json(config) or {}).get("mcpServers", {})
    facts = []
    for name, spec in servers.items():
        args = [str(a) for a in spec.get("args", [])]
        facts.append(
            _fact(
                "control",
                f"Claude Desktop MCP '{name}'",
                _clip(" ".join([str(spec.get("command", "")), *args]), 240),
                config,
                concern=True,
            )
        )
    return facts


def _computer_use(home: Path) -> list[HostFact]:
    apps = sorted((home / ".codex/computer-use").glob("*.app"))
    return [
        _fact("control", app.stem, "Codex screen and input control helper", app, concern=True)
        for app in apps
    ]


def _tcc_grants(db: Path) -> list[tuple[str, str]] | None:
    """(client, service) grants from a TCC database, or None when it cannot be read."""
    if not db.exists():
        return None
    try:
        with sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True, timeout=2) as conn:
            rows = conn.execute(
                "SELECT client, service FROM access WHERE auth_value = 2"
            ).fetchall()
    except sqlite3.Error:
        return None
    return [(str(client), str(service)) for client, service in rows]


def _tcc_facts(home: Path) -> list[HostFact]:
    databases = [
        home / "Library/Application Support/com.apple.TCC/TCC.db",
        Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    ]
    grants: list[tuple[str, str]] = []
    readable = False
    for db in databases:
        rows = _tcc_grants(db)
        if rows is not None:
            readable = True
            grants.extend(rows)
    if not any(db.exists() for db in databases):
        return []
    if not readable:
        return [
            _fact(
                "control",
                "macOS privacy permissions",
                "could not read the TCC database, so this terminal does not have Full Disk "
                "Access; grants to other apps were not checked",
                databases[0],
            )
        ]
    facts = [
        _fact(
            "control",
            "Full Disk Access for this terminal",
            "this audit could read the protected TCC database, so the terminal it ran in "
            "has Full Disk Access, and so does every agent started from it",
            databases[0],
            concern=True,
        )
    ]
    for client, service in sorted(set(grants)):
        relevant = client in TERMINALS or any(w in client.lower() for w in TOOL_WORDS)
        if relevant and service in TCC_SERVICES:
            facts.append(_fact("control", client, TCC_SERVICES[service], concern=True))
    return facts


def control(home: Path) -> list[HostFact]:
    """Paths by which software can drive the browser, screen, keyboard or files."""
    return _native_hosts(home) + _desktop_mcp(home) + _computer_use(home) + _tcc_facts(home)


# --- backups -----------------------------------------------------------------------------------


def backups(system: System, roots: Iterable[Path]) -> list[HostFact]:
    """Whether AI-tool data folders are copied by Time Machine, and to where."""
    if not system.has_probe("tmutil"):
        return []
    destinations = system.run("tmutil", ["destinationinfo"])
    names = re.findall(r"^Name\s*:\s*(.+)$", destinations.stdout, re.MULTILINE)
    kinds = re.findall(r"^Kind\s*:\s*(.+)$", destinations.stdout, re.MULTILINE)
    if not names:
        return [_fact("backup", "Time Machine", "no backup destination configured")]
    where = ", ".join(f"{n} ({k.lower()})" for n, k in zip(names, kinds, strict=False))
    facts = [_fact("backup", "Time Machine destinations", where)]
    for root in roots:
        if not root.exists():
            continue
        result = system.run("tmutil", ["isexcluded", str(root)])
        included = "[Included]" in result.stdout
        facts.append(
            _fact(
                "backup",
                root.name or str(root),
                f"included in backups to {where}" if included else "excluded",
                root,
                concern=included,
            )
        )
    return facts


# --- what runs when you are not there -----------------------------------------------------------


def process_needle(detail: str) -> str | None:
    """The string a running MCP server shows in `ps`, from its configured command line."""
    try:
        words = shlex.split(detail)
    except ValueError:
        words = detail.split()
    if not words:
        return None
    return command_target(words[0], words[1:])


def _mcp_needles(tools: list[ToolReport]) -> dict[str, tuple[str, list[str]]]:
    """``{process needle: (server name, tools that configure it)}`` for local MCP servers."""
    needles: dict[str, tuple[str, list[str]]] = {}
    for tool in tools:
        for ext in tool.extensions:
            if ext.kind != "mcp" or ext.detail.startswith(("remote", "http")):
                continue
            target = process_needle(ext.detail)
            if not target or len(target) <= 6:
                continue
            _name, users = needles.setdefault(target, (ext.name, []))
            if tool.display_name not in users:
                users.append(tool.display_name)
    return needles


def _common_needle(orphans: list[ProcessInfo]) -> str:
    """The executable path shared by orphaned processes, for a targeted pkill pattern."""
    commands = [p.command for p in orphans]
    first = commands[0]
    for marker in (" --", " -"):
        first = first.split(marker, 1)[0]
    return first if all(first in c for c in commands) else commands[0]


def unattended(system: System, tools: list[ToolReport], home: Path) -> list[HostFact]:
    """Orphaned MCP servers and launch agents for AI tools (each tool reports its own daemons)."""
    procs = all_processes(system)
    facts = []
    groups: dict[frozenset[int], tuple[list[str], list[str], list[ProcessInfo]]] = {}
    for needle, (name, users) in _mcp_needles(tools).items():
        orphans = [p for p in procs if needle in p.command and p.ppid == 1]
        if not orphans:
            continue
        names, tools_using, _procs = groups.setdefault(
            frozenset(p.pid for p in orphans), ([], [], orphans)
        )
        names.extend(n for n in [name] if n not in names)
        tools_using.extend(u for u in users if u not in tools_using)
    for names, users, orphans in groups.values():
        oldest = min((d for d in map(started_at, orphans) if d), default=None)
        since = f", oldest started {oldest:%Y-%m-%d}" if oldest else ""
        facts.append(
            _fact(
                "unattended",
                f"MCP server '{', '.join(names)}' ({', '.join(users)})",
                f"{len(orphans)} orphaned process(es) still running after their "
                f"session ended{since}",
                _common_needle(orphans),
                concern=True,
            )
        )
    return facts + _launch_agents(home)


def _launch_agents(home: Path) -> list[HostFact]:
    folders = [
        home / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    facts = []
    for folder in folders:
        for plist in sorted(folder.glob("*.plist")) if folder.is_dir() else []:
            try:
                data = plistlib.loads(plist.read_bytes())
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            program = " ".join(
                [str(data.get("Program", "")), *map(str, data.get("ProgramArguments", []))]
            ).strip()
            if any(w in program.lower() for w in TOOL_WORDS):
                facts.append(
                    _fact(
                        "unattended",
                        plist.stem,
                        f"starts at login: {_clip(program, 160)}",
                        plist,
                        concern=True,
                    )
                )
    return facts


# --- AI tools this audit does not analyse in depth ---------------------------------------------

OTHER_TOOLS = (
    (
        "Claude Desktop",
        ("Library/Application Support/Claude", "Library/Logs/Claude"),
        "Library/Application Support/Claude/claude_desktop_config.json",
    ),
    ("ChatGPT app", ("Library/Application Support/com.openai.chat",), ""),
    ("Cursor", ("Library/Application Support/Cursor", ".cursor"), ".cursor/mcp.json"),
    ("Gemini CLI", (".gemini",), ".gemini/settings.json"),
    ("GitHub Copilot", (".config/github-copilot",), ""),
    ("Windsurf", (".codeium",), ".codeium/windsurf/mcp_config.json"),
    ("Continue", (".continue",), ""),
    ("aider", (".aider",), ""),
)


def other_tools(home: Path) -> list[HostFact]:
    """Footprint of AI tools outside this audit's depth, with any MCP servers they configure."""
    facts = []
    for name, rels, mcp_rel in OTHER_TOOLS:
        paths = [home / rel for rel in rels if (home / rel).exists()]
        if not paths:
            continue
        size = sum(tree_stats(p).size_bytes for p in paths)
        servers = list((load_json(home / mcp_rel) or {}).get("mcpServers", {})) if mcp_rel else []
        exposed = [p for p in paths if readable_by_others(p)]
        detail = f"{human_size(size)} in {', '.join(str(p).replace(str(home), '~') for p in paths)}"
        if servers:
            detail += f"; MCP servers: {', '.join(servers)}"
        if exposed:
            detail += f"; readable by other accounts ({mode_string(exposed[0].stat().st_mode)})"
        facts.append(_fact("other-tools", name, detail, paths[0], concern=bool(servers or exposed)))
    return facts


DATA_ROOTS = {
    "claude": (".claude",),
    "codex": (".codex",),
    "opencode": (".local/share/opencode", ".config/opencode"),
}


def scan(home: Path, system: System, tools: list[ToolReport]) -> list[HostFact]:
    """Every host-level observation, in report order."""
    roots = [home / rel for t in tools if t.installed for rel in DATA_ROOTS.get(t.name, ())]
    return (
        reach(home, system)
        + control(home)
        + backups(system, roots)
        + unattended(system, tools, home)
        + other_tools(home)
    )
