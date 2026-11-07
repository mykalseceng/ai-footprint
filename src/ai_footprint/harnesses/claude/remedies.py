"""Claude Code fixes that depend on the platform or on where an MCP server is configured."""

import shlex
from collections.abc import Mapping
from pathlib import Path

from ai_footprint.harnesses.base import RemedyContext
from ai_footprint.harnesses.profile import Remedy
from ai_footprint.model import Fix, FixCommand


def _q(text: str) -> str:
    return shlex.quote(text)


def require_approval(platform: str) -> Fix:
    """Block bypass mode with a root-owned managed policy, wherever the platform keeps it."""
    policy = (
        "/Library/Application Support/ClaudeCode" if platform == "darwin" else "/etc/claude-code"
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
            FixCommand("Remove shell aliases that add --dangerously-skip-permissions", manual=True),
        ],
    )


def remove_mcp(name: str, source: str, home: Path) -> Fix:
    """Remove a server from the scope that configures it: plugin, user or project."""
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
    if source.startswith("repo "):
        repo = source.removeprefix("repo ")
        repo = str(home) + repo[1:] if repo.startswith("~") else repo
        return Fix(
            "Remove the server from the repo's .mcp.json",
            [
                FixCommand(
                    f"cd {_q(repo)} && claude mcp remove {_q(name)} -s project",
                    help_probe=("claude", "mcp", "remove"),
                )
            ],
        )
    if source == "managed":
        return Fix(
            "Ask whoever manages this Mac to remove the server from managed-mcp.json",
            [FixCommand(f"Remove {name} from managed-mcp.json (needs admin rights)", manual=True)],
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


def remedy(action: Remedy, where: RemedyContext, args: Mapping[str, str]) -> Fix | None:
    """Fixes the profile's templates cannot express; None defers to the profile."""
    if action is Remedy.REQUIRE_APPROVAL:
        return require_approval(where.platform)
    if action is Remedy.REMOVE_MCP:
        return remove_mcp(args["name"], args["source"], where.home)
    return None
