"""Profile a harness: its documented features mapped onto this machine, and what is new.

``profile(ctx, harness)`` answers, for one installed tool:

* for each feature in the profile's inventory, whether the installed binary has it (its
  marker), whether it is configured here, and which central checks audit it;
* what the machine shows that the inventory does not cover yet (``discover``).

Documentation research is not done here: it needs judgement, so the harness profiler agent
(``.claude/agents/harness-profiler.md``) reads the official docs, edits ``profile.toml``, and
reruns this to confirm every marker it added is in the installed binary.
"""

from dataclasses import dataclass, field
from pathlib import Path

from ai_footprint import checks
from ai_footprint.harnesses.base import Harness
from ai_footprint.harnesses.common import Context
from ai_footprint.harnesses.profile import Feature, FeatureKind
from ai_footprint.model import ToolReport
from ai_footprint.profiling import discover

PROFILER_AGENT = ".claude/agents/harness-profiler.md"
"""The agent that researches docs and writes what it confirms into profile.toml."""


@dataclass
class FeatureStatus:
    """One documented feature as found on this machine.

    Attributes:
        in_binary: True or False when the feature has a marker; None when it has none.
        configured: What this machine shows for it, or "" when nothing.
        checks: Check ids that audit it; empty means no check covers it.
    """

    id: str
    kind: str
    name: str
    summary: str
    doc: str
    in_binary: bool | None
    configured: str
    checks: list[str] = field(default_factory=list)


@dataclass
class ToolProfile:
    """A harness profiled on this machine."""

    tool: str
    display_name: str
    installed: bool
    version: str
    binary: str
    docs: list[str]
    features: list[FeatureStatus]
    unmapped_paths: list[str]
    unknown_config_keys: dict[str, list[str]]
    unknown_env: list[str]

    @property
    def uncovered(self) -> list[FeatureStatus]:
        """Features present in the binary that no check audits."""
        return [f for f in self.features if f.in_binary is not False and not f.checks]


def check_ids() -> set[str]:
    """Every central check id, tool and host."""
    return {r.id for r in checks.TOOL_RULES} | {r.id for r in checks.HOST_RULES}


def _same_setting(key: str, name: str) -> bool:
    """A recorded setting key names the feature: equal, or ending in it (``env.X``, ``a.b``)."""
    return key == name or key.endswith(f".{name}") or name.endswith(f".{key}")


def _configured(ctx: Context, feature: Feature, report: ToolReport) -> str:
    if feature.kind is FeatureKind.ENV:
        return "set in this environment" if feature.name in ctx.system.env else ""
    if feature.kind is FeatureKind.PATH:
        path = Path(feature.name.replace("~", str(ctx.home), 1))
        return "exists" if path.exists() else ""
    if feature.kind is FeatureKind.SETTING:
        hit = next((s for s in report.settings if _same_setting(s.key, feature.name)), None)
        return f"{hit.key} = {hit.value}" if hit and hit.value != "not set" else ""
    if feature.kind is FeatureKind.ENDPOINT:
        seen = [e.source for e in report.endpoints if e.host == feature.name]
        return f"seen ({', '.join(sorted(set(seen)))})" if seen else ""
    return ""


def profile(ctx: Context, harness: Harness) -> ToolProfile:
    """Map the harness's feature inventory onto this machine and list what is new.

    Args:
        ctx: Collection context; the secret scan is not run.
        harness: The tool to profile.
    """
    found = harness.detect(ctx, sized=False)
    report = (
        harness.collect(ctx, found)
        if found.installed
        else ToolReport(harness.name, harness.display_name)
    )
    binary = found.binaries[0].resolved if found.binaries else ""
    markers = [f.marker for f in harness.profile.features if f.marker]
    present = ctx.binary_has(binary, markers) if binary else {}
    features = [
        FeatureStatus(
            id=f.id,
            kind=str(f.kind),
            name=f.name,
            summary=f.summary,
            doc=f.doc,
            in_binary=present.get(f.marker, False) if f.marker and binary else None,
            configured=_configured(ctx, f, report),
            checks=list(f.checks),
        )
        for f in harness.profile.features
    ]
    return ToolProfile(
        tool=harness.name,
        display_name=harness.display_name,
        installed=found.installed,
        version=found.binaries[0].version if found.binaries else "",
        binary=ctx.display(binary) if binary else "",
        docs=[d.url for d in harness.profile.docs],
        features=features,
        unmapped_paths=discover.names(discover.unmapped_paths(ctx, harness), ctx),
        unknown_config_keys=discover.unknown_config_keys(ctx, harness),
        unknown_env=discover.unknown_env(binary, harness),
    )
