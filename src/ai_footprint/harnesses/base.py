"""The harness contract: one supported AI tool, its profile and the code that reads it.

Central code (the audit, the checks, the reports) knows a tool only through ``Harness``.
What is data lives in the profile; what needs code is a function on the harness:

* ``collect`` reads the tool's footprint into a ``ToolReport``;
* ``detect`` says whether the tool is installed (the default reads the profile);
* ``remedy`` builds fixes that need more than a template (the default fills the
  profile's templates).
"""

import re
import shlex
import string
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from ai_footprint.fsinfo import describe, describe_matches
from ai_footprint.harnesses.common import (
    Claim,
    Context,
    binary_info,
    fingerprint_items,
    presence,
)
from ai_footprint.harnesses.profile import Profile, Remedy, path_of
from ai_footprint.model import (
    Artifact,
    BinaryInfo,
    FingerprintItem,
    Fix,
    FixCommand,
    ToolPresence,
    ToolReport,
)

VERSION = re.compile(r"\d+\.\d+\.\d+")


@dataclass(frozen=True)
class RemedyContext:
    """What a remedy may depend on besides its arguments."""

    platform: str
    home: Path


Collector = Callable[[Context, ToolPresence], ToolReport]
BinaryFinder = Callable[[Context], list[BinaryInfo]]
RemedyFn = Callable[[Remedy, RemedyContext, Mapping[str, str]], Fix | None]


def _no_code_remedy(action: Remedy, where: RemedyContext, args: Mapping[str, str]) -> None:
    del action, where, args


def resolve_roots(ctx: Context, profile: Profile) -> dict[str, Path]:
    """Each root as a path: the environment override when set, else the default.

    ``~`` means the audited home, so tests and ``--home`` audit a different folder, and an
    absolute default is read under the system's root, so tests never see this machine's apps.
    """
    out = {}
    for name, root in profile.roots.items():
        base = (ctx.system.env.get(root.env) if root.env else "") or root.default
        if base == "~" or base.startswith("~/"):
            base = str(ctx.home) + base[1:]
        path = Path(base)
        if path.is_absolute() and base == root.default:
            path = ctx.system.root / path.relative_to("/")
        out[name] = path / root.child if root.child else path
    return out


def resolve(ctx: Context, profile: Profile, template: str) -> Path:
    """``{root}/relative`` as a path on this machine."""
    return path_of(template, resolve_roots(ctx, profile))


def artifacts(ctx: Context, profile: Profile) -> list[Artifact]:
    """The profile's artifacts that exist, described, in profile order."""
    roots = resolve_roots(ctx, profile)
    out = []
    for spec in profile.artifacts:
        path = path_of(spec.path, roots)
        if "*" in spec.path:
            artifact = describe_matches(
                sorted(_glob(path)),
                shown=str(path),
                label=spec.label,
                category=spec.category,
                description=spec.description,
            )
        else:
            artifact = describe(
                path, label=spec.label, category=spec.category, description=spec.description
            )
        if artifact.exists:
            out.append(artifact)
    return out


def _glob(pattern: Path) -> list[Path]:
    """Matches of an absolute pattern whose wildcards are below its fixed prefix."""
    parts = pattern.parts
    fixed = next(i for i, part in enumerate(parts) if "*" in part)
    return list(Path(*parts[:fixed]).glob(str(Path(*parts[fixed:]))))


def project_artifacts(profile: Profile, projects: list[str]) -> list[Artifact]:
    """The profile's per-project files that exist, project by project; the path names it."""
    out = []
    for project in projects:
        for spec in profile.project_artifacts:
            artifact = describe(
                Path(project) / spec.path,
                label=spec.label,
                category=spec.category,
                description=spec.description,
            )
            if artifact.exists:
                out.append(artifact)
    return out


def fingerprint(ctx: Context, profile: Profile, report: ToolReport) -> list[FingerprintItem]:
    """The profile's fingerprint rows that the installed binary confirms."""
    binary = report.binaries[0].resolved if report.binaries else ""
    version = report.binaries[0].version if report.binaries else "?"
    rows = [(r.label, r.value.format(version=version), r.marker) for r in profile.fingerprint]
    return fingerprint_items(ctx, binary, rows)


def known_endpoints(profile: Profile) -> dict[str, str]:
    """``{host: purpose}`` for the hosts the profile lists."""
    return {e.host: e.purpose for e in profile.endpoints}


def endpoint_markers(profile: Profile) -> dict[str, str]:
    """``{host: marker}`` where the binary marker differs from the host name."""
    return {e.host: e.marker for e in profile.endpoints if e.marker != e.host}


def default_binaries(ctx: Context, profile: Profile) -> list[BinaryInfo]:
    """Every copy of the profile's binaries on PATH, in PATH order, with ``--version``."""
    found = []
    for name in profile.binaries:
        for path in ctx.system.which_all(name):
            result = ctx.system.run_tool(str(Path(path).resolve()), ["--version"])
            match = VERSION.search(result.stdout)
            found.append(binary_info(ctx.system, path, version=match.group(0) if match else ""))
    return found


def profile_claims(profile: Profile) -> tuple[Claim, ...]:
    """Claims every profile makes: endpoints, fingerprint, settings and env vars."""
    return (
        *(Claim(f"endpoint {e.host}", e.marker) for e in profile.endpoints),
        *(Claim(f"signature: {r.label}", r.marker) for r in profile.fingerprint),
        *(Claim(f"setting {s.name}", s.marker) for s in profile.settings),
        *(Claim(f"env {v.name}", v.marker) for v in profile.env),
    )


@dataclass(frozen=True)
class Harness:
    """A supported AI tool.

    Attributes:
        profile: The tool's declarative profile.
        collect_fn: Reads the footprint of a tool that ``detect`` found.
        binaries_fn: Finds the installed binaries when that needs more than a PATH lookup
            (a version read from a package, a native binary behind a launcher).
        remedy_fn: Builds fixes the profile's templates cannot express; returning None
            falls back to the template.
        extra_claims: Claims the collector makes beyond the profile's.
    """

    profile: Profile
    collect_fn: Collector
    binaries_fn: BinaryFinder | None = None
    remedy_fn: RemedyFn = _no_code_remedy
    extra_claims: tuple[Claim, ...] = field(default=())

    @property
    def name(self) -> str:
        """Registry key and the tool's command name."""
        return self.profile.name

    @property
    def display_name(self) -> str:
        """Name shown in reports."""
        return self.profile.display_name

    @cached_property
    def claims(self) -> tuple[Claim, ...]:
        """Every claim the report may make about this tool, each gated on a binary marker."""
        return (*profile_claims(self.profile), *self.extra_claims)

    def detect(self, ctx: Context, *, sized: bool = True) -> ToolPresence:
        """Is the tool installed, and where?"""
        finder = self.binaries_fn or (lambda c: default_binaries(c, self.profile))
        paths = [resolve(ctx, self.profile, t) for t in self.profile.presence]
        return presence(self.name, self.display_name, finder(ctx), paths, sized=sized)

    def collect(self, ctx: Context, found: ToolPresence | None = None) -> ToolReport:
        """Read the tool's footprint.

        Args:
            ctx: Collection context.
            found: This tool's presence when already detected, so binaries are probed once.
        """
        return self.collect_fn(ctx, found or self.detect(ctx, sized=False))

    def remedy(self, action: Remedy, where: RemedyContext, **args: str) -> Fix | None:
        """The tool's fix for ``action``, or None when the tool has none.

        Args:
            action: Which fix the check needs.
            where: Platform and home, for fixes whose paths depend on them.
            **args: Values for the template's ``$name`` placeholders; each is shell-quoted
                in ``run`` commands and inserted as is in ``manual`` steps.

        Raises:
            KeyError: The profile's template names a placeholder the check did not pass.
        """
        fix = self.remedy_fn(action, where, args)
        if fix is not None:
            return fix
        template = self.profile.remedies.get(action)
        if template is None:
            return None
        commands = []
        for command in template.commands:
            values = args if command.manual else {k: shlex.quote(v) for k, v in args.items()}
            commands.append(
                FixCommand(
                    string.Template(command.text).substitute(values),
                    manual=command.manual,
                    help_probe=(self.name, *command.help) if command.help else (),
                    markers=command.markers,
                    marker_tool=self.name if command.markers else "",
                )
            )
        return Fix(template.summary, commands)
