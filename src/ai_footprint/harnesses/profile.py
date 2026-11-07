"""A harness's declarative profile: where it keeps data, what it names, how to fix it.

Each harness package ships ``profile.toml``. It holds everything about a tool that is data
rather than logic, so a new harness or a new feature of an existing one is a reviewed edit
to one file, which a person or an agent can make:

* ``roots``: folders the tool writes to, with the environment variable that moves each one;
* ``artifacts``: the files and folders inside those roots and what they hold; a path with
  ``*`` is a glob whose matches are reported as one artifact;
* ``project_artifacts``: files the tool reads inside each project folder it knows;
* ``endpoints``, ``fingerprint``, ``settings``, ``env``: names the installed binary must
  contain before the report states them (each becomes a ``Claim``);
* ``signals`` and ``capabilities``: what the central checks read for this tool;
* ``drives``: other harnesses this tool runs, by the tool's own provider id;
* ``remedies``: tool-specific fix commands the central checks offer;
* ``docs`` and ``features``: the documented feature inventory that ``--profile`` maps
  against this machine, and ``env_prefixes``, which it uses to find variables the installed
  binary reads that the inventory does not list yet.

Loading fails fast, naming the file and the key, when the profile is malformed.
"""

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any

from ai_footprint.model import Category

PROFILE_FILE = "profile.toml"


class ProfileError(ValueError):
    """Raised when a ``profile.toml`` is missing a key, has an unknown one, or a bad value."""


class Remedy(StrEnum):
    """Fixes a central check asks a harness for; a harness without one gets the generic fix."""

    REQUIRE_APPROVAL = "require-approval"
    PROTECT_CREDENTIALS = "protect-credentials"
    STOP_DAEMONS = "stop-daemons"
    REMOVE_MCP = "remove-mcp"
    WITHDRAW_TRUST = "withdraw-trust"
    DATA_CONTROLS = "data-controls"
    DISABLE_SHARE = "disable-share"


class Capability(StrEnum):
    """Facts a harness can record that some checks need before they can run."""

    ACCOUNT_SIGNALS = "account-signals"
    """The harness marks signs that a credential is used elsewhere as concerns."""


class FeatureKind(StrEnum):
    """What a documented feature is, which decides how ``--profile`` looks for it locally."""

    SETTING = "setting"
    ENV = "env"
    SUBCOMMAND = "subcommand"
    PATH = "path"
    HOOK = "hook"
    ENDPOINT = "endpoint"
    INTEGRATION = "integration"


@dataclass(frozen=True)
class Root:
    """A folder the tool writes to: ``$env`` when set, else ``default``, then ``child``."""

    default: str
    env: str = ""
    child: str = ""


@dataclass(frozen=True)
class ArtifactTemplate:
    """A known location, as ``{root}/relative/path``."""

    label: str
    path: str
    category: Category
    description: str


@dataclass(frozen=True)
class ProjectArtifact:
    """A location inside each project folder the tool knows, as a path relative to it."""

    label: str
    path: str
    category: Category
    description: str


@dataclass(frozen=True)
class EndpointSpec:
    """A host the tool names; ``marker`` is the string the binary must contain."""

    host: str
    purpose: str
    marker: str


@dataclass(frozen=True)
class Named:
    """A setting key or environment variable, and the string that proves the binary reads it."""

    name: str
    marker: str


@dataclass(frozen=True)
class FingerprintRow:
    """A trait of the tool's traffic or behaviour; ``{version}`` in ``value`` is filled in."""

    label: str
    value: str
    marker: str


@dataclass(frozen=True)
class CommandTemplate:
    """One fix step; ``$name`` placeholders are filled with shell-quoted arguments."""

    text: str
    manual: bool = False
    help: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class FixTemplate:
    """A remedy as the profile declares it."""

    summary: str
    commands: tuple[CommandTemplate, ...]


@dataclass(frozen=True)
class HostControl:
    """Apps in a tool's folder that can drive the screen and input, reported as host facts."""

    glob: str
    detail: str


@dataclass(frozen=True)
class DocSource:
    """An official page the harness profiler reads."""

    url: str
    topic: str


@dataclass(frozen=True)
class Feature:
    """One documented feature and how to find it on this machine.

    Attributes:
        id: Stable id, ``kind:name``.
        kind: What the feature is.
        name: The key, variable, subcommand (space-separated), path or host.
        summary: What it does, in one line.
        doc: Official page that documents it.
        marker: String the installed binary contains when it has the feature ("" when the
            feature cannot be seen in the binary).
        checks: Ids of the central checks that audit it; empty means no check covers it.
    """

    id: str
    kind: FeatureKind
    name: str
    summary: str
    doc: str = ""
    marker: str = ""
    checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class Profile:
    """Everything declarative about one harness."""

    name: str
    display_name: str
    binaries: tuple[str, ...]
    roots: Mapping[str, Root]
    presence: tuple[str, ...]
    process: str
    artifacts: tuple[ArtifactTemplate, ...] = ()
    project_artifacts: tuple[ProjectArtifact, ...] = ()
    endpoints: tuple[EndpointSpec, ...] = ()
    fingerprint: tuple[FingerprintRow, ...] = ()
    settings: tuple[Named, ...] = ()
    env: tuple[Named, ...] = ()
    approval_off: Mapping[str, str] = field(default_factory=dict)
    approval_off_flagged: tuple[str, ...] = ()
    capabilities: frozenset[Capability] = frozenset()
    process_words: tuple[str, ...] = ()
    env_prefixes: tuple[str, ...] = ()
    drives: Mapping[str, str] = field(default_factory=dict)
    host_control: tuple[HostControl, ...] = ()
    remedies: Mapping[Remedy, FixTemplate] = field(default_factory=dict)
    docs: tuple[DocSource, ...] = ()
    features: tuple[Feature, ...] = ()


_TOP = {
    "name",
    "display_name",
    "binaries",
    "process",
    "process_words",
    "env_prefixes",
    "drives",
    "roots",
    "presence",
    "artifacts",
    "project_artifacts",
    "endpoints",
    "fingerprint",
    "settings",
    "env",
    "signals",
    "capabilities",
    "host_control",
    "remedies",
    "docs",
    "features",
}


def _keys(where: str, table: Mapping[str, Any], allowed: set[str], required: set[str]) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ProfileError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    missing = required - set(table)
    if missing:
        raise ProfileError(f"{where}: missing key(s) {', '.join(sorted(missing))}")


def _str_tuple(where: str, value: Any) -> tuple[str, ...]:  # noqa: ANN401 - raw TOML
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ProfileError(f"{where}: expected a list of strings")
    return tuple(value)


def _enum[E: StrEnum](where: str, kind: type[E], value: str) -> E:
    try:
        return kind(value)
    except ValueError:
        allowed = ", ".join(member.value for member in kind)
        raise ProfileError(f"{where}: {value!r} is not one of {allowed}") from None


def _roots(where: str, raw: Mapping[str, Any]) -> dict[str, Root]:
    roots = {}
    for name, spec in raw.items():
        _keys(f"{where}.roots.{name}", spec, {"default", "env", "child"}, {"default"})
        roots[name] = Root(**spec)
    return roots


def _artifacts(where: str, raw: list[Mapping[str, Any]], roots: Mapping[str, Root]) -> tuple:
    out = []
    for index, spec in enumerate(raw):
        at = f"{where}.artifacts[{index}]"
        _keys(at, spec, {"label", "path", "category", "description"}, {"label", "path"})
        _check_root(at, spec["path"], roots)
        out.append(
            ArtifactTemplate(
                spec["label"],
                spec["path"],
                _enum(at, Category, spec.get("category", "")),
                spec.get("description", ""),
            )
        )
    return tuple(out)


def _project_artifacts(where: str, raw: list[Mapping[str, Any]]) -> tuple[ProjectArtifact, ...]:
    out = []
    for index, spec in enumerate(raw):
        at = f"{where}.project_artifacts[{index}]"
        _keys(at, spec, {"label", "path", "category", "description"}, {"label", "path"})
        if spec["path"].startswith(("/", "{", "~")) or ".." in Path(spec["path"]).parts:
            raise ProfileError(f"{at}: path {spec['path']!r} must be relative to the project")
        out.append(
            ProjectArtifact(
                spec["label"],
                spec["path"],
                _enum(at, Category, spec.get("category", "")),
                spec.get("description", ""),
            )
        )
    return tuple(out)


def _check_root(where: str, template: str, roots: Mapping[str, Root]) -> None:
    root = template.removeprefix("{").partition("}")[0]
    if not template.startswith("{") or root not in roots:
        names = ", ".join(f"{{{name}}}" for name in roots)
        raise ProfileError(f"{where}: path {template!r} must start with a root: {names}")


def _endpoints(where: str, raw: list[Mapping[str, Any]]) -> tuple[EndpointSpec, ...]:
    out = []
    for index, spec in enumerate(raw):
        at = f"{where}.endpoints[{index}]"
        _keys(at, spec, {"host", "purpose", "marker"}, {"host", "purpose"})
        out.append(EndpointSpec(spec["host"], spec["purpose"], spec.get("marker", spec["host"])))
    return tuple(out)


def _named(where: str, raw: list[Any]) -> tuple[Named, ...]:
    out = []
    for index, spec in enumerate(raw):
        if isinstance(spec, str):
            out.append(Named(spec, spec))
            continue
        _keys(f"{where}[{index}]", spec, {"name", "marker"}, {"name"})
        out.append(Named(spec["name"], spec.get("marker", spec["name"])))
    return tuple(out)


def _fingerprint(where: str, raw: list[Mapping[str, Any]]) -> tuple[FingerprintRow, ...]:
    out = []
    for index, spec in enumerate(raw):
        _keys(f"{where}.fingerprint[{index}]", spec, {"label", "value", "marker"}, {"label"})
        out.append(FingerprintRow(spec["label"], spec["value"], spec["marker"]))
    return tuple(out)


def _command(where: str, raw: Mapping[str, Any]) -> CommandTemplate:
    _keys(where, raw, {"run", "manual", "help", "markers"}, set())
    if ("run" in raw) == ("manual" in raw):
        raise ProfileError(f"{where}: give exactly one of run (a shell command) or manual")
    return CommandTemplate(
        text=raw.get("run") or raw["manual"],
        manual="manual" in raw,
        help=_str_tuple(f"{where}.help", raw.get("help", [])),
        markers=_str_tuple(f"{where}.markers", raw.get("markers", [])),
    )


def _remedies(where: str, raw: Mapping[str, Any]) -> dict[Remedy, FixTemplate]:
    out = {}
    for key, spec in raw.items():
        at = f"{where}.remedies.{key}"
        _keys(at, spec, {"summary", "commands"}, {"summary", "commands"})
        commands = tuple(
            _command(f"{at}.commands[{i}]", cmd) for i, cmd in enumerate(spec["commands"])
        )
        out[_enum(at, Remedy, key)] = FixTemplate(spec["summary"], commands)
    return out


def _features(where: str, raw: list[Mapping[str, Any]]) -> tuple[Feature, ...]:
    out = []
    seen: set[str] = set()
    allowed = {"kind", "name", "summary", "doc", "marker", "checks"}
    for index, spec in enumerate(raw):
        at = f"{where}.features[{index}]"
        _keys(at, spec, allowed, {"kind", "name", "summary"})
        kind = _enum(at, FeatureKind, spec["kind"])
        feature_id = f"{kind}:{spec['name']}"
        if feature_id in seen:
            raise ProfileError(f"{at}: duplicate feature {feature_id}")
        seen.add(feature_id)
        out.append(
            Feature(
                id=feature_id,
                kind=kind,
                name=spec["name"],
                summary=spec["summary"],
                doc=spec.get("doc", ""),
                marker=spec.get("marker", ""),
                checks=_str_tuple(f"{at}.checks", spec.get("checks", [])),
            )
        )
    return tuple(out)


def _docs(where: str, raw: list[Mapping[str, Any]]) -> tuple[DocSource, ...]:
    out = []
    for index, spec in enumerate(raw):
        _keys(f"{where}.docs[{index}]", spec, {"url", "topic"}, {"url", "topic"})
        out.append(DocSource(spec["url"], spec["topic"]))
    return tuple(out)


def _drives(where: str, raw: Mapping[str, Any]) -> dict[str, str]:
    """The tool's own provider ids mapped to the harness each one runs."""
    if not all(isinstance(v, str) for v in raw.values()):
        raise ProfileError(f"{where}.drives: expected provider id = harness name")
    return dict(raw)


def _host_control(
    where: str, raw: list[Mapping[str, Any]], roots: Mapping[str, Root]
) -> tuple[HostControl, ...]:
    out = []
    for index, spec in enumerate(raw):
        at = f"{where}.host_control[{index}]"
        _keys(at, spec, {"glob", "detail"}, {"glob", "detail"})
        _check_root(at, spec["glob"], roots)
        out.append(HostControl(spec["glob"], spec["detail"]))
    return tuple(out)


def _signals(where: str, raw: Mapping[str, Any]) -> tuple[dict[str, str], tuple[str, ...]]:
    """Setting values that turn approval off, and setting keys that do so when flagged."""
    _keys(f"{where}.signals", raw, {"approval_off", "approval_off_flagged"}, set())
    flagged = _str_tuple(
        f"{where}.signals.approval_off_flagged", raw.get("approval_off_flagged", [])
    )
    return dict(raw.get("approval_off", {})), flagged


def parse(where: str, raw: Mapping[str, Any]) -> Profile:
    """Build a ``Profile`` from parsed TOML.

    Raises:
        ProfileError: A key is missing or unknown, or a value has the wrong shape.
    """
    _keys(where, raw, _TOP, {"name", "display_name", "binaries", "roots", "presence", "process"})
    roots = _roots(where, raw["roots"])
    approval_off, approval_off_flagged = _signals(where, raw.get("signals", {}))
    for index, template in enumerate(raw["presence"]):
        _check_root(f"{where}.presence[{index}]", template, roots)
    return Profile(
        name=raw["name"],
        display_name=raw["display_name"],
        binaries=_str_tuple(f"{where}.binaries", raw["binaries"]),
        roots=roots,
        presence=_str_tuple(f"{where}.presence", raw["presence"]),
        process=raw["process"],
        artifacts=_artifacts(where, raw.get("artifacts", []), roots),
        project_artifacts=_project_artifacts(where, raw.get("project_artifacts", [])),
        endpoints=_endpoints(where, raw.get("endpoints", [])),
        fingerprint=_fingerprint(where, raw.get("fingerprint", [])),
        settings=_named(f"{where}.settings", raw.get("settings", [])),
        env=_named(f"{where}.env", raw.get("env", [])),
        approval_off=approval_off,
        approval_off_flagged=approval_off_flagged,
        capabilities=frozenset(
            _enum(f"{where}.capabilities", Capability, c) for c in raw.get("capabilities", [])
        ),
        process_words=_str_tuple(f"{where}.process_words", raw.get("process_words", [])),
        env_prefixes=_str_tuple(f"{where}.env_prefixes", raw.get("env_prefixes", [])),
        drives=_drives(where, raw.get("drives", {})),
        host_control=_host_control(where, raw.get("host_control", []), roots),
        remedies=_remedies(where, raw.get("remedies", {})),
        docs=_docs(where, raw.get("docs", [])),
        features=_features(where, raw.get("features", [])),
    )


def load(package: str) -> Profile:
    """Load and validate the ``profile.toml`` shipped in a harness package.

    Raises:
        ProfileError: The file is missing, is not TOML, or does not match the schema.
    """
    source = resources.files(package) / PROFILE_FILE
    where = f"{package.replace('.', '/')}/{PROFILE_FILE}"
    try:
        raw = tomllib.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ProfileError(f"{where}: every harness package needs a profile") from None
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"{where}: {exc}") from None
    profile = parse(where, raw)
    if profile.name != package.rpartition(".")[2]:
        raise ProfileError(f"{where}: name {profile.name!r} must match the package name")
    return profile


def load_beside(module: str) -> Profile:
    """Load the profile of the harness package that contains ``module`` (pass ``__name__``)."""
    return load(module.rpartition(".")[0])


def path_of(template: str, roots: Mapping[str, Path]) -> Path:
    """Resolve ``{root}/relative`` against resolved roots."""
    root, _, rest = template.removeprefix("{").partition("}")
    return roots[root] / rest.lstrip("/") if rest.strip("/") else roots[root]
