"""Usage data a tool sends its vendor, stated the same way for every harness.

Each profile's ``telemetry`` entries say what a stream sends, where, whether it is on by
default and which settings switch it. The harness passes the places it read settings from;
this module decides on or off with the tool's own precedence and writes one ``usage`` note
per stream, plus a note for each other tool's login that a stream which is on reads an
identifier from. A stream is stated only when the installed binary carries its markers, and
another tool's login file is read for which keys it has, never for their values.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

from ai_footprint.harnesses import registry
from ai_footprint.harnesses.account_notes import note
from ai_footprint.harnesses.common import Context, binary_path, load_json
from ai_footprint.harnesses.profile import ANY_VALUE, LoginRead, Profile, Telemetry
from ai_footprint.model import OTHER_TOOL_LOGIN, USAGE, AccountNote, ToolReport
from ai_footprint.text import join


class Value(NamedTuple):
    """A switch's value on this machine and where it was read."""

    value: str
    source: str


class State(NamedTuple):
    """Whether a stream is on, and the switch that decided it (None for the default)."""

    on: bool
    switch: str | None = None
    value: Value | None = None


def lookup(mapping: Mapping[str, Any], key: str) -> Any:  # noqa: ANN401 - JSON or TOML value
    """``mapping[key]``, or the value at a dotted path through nested tables; None if absent."""
    if key in mapping:
        return mapping[key]
    node: Any = mapping
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _text(value: Any) -> str:  # noqa: ANN401 - JSON or TOML value
    if isinstance(value, bool):
        return str(value).lower()
    return "" if value is None else str(value)


def read_values(
    profile: Profile, sources: Sequence[tuple[str, Mapping[str, Any]]]
) -> dict[str, Value]:
    """Each switch's value from the first source that sets it, in the order given.

    Args:
        profile: The harness profile whose switches are read.
        sources: ``(where, mapping)`` pairs, highest precedence first: the environment, or a
            parsed config file whose keys may be dotted paths.
    """
    names = {s.name for stream in profile.telemetry for s in stream.switches}
    values = {}
    for name in sorted(names):
        for where, mapping in sources:
            text = _text(lookup(mapping, name)).strip()
            if text:
                values[name] = Value(text, where)
                break
    return values


def _matches(value: str, accepted: tuple[str, ...]) -> bool:
    folded = value.lower()
    return any(a == ANY_VALUE or a.lower() == folded for a in accepted)


def state(stream: Telemetry, values: Mapping[str, Value]) -> State:
    """On or off: the first switch whose value turns the stream on or off, else the default.

    A switch's ``on`` values are tried before its ``off`` values, so ``*`` in ``off`` means
    every value not listed in ``on``.
    """
    for switch in stream.switches:
        found = values.get(switch.name)
        if found is None:
            continue
        if _matches(found.value, switch.on):
            return State(on=True, switch=switch.name, value=found)
        if _matches(found.value, switch.off):
            return State(on=False, switch=switch.name, value=found)
    return State(on=stream.default_on)


def _reason(decided: State) -> str:
    if decided.switch is None or decided.value is None:
        return "on by default" if decided.on else "off by default"
    word = "on" if decided.on else "off"
    return f"{word} ({decided.switch}={decided.value.value} in {decided.value.source})"


def _stream_note(stream: Telemetry, decided: State, checked: str) -> AccountNote:
    where = f" to {stream.host}" if stream.host else ""
    return note(
        USAGE,
        f"{stream.label}{where}: {_reason(decided)}. Sends {stream.sends}. "
        f"Identifier: {stream.identity}.",
        f"markers in the installed binary; {checked}",
        concern=decided.on,
    )


def _present(data: Any, fields: tuple[str, ...]) -> list[str]:  # noqa: ANN401 - parsed JSON
    if not isinstance(data, Mapping):
        return []
    return [f for f in fields if _text(lookup(data, f))]


def _read_note(
    home: Path, report: ToolReport, stream: Telemetry, read: LoginRead
) -> list[AccountNote]:
    present = _present(load_json(home / read.path.removeprefix("~/")), read.fields)
    if not present:
        return []
    other = registry().get(read.tool)
    owner = other.display_name if other else read.tool
    return [
        note(
            USAGE,
            f"{report.display_name} reads {owner}'s login file {read.path}, which holds "
            f"{join(present)} here. Its {stream.label.lower()} carry {read.sends}.",
            f"{read.path} keys; markers in the installed binary",
            concern=True,
            signal=OTHER_TOOL_LOGIN,
        )
    ]


def notes(
    ctx: Context,
    profile: Profile,
    report: ToolReport,
    sources: Sequence[tuple[str, Mapping[str, Any]]],
) -> list[AccountNote]:
    """One note per telemetry stream the installed binary confirms, and its other-tool reads.

    Args:
        ctx: Collection context.
        profile: The harness profile.
        report: The tool's report, for its binary and display name.
        sources: Where switches are read, highest precedence first (see ``read_values``).
    """
    binary = binary_path(report)
    if not binary:
        return []
    values = read_values(profile, sources)
    checked = join([where for where, _mapping in sources])
    out = []
    for stream in profile.telemetry:
        if not all(ctx.binary_has(binary, stream.markers).values()):
            continue
        decided = state(stream, values)
        out.append(_stream_note(stream, decided, checked))
        if not decided.on:
            continue
        for read in stream.reads:
            if ctx.binary_has(binary, [read.marker])[read.marker]:
                out += _read_note(ctx.home, report, stream, read)
    return out
