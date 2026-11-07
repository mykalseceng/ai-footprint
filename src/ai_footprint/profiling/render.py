"""``--profile`` output: plain text for people, JSON for the harness profiler agent."""

import dataclasses
from typing import Any

from ai_footprint.profiling import PROFILER_AGENT, ToolProfile, check_ids
from ai_footprint.text import plural


def to_json(profiles: list[ToolProfile]) -> dict[str, Any]:
    """Every profile as plain data, with each tool's uncovered features listed apart."""
    return {
        "tools": [
            {**dataclasses.asdict(p), "uncovered": [f.id for f in p.uncovered]} for p in profiles
        ],
        "check_ids": sorted(check_ids()),
    }


BINARY_WORDS = {None: "no marker", True: "in binary", False: "NOT in binary"}


def _feature_lines(profile: ToolProfile) -> list[str]:
    lines = [f"  Documented features ({len(profile.features)}):"]
    for f in profile.features:
        covered = ", ".join(f.checks) if f.checks else "no check"
        local = f"; {f.configured}" if f.configured else ""
        lines.append(f"    {f.id:<44} {BINARY_WORDS[f.in_binary]:<14} {covered}{local}")
    if not profile.features:
        lines.append("    none yet: the inventory is empty")
    return lines


def _discovery_lines(profile: ToolProfile) -> list[str]:
    lines = ["  Not in the profile yet:"]
    if profile.unmapped_paths:
        lines.append(f"    {plural(len(profile.unmapped_paths), 'path')} no artifact covers:")
        lines += [f"      {p}" for p in profile.unmapped_paths]
    for config, keys in profile.unknown_config_keys.items():
        lines.append(f"    {config}: {plural(len(keys), 'key')} no setting names:")
        lines.append(f"      {', '.join(keys)}")
    if profile.unknown_env:
        lines.append(f"    {plural(len(profile.unknown_env), 'variable')} the binary names:")
        lines.append(f"      {', '.join(profile.unknown_env)}")
    if len(lines) == 1:
        lines.append("    nothing: every path, config key and variable found is in the profile")
    return lines


def to_text(profiles: list[ToolProfile]) -> str:
    """One block per tool: identity, feature map, uncovered features, discoveries."""
    out = []
    for p in profiles:
        state = f"v{p.version}" if p.version else "installed" if p.installed else "not installed"
        out.append(
            f"{p.display_name} ({p.tool}) · {state}" + (f" · {p.binary}" if p.binary else "")
        )
        out += _feature_lines(p)
        if p.uncovered:
            ids = ", ".join(f.id for f in p.uncovered)
            out.append(f"  In the binary but audited by no check: {ids}")
        out += _discovery_lines(p)
        out.append("")
    out.append(
        f"Research the docs for anything above with the harness profiler ({PROFILER_AGENT}); "
        "it adds confirmed features to harnesses/<tool>/profile.toml."
    )
    return "\n".join(out)
