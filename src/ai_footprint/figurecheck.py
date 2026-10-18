"""Recompute every figure in the run's document from its raw data, with separate code.

``figures.py`` computes the numbers the dashboard and the report show. This module reads
only the JSON document and recomputes each one, then checks that they match, that no sum
adds a location twice or a scanned folder twice, that a count added across tools never
calls itself distinct, and that the signals grid, the disk chart, the checklist, the
method summary and the headline agree with the signals they summarise. Any mismatch fails
``--validate``.
"""

import re
from collections.abc import Callable
from typing import Any

from ai_footprint import rules
from ai_footprint.fsinfo import human_size
from ai_footprint.model import CheckResult, CommandValidation

Doc = dict[str, Any]
SESSION, BINARY = "session", "binary"
TOOL_RUNS = {"Confirm tool version", "Confirm subcommand exists"}
_HELD = re.compile(r"holding ([\d,]+) (?:distinct )?secret-shaped values")


def _installed(doc: Doc) -> list[Doc]:
    return [t for t in doc["tools"] if t["installed"]]


def _exposures(doc: Doc) -> list[Doc]:
    return [x for t in _installed(doc) for x in t["exposures"]] + doc["host_exposures"]


def _outer(artifacts: list[Doc]) -> list[Doc]:
    """Each distinct path once, skipping any path inside another listed path."""
    by_path: dict[str, Doc] = {}
    for artifact in artifacts:
        by_path.setdefault(artifact["path"].rstrip("/"), artifact)
    kept: list[str] = []
    for path in sorted(by_path, key=lambda p: (len(p), p)):
        if not any(path.startswith(parent + "/") for parent in kept):
            kept.append(path)
    return [by_path[p] for p in kept]


def _bytes(artifacts: list[Doc], category: str | None = None) -> int:
    total = 0
    for artifact in _outer(artifacts):
        if category is None or artifact["category"] == category:
            total += artifact["size_bytes"]
    return total


def _secret_total(tools: list[Doc]) -> int | None:
    scans = [t["secret_scan"] for t in tools if t["secret_scan"]]
    if not scans:
        return None
    return sum(kind["unique"] for scan in scans for kind in scan["kinds"])


def _approval(tool: Doc) -> str:
    if any(x["id"] == f"{tool['name']}:no-approval" for x in tool["exposures"]):
        return "found"
    if any(s["key"] in rules.APPROVAL_KEYS for s in tool["settings"]):
        return "not found"
    return "not checked"


def _network_hosts(doc: Doc, tool: Doc) -> int | str:
    capture = doc.get("network") or {}
    found = [t for t in capture.get("tools", []) if t["tool"] == tool["name"]]
    if not found:
        return "not captured"
    return len({c["host"] for c in found[0]["connections"]})


def _compare(figure: Doc | None, expected: object, show: Callable[[Any], str]) -> CheckResult:
    if figure is None:
        return CheckResult("figure present", passed=False, detail="missing")
    shown = "not scanned" if expected is None else show(expected)
    ok = figure["value"] == expected and figure["display"] == shown
    return CheckResult(
        f"{figure['label']} = {shown}",
        passed=ok,
        detail="recomputed" if ok else f"document has {figure['display']!r}",
    )


def _by_id(figures: list[Doc]) -> dict[str, Doc]:
    return {f["id"]: f for f in figures}


def _machine(doc: Doc) -> CommandValidation:
    tools = _installed(doc)
    shown = _by_id(doc["views"]["figures"]["machine"])
    exposed = sum(1 for c in doc["checklist"] if c["exposures"])
    artifacts = [a for t in tools for a in t["artifacts"]]
    autostart = sum(1 for x in doc["views"]["extensions"] if x["autostart"])
    checks = [
        _compare(shown.get("tools"), len(tools), str),
        _compare(shown.get("signals"), len(_exposures(doc)), str),
        _compare(shown.get("checks"), exposed, lambda n: f"{n} of {len(doc['checklist'])}"),
        _compare(shown.get("credentials"), sum(len(t["credentials"]) for t in tools), str),
        _compare(shown.get("secrets"), _secret_total(tools), lambda n: f"{n:,}"),
        _compare(shown.get("disk"), _bytes(artifacts), human_size),
        _compare(shown.get("autostart"), autostart, str),
        _compare(shown.get("api_keys"), _api_key_count(doc), str),
        _distinct_wording(shown.get("secrets"), tools),
        _roots_disjoint(tools),
        _extensions_grouped(doc),
    ]
    return CommandValidation("figures on the overview", checks)


def _tool(doc: Doc, tool: Doc) -> CommandValidation:
    shown = _by_id(doc["views"]["figures"]["tools"].get(tool["name"], []))
    checks = [
        _compare(shown.get("disk"), _bytes(tool["artifacts"]), human_size),
        _compare(shown.get("sessions"), _bytes(tool["artifacts"], SESSION), human_size),
        _compare(shown.get("credentials"), len(tool["credentials"]), str),
        _compare(shown.get("extensions"), len(tool["extensions"]), str),
        _compare(shown.get("signals"), len(tool["exposures"]), str),
        _compare(shown.get("secrets"), _secret_total([tool]), lambda n: f"{n:,}"),
        _compare(shown.get("approval"), _approval(tool), str),
        _compare(shown.get("network"), _network_hosts(doc, tool), str),
    ]
    return CommandValidation(f"figures on tool-{tool['name']}", checks)


def _distinct_wording(figure: Doc | None, tools: list[Doc]) -> CheckResult:
    scanned = sum(1 for t in tools if t["secret_scan"])
    detail = figure["detail"] if figure else ""
    ok = scanned <= 1 or "within each tool" in detail
    return CheckResult(
        "a secret count added across tools says it is distinct only within each tool",
        passed=ok,
        detail=detail or "no figure",
    )


def _roots_disjoint(tools: list[Doc]) -> CheckResult:
    roots = [
        (t["name"], r.rstrip("/"))
        for t in tools
        if t["secret_scan"]
        for r in t["secret_scan"]["roots"]
    ]
    shared = sorted(
        f"{a} {ra} / {b} {rb}"
        for i, (a, ra) in enumerate(roots)
        for b, rb in roots[i + 1 :]
        if a != b and (ra == rb or ra.startswith(rb + "/") or rb.startswith(ra + "/"))
    )
    return CheckResult(
        "secret scans of different tools never read the same folder",
        passed=not shared,
        detail="; ".join(shared) or "disjoint",
    )


def _extensions_grouped(doc: Doc) -> CheckResult:
    keys = {
        (x["kind"], x["identity"] or f"{x['name']} {x['detail']}")
        for t in _installed(doc)
        for x in t["extensions"]
    }
    count = len(doc["views"]["extensions"])
    return CheckResult(
        "extensions across tools are listed once per identity",
        passed=count == len(keys),
        detail=f"{count} listed, {len(keys)} distinct",
    )


def _matrix(doc: Doc) -> CommandValidation:
    expected: dict[str, dict[str, int]] = {}
    for exposure in _exposures(doc):
        row = expected.setdefault(exposure["lens"], {})
        row[exposure["tool"]] = row.get(exposure["tool"], 0) + 1
    grid = doc["views"]["signals_matrix"]
    checks = []
    for lens, row in grid.items():
        nonzero = {tool: n for tool, n in row.items() if n}
        checks.append(
            CheckResult(
                f"signals grid row {lens}",
                passed=nonzero == expected.get(lens, {}),
                detail=str(nonzero),
            )
        )
    missing = set(expected) - set(grid)
    checks.append(
        CheckResult("every position has a row", passed=not missing, detail=str(sorted(missing)))
    )
    return CommandValidation("signals grid", checks)


def _disk_chart(doc: Doc) -> CommandValidation:
    checks = []
    chart = {row["tool"]: row["parts"] for row in doc["views"]["disk"]}
    for tool in _installed(doc):
        parts = chart.get(tool["name"], {})
        expected = {
            category: _bytes(tool["artifacts"], category) for category in doc["views"]["categories"]
        }
        checks.append(
            CheckResult(
                f"disk chart for {tool['name']}",
                passed=parts == expected and sum(parts.values()) == _bytes(tool["artifacts"]),
                detail=f"{human_size(sum(parts.values()))} charted",
            )
        )
    return CommandValidation("disk chart", checks)


def _checklist(doc: Doc) -> CommandValidation:
    referenced = [x for c in doc["checklist"] for x in c["exposures"]]
    found = [x["id"] for x in _exposures(doc)]
    return CommandValidation(
        "checklist",
        [
            CheckResult(
                "each signal belongs to exactly one check",
                passed=sorted(referenced) == sorted(found),
                detail=f"{len(referenced)} referenced, {len(found)} found",
            ),
            CheckResult(
                "a check has a signal exactly when it lists one",
                passed=all(c["exposed"] == bool(c["exposures"]) for c in doc["checklist"]),
                detail=f"{len(doc['checklist'])} checks",
            ),
            CheckResult(
                "a check marked not checked has no signal and says why",
                passed=all(
                    not c["exposures"] and c["unchecked"].strip()
                    for c in doc["checklist"]
                    if c["unchecked"]
                ),
                detail=f"{sum(1 for c in doc['checklist'] if c['unchecked'])} not checked",
            ),
        ],
    )


def _method(doc: Doc) -> CommandValidation:
    executed = doc["executed"]
    tool_runs = sum(1 for r in executed if r["purpose"] in TOOL_RUNS)
    text = doc["views"]["method"]
    word = "command" if len(executed) == 1 else "commands"
    wanted = [
        f"It ran {len(executed)} {word}",
        f"{len(executed) - tool_runs} from its probe registry and {tool_runs} of installed",
    ]
    return CommandValidation(
        "method summary",
        [
            CheckResult(f"says {w!r}", passed=w in text, detail="counted from the command log")
            for w in wanted
        ],
    )


def _headlines(doc: Doc) -> CommandValidation:
    views = doc["views"]
    pages = [("summary", views["machine"]["headline"], _installed(doc))]
    pages += [
        (f"tool-{t['name']}", views["tools"][t["name"]]["headline"], [t]) for t in _installed(doc)
    ]
    checks = []
    for page, headline, tools in pages:
        for held in _HELD.findall(" ".join(headline)):
            total = _secret_total(tools)
            checks.append(
                CheckResult(
                    f"{page} headline secret count",
                    passed=int(held.replace(",", "")) == total,
                    detail=f"says {held}, recomputed {total}",
                )
            )
    return CommandValidation(
        "headline numbers", checks or [CheckResult("no counts to check", passed=True, detail="")]
    )


# --- keys: rebuilt from the raw credentials --------------------------------------------------


def _key_type(tokens: list[Doc]) -> str:
    """Classify a credential entry with separate rules from tokens.kind_of."""
    names = [t["field"].lower() for t in tokens]
    kinds = [t["kind"] for t in tokens]
    api_kind = any(
        "api_key" in k
        or "admin_key" in k
        or k in {"openai_project_key"}
        or k.startswith("github_pat")
        for k in kinds
    )
    if api_kind or any(n in {"key", "apikey", "api_key"} or n.endswith("_api_key") for n in names):
        return "API key"
    if any(k == "jwt" or "oauth" in k or "refresh" in k for k in kinds):
        return "OAuth login"
    if "password" in names:
        return "Password"
    return "Secret"


def _key_groups(doc: Doc) -> dict[tuple[str, tuple[str, ...]], list[tuple[str, Doc]]]:
    groups: dict[tuple[str, tuple[str, ...]], list[tuple[str, Doc]]] = {}
    for tool in _installed(doc):
        for cred in tool["credentials"]:
            if cred["tokens"]:
                prints = tuple(sorted(t["fingerprint"] for t in cred["tokens"]))
                groups.setdefault((cred["provider"], prints), []).append(
                    (tool["display_name"], cred)
                )
    return groups


def _api_key_count(doc: Doc) -> int:
    return sum(
        1 for held in _key_groups(doc).values() if _key_type(held[0][1]["tokens"]) == "API key"
    )


def _owner_recorded(row: Doc, creds: list[Doc]) -> bool:
    """A row's owner must be a value recorded in its own credentials, at the stated source."""
    if not row["owner"]:
        return not row["owner_source"]
    for cred in creds:
        if cred["owner"] == row["owner"] and cred["owner_source"] == row["owner_source"]:
            return True
        for token in cred["tokens"]:
            for claim, value in token["claims"].items():
                source = f"{token['field']} token claim {claim}"
                if value == row["owner"] and source == row["owner_source"]:
                    return True
    return False


def _shown_ok(row: Doc, tokens: list[Doc]) -> bool:
    if row["kind"] == "OAuth login":
        return row["shown"] == ", ".join(t["field"] for t in tokens)
    token = tokens[0]
    return row["shown"] == token["prefix"] + token["last4"] and len(token["last4"]) in {0, 4}


def _row_problems(row: Doc, held: list[tuple[str, Doc]]) -> list[str]:
    creds = [cred for _name, cred in held]
    want = sorted((n, c["store"], c["location"], c["readable_by_others"]) for n, c in held)
    have = sorted(
        (loc["tool"], loc["store"], loc["location"], loc["readable_by_others"])
        for loc in row["locations"]
    )
    problems = []
    if want != have:
        problems.append("locations")
    if row["kind"] != _key_type(creds[0]["tokens"]):
        problems.append("type")
    if not _owner_recorded(row, creds):
        problems.append("owner")
    if not _shown_ok(row, creds[0]["tokens"]):
        problems.append("key shown")
    if row["used_by"] != list(dict.fromkeys(n for n, _c in held)):
        problems.append("used by")
    return problems


def _keys(doc: Doc) -> CommandValidation:
    groups = _key_groups(doc)
    rows = doc["views"]["keys"]
    listed = [(r["provider"], tuple(r["fingerprints"])) for r in rows]
    bad = []
    for row, key in zip(rows, listed, strict=True):
        problems = _row_problems(row, groups.get(key, []))
        if problems:
            bad.append(f"{row['provider']} {row['kind']}: {', '.join(problems)}")
    return CommandValidation(
        "keys",
        [
            CheckResult(
                "every stored credential is exactly one row, and every row is a stored credential",
                passed=sorted(listed) == sorted(groups) and len(set(listed)) == len(listed),
                detail=f"{len(rows)} rows, {len(groups)} distinct credentials",
            ),
            CheckResult(
                "each row's locations, type, owner, shown key and tools match its credentials",
                passed=not bad,
                detail="; ".join(bad) or f"{len(rows)} rows rebuilt",
            ),
        ],
    )


def check_figures(doc: Doc) -> list[CommandValidation]:
    """Every figure, grid, chart and count in the document, recomputed from its raw data."""
    return [
        _machine(doc),
        *(_tool(doc, tool) for tool in _installed(doc)),
        _matrix(doc),
        _keys(doc),
        _disk_chart(doc),
        _checklist(doc),
        _method(doc),
        _headlines(doc),
    ]
