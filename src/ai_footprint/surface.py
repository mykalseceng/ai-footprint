"""Write the attack-surface narrative from collected facts.

The narrative answers one question per attacker position (``Lens``) in plain sentences built
from counts, names and paths the audit observed. Nothing is rated: the reader sees what an
attacker in each position gets and decides what matters.
"""

import re
from dataclasses import dataclass, field

from ai_footprint.fsinfo import human_size, tilde
from ai_footprint.model import AuditReport, Category, Credential, Exposure, Lens, ToolReport


@dataclass
class Point:
    """One sentence in a lens, linked to the exposure (if any) it came from."""

    text: str
    tool: str
    exposure_id: str = ""


@dataclass
class LensView:
    """Everything an attacker in one position gets."""

    lens: Lens
    points: list[Point] = field(default_factory=list)


@dataclass
class Narrative:
    """A short headline paragraph plus the four lenses."""

    headline: list[str]
    lenses: list[LensView]


def join(items: list[str]) -> str:
    """English list: "a", "a and b", "a, b and c"."""
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + f" and {items[-1]}"


_ISO = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2})?(?:\.\d+)?(?:\+00:00|Z| UTC)?")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`~/])")


def when(text: str) -> str:
    """Rewrite ISO timestamps in ``text`` as ``YYYY-MM-DD HH:MM UTC`` so dates read one way."""
    return _ISO.sub(r"\1 \2 UTC", text)


def sentences(text: str) -> list[str]:
    """Split prose into sentences at a terminator followed by a capital, backtick or path."""
    return [part for part in _SENTENCE.split(text.strip()) if part]


def short_path(path: str, home: str) -> str:
    """Path with ``~`` for home and a long last segment (a hash) cut to 12 characters."""
    shown = tilde(path, home)
    head, _, name = shown.rpartition("/")
    return f"{head}/{name[:12]}…" if len(name) > 16 else shown


def plural(count: int, word: str) -> str:
    """``3 credentials`` / ``1 credential``."""
    return f"{count} {word}{'' if count == 1 else 's'}"


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def is_local_secret(cred: Credential) -> bool:
    """A password for a local service rather than a provider account."""
    return "local server" in cred.provider


def merged_credentials(tools: list[ToolReport]) -> list[tuple[ToolReport, list[Credential]]]:
    """Group each tool's credentials by provider so a key stored twice is told once."""
    out = []
    for tool in tools:
        by_provider: dict[str, list[Credential]] = {}
        for cred in tool.credentials:
            if cred.tokens:
                by_provider.setdefault(cred.provider, []).append(cred)
        out.extend((tool, group) for group in by_provider.values())
    return out


def _is_api_key(creds: list[Credential]) -> bool:
    return all(
        t.field in {"key", "OPENAI_API_KEY"} or t.kind.endswith("api_key")
        for c in creds
        for t in c.tokens
    )


def lifetime(creds: list[Credential]) -> str:
    """How long a copied credential keeps working, from recorded expiry fields."""
    tokens = [t for c in creds for t in c.tokens]
    access = next((t for t in tokens if t.field.lower().startswith("access")), None)
    refresh = next((t for t in tokens if "refresh" in t.field.lower()), None)
    parts = []
    if access and access.expires_at:
        when = access.expires_at[:16].replace("T", " ") + " UTC"
        parts.append(f"the access token {'expired' if access.expired else 'works until'} {when}")
    if refresh:
        parts.append(
            f"the refresh token mints new ones until {refresh.expires_at[:10]}"
            if refresh.expires_at
            else "the refresh token has no recorded expiry"
        )
    return "; ".join(parts) or "no recorded expiry"


def _stores(creds: list[Credential]) -> str:
    return join(sorted({c.store for c in creds}))


def _oauth_point(tool: ToolReport, creds: list[Credential]) -> Point:
    scopes = sorted({scope for c in creds for t in c.tokens for scope in t.scopes})
    plan = next(
        (
            value
            for c in creds
            for t in c.tokens
            for key, value in t.claims.items()
            if key.endswith("chatgpt_plan_type")
        ),
        "",
    )
    facts = [f"scopes {', '.join(scopes)}" if scopes else "no scopes recorded"]
    if plan:
        facts.append(f"ChatGPT plan {plan}")
    text = f"{creds[0].provider} login ({_stores(creds)}): {'; '.join(facts)}. "
    return Point(text + f"{_sentence(lifetime(creds))}.", tool.display_name)


def _remote_points(tools: list[ToolReport]) -> list[Point]:
    points = []
    for tool in tools:
        groups = [creds for t, creds in merged_credentials([tool]) if t is tool]
        keys = [g for g in groups if _is_api_key(g) and not is_local_secret(g[0])]
        for creds in groups:
            if creds in keys:
                continue
            if is_local_secret(creds[0]):
                points.append(
                    Point(f"{creds[0].provider} password ({_stores(creds)}).", tool.display_name)
                )
            else:
                points.append(_oauth_point(tool, creds))
        if keys:
            names = join(sorted(g[0].provider for g in keys))
            stores = join(sorted({c.store for g in keys for c in g}))
            points.append(
                Point(f"API keys for {names} ({stores}): no recorded expiry.", tool.display_name)
            )
    return points


def _points(exposures: list[Exposure], lens: Lens, names: dict[str, str]) -> list[Point]:
    return [
        Point(x.statement, names.get(x.tool, "Host"), x.id) for x in exposures if x.lens is lens
    ]


def _lenses(tools: list[ToolReport], exposures: list[Exposure]) -> list[LensView]:
    names = {t.name: t.display_name for t in tools}
    views = []
    for lens in Lens:
        points = _remote_points(tools) if lens is Lens.REMOTE else []
        points += _points(exposures, lens, names)
        views.append(LensView(lens, points))
    return views


def _takeable(creds: list[Credential]) -> bool:
    return any(
        "plaintext" in c.store or "SQLite" in c.store or "without a prompt" in c.protection
        for c in creds
    )


def _inventory(tools: list[ToolReport], accounts: list[list[Credential]]) -> str:
    named = join(
        [f"{t.display_name} {t.binaries[0].version if t.binaries else ''}".strip() for t in tools]
    )
    providers = sorted({g[0].provider for g in accounts})
    size = sum(a.size_bytes for t in tools for a in t.artifacts if a.category is Category.SESSION)
    holding = (
        f"{plural(len(accounts), 'credential')} for {join(providers)}"
        if accounts
        else "no credentials"
    )
    verb = "holds" if len(tools) == 1 else "hold"
    return f"{named} {verb} {holding} and {human_size(size)} of conversations, prompts and logs."


def _headline(tools: list[ToolReport], exposures: list[Exposure], audit: AuditReport) -> list[str]:
    if not tools:
        return ["No supported AI coding tools were found on this machine."]
    accounts = [g for _t, g in merged_credentials(tools) if not is_local_secret(g[0])]
    sentences = [_inventory(tools, accounts)]
    takeable = [g for g in accounts if _takeable(g)]
    secrets = sum(k.unique for t in tools if t.secret_scan for k in t.secret_scan.kinds)
    if takeable:
        share = "all of them" if len(takeable) == len(accounts) else f"{len(takeable)} of them"
        counted = "distinct secrets" if len(tools) == 1 else "secret values (distinct per tool)"
        history = f", plus history holding {secrets} {counted}" if secrets else ""
        sentences.append(f"Anything that runs as you can take {share} without a prompt{history}.")
    inherited = [f for f in audit.host.facts if f.topic == "reach" and f.concern]
    if inherited and len(tools) > 1:
        names = join([f.name for f in inherited[:3]])
        sentences.append(
            f"The same goes for {plural(len(inherited), 'other credential')} on this machine, "
            f"including {names}."
        )
    unattended = [
        t.display_name for t in tools if any(x.id == f"{t.name}:no-approval" for x in exposures)
    ]
    if unattended:
        verb = "runs" if len(unattended) == 1 else "run"
        sentences.append(
            f"{join(unattended)} {verb} commands without asking, so a web page, repo file or tool "
            "result that steers the model becomes code running on this machine."
        )
    if audit.host.other_users and any(x.lens is Lens.ACCOUNT for x in exposures):
        sentences.append(
            f"{join(audit.host.other_users)}, another account on this machine, can "
            "already read or plant part of this."
        )
    copies = sorted({x.label[:1].lower() + x.label[1:] for x in exposures if x.lens is Lens.COPIES})
    if copies:
        sentences.append(f"Copies also live outside your control: {join(copies)}.")
    unexpiring = [g for g in accounts if "no recorded expiry" in lifetime(g)]
    if unexpiring:
        sentences.append(
            f"{len(unexpiring)} of these credentials "
            f"{'has' if len(unexpiring) == 1 else 'have'} no recorded expiry."
        )
    return sentences


def for_machine(audit: AuditReport) -> Narrative:
    """Narrative across every installed tool and the host."""
    tools = [t for t in audit.tools if t.installed]
    exposures = audit.all_exposures()
    return Narrative(_headline(tools, exposures, audit), _lenses(tools, exposures))


def for_tool(audit: AuditReport, tool: ToolReport) -> Narrative:
    """Narrative for one tool."""
    return Narrative(
        _headline([tool], tool.exposures, audit), _lenses([tool], list(tool.exposures))
    )
