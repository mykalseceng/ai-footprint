"""Turn a packet capture into the connections each tool made while launched idle.

A packet belongs to a tool when macOS recorded one of the tool's processes as its owner
(``proc``) or as the process it was sent for (``eproc``), during that tool's window. Process
ownership comes from ``tcpdump -r -k`` (packet metadata the kernel attached); everything
else comes from the packets themselves (see ``pcap``). DNS traffic is listed as the names
looked up, not as connections to the resolver. Loopback, link-local and multicast traffic
is counted but not listed: it never leaves the machine.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ai_footprint import pcap
from ai_footprint.model import Connection, ToolCapture

GRACE_SECONDS = 5.0
"""Packets this long after a tool is stopped still count: connections closing down."""
MAX_HELLO_BYTES = 16384
HELPER_NAMES = frozenset({"node", "bun", "npm", "npx", "git", "curl", "uv", "uvx", "python3"})
"""Process names reported as unattributed when they talk during a tool's window but were not
seen in its process tree (a short-lived child the process sampling missed, or unrelated)."""

_LINE = re.compile(r"^(?P<ts>\d+\.\d+)\s+(?:\((?P<meta>[^)]*)\))?")
_PROC = re.compile(r"(?:^|[ ,])proc (?P<name>.+?):(?P<pid>\d+)")
_EPROC = re.compile(r"(?:^|[ ,])eproc (?P<name>.+?):(?P<pid>\d+)")
_DIRECTION = re.compile(r"(?:^|[ ,])(?P<dir>in|out)(?:$|[ ,])")


class AlignmentError(ValueError):
    """tcpdump's metadata lines do not match the packets read from the file."""


@dataclass(frozen=True)
class Meta:
    """Kernel metadata for one packet, as ``tcpdump -k NPD`` prints it."""

    timestamp: float
    pid: int = 0
    name: str = ""
    epid: int = 0
    ename: str = ""
    direction: str = ""


@dataclass
class Window:
    """One tool's launch: when it ran and every process seen in its tree."""

    tool: str
    display_name: str
    version: str
    command: list[str]
    start: float
    end: float
    pids: set[int] = field(default_factory=set)
    switches: list[str] = field(default_factory=list)
    stopped: list[str] = field(default_factory=list)


def parse_metadata(text: str) -> list[Meta]:
    """One ``Meta`` per packet line of ``tcpdump -r FILE -n -tt -q -k NPD`` output."""
    found = []
    for line in text.splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        meta = match.group("meta") or ""
        proc, eproc, direction = _PROC.search(meta), _EPROC.search(meta), _DIRECTION.search(meta)
        found.append(
            Meta(
                float(match.group("ts")),
                int(proc.group("pid")) if proc else 0,
                proc.group("name") if proc else "",
                int(eproc.group("pid")) if eproc else 0,
                eproc.group("name") if eproc else "",
                direction.group("dir") if direction else "",
            )
        )
    return found


def align(raw: list[pcap.RawPacket], meta: list[Meta]) -> list[Meta]:
    """Check that tcpdump printed one line per packet in file order, then return the lines.

    Raises:
        AlignmentError: The counts differ, or a timestamp does not match its packet.
    """
    if len(raw) != len(meta):
        raise AlignmentError(f"{len(raw)} packets in the file, {len(meta)} lines from tcpdump")
    for packet, line in zip(raw, meta, strict=True):
        if packet.timestamp and abs(packet.timestamp - line.timestamp) > 0.001:
            raise AlignmentError(
                f"packet {packet.index} is at {packet.timestamp:.6f}, tcpdump says "
                f"{line.timestamp:.6f}"
            )
    return meta


def is_local(address: str) -> bool:
    """True for traffic that never leaves the machine or the link."""
    ip = ipaddress.ip_address(address)
    return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified


def _remote(packet: pcap.Packet, meta: Meta) -> tuple[str, int]:
    if meta.direction == "in":
        return packet.src, packet.sport
    if meta.direction == "out":
        return packet.dst, packet.dport
    return (
        (packet.dst, packet.dport) if packet.dport <= packet.sport else (packet.src, packet.sport)
    )


@dataclass
class _Flow:
    host: str = ""
    named_by: str = ""
    first: float = 0.0
    packets: int = 0
    size: int = 0
    processes: set[str] = field(default_factory=set)
    hello: bytes = b""


class Names:
    """Hosts named by the capture's own packets: DNS answers seen anywhere in it."""

    def __init__(self, packets: Iterable[pcap.Packet]) -> None:
        self.by_address: dict[str, str] = {}
        for packet in packets:
            if packet.transport == pcap.UDP and packet.sport == 53:
                asked, addresses = pcap.dns_answers(packet.payload)
                for address in addresses:
                    self.by_address.setdefault(address, asked)


def _owner(meta: Meta, pids: set[int]) -> str:
    if meta.pid in pids:
        return f"{meta.name} (pid {meta.pid})"
    if meta.epid in pids:
        return f"{meta.ename} (pid {meta.epid}) via {meta.name}"
    return ""


def _name_flow(flow: _Flow, packet: pcap.Packet, meta: Meta) -> None:
    if flow.named_by or meta.direction == "in" or not packet.payload:
        return
    if packet.transport == pcap.TCP and len(flow.hello) < MAX_HELLO_BYTES:
        flow.hello += packet.payload
        sni = pcap.server_name(flow.hello)
        if sni:
            flow.host, flow.named_by = sni, "TLS server name"
            return
    host = pcap.http_host(packet.payload)
    if host:
        flow.host, flow.named_by = host, "HTTP Host header"


def tool_capture(
    window: Window, packets: list[tuple[pcap.Packet, Meta]], names: Names
) -> ToolCapture:
    """The connections, DNS lookups and local traffic of one tool's window."""
    flows: dict[tuple[str, str, int], _Flow] = {}
    lookups: list[str] = []
    local = 0
    for packet, meta in packets:
        owner = _owner(meta, window.pids)
        if not owner or not window.start <= packet.timestamp <= window.end + GRACE_SECONDS:
            continue
        address, port = _remote(packet, meta)
        if port == 53:
            asked = pcap.dns_question(packet.payload)
            lookups += [asked] if asked and asked not in lookups else []
            continue
        if is_local(address):
            local += 1
            continue
        transport = "tcp" if packet.transport == pcap.TCP else "udp"
        flow = flows.setdefault((transport, address, port), _Flow(first=packet.timestamp))
        flow.packets += 1
        flow.size += packet.length
        flow.processes.add(owner)
        _name_flow(flow, packet, meta)
    return ToolCapture(
        tool=window.tool,
        display_name=window.display_name,
        version=window.version,
        command=window.command,
        seconds=round(window.end - window.start, 1),
        pids=sorted(window.pids),
        connections=[
            _connection(key, flow, names, window.start) for key, flow in sorted(flows.items())
        ],
        lookups=lookups,
        local_packets=local,
        stopped=window.stopped,
        switches=window.switches,
    )


def _connection(key: tuple[str, str, int], flow: _Flow, names: Names, start: float) -> Connection:
    transport, address, port = key
    host, named_by = flow.host, flow.named_by
    if not host and address in names.by_address:
        host, named_by = names.by_address[address], "DNS answer in this capture"
    return Connection(
        host=host or address,
        address=address,
        port=port,
        transport=transport,
        named_by=named_by or "address only",
        processes=sorted(flow.processes),
        first_second=round(flow.first - start, 2),
        packets=flow.packets,
        bytes=flow.size,
    )


def unattributed(
    windows: list[Window], packets: list[tuple[pcap.Packet, Meta]], names: Names
) -> list[Connection]:
    """Connections from helper-named processes outside every tool's tree, during a window."""
    pids = set().union(*(w.pids for w in windows)) if windows else set()
    helpers: list[tuple[pcap.Packet, Meta]] = [
        (p, m) for p, m in packets if m.name in HELPER_NAMES and m.pid not in pids
    ]
    found = []
    for window in windows:
        others = {m.pid for p, m in helpers if window.start <= p.timestamp <= window.end}
        stray = Window("", "", "", [], window.start, window.end, others)
        found += tool_capture(stray, helpers, names).connections
    return found
