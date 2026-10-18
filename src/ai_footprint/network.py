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

_LINE = re.compile(r"^(?P<ts>\d+\.\d+)\s+(?:\((?P<meta>.*?\b(?:in|out))\))?")
"""A packet line; the metadata ends at its direction, since process names hold parentheses."""
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


FlowKey = tuple[int, tuple[str, int], tuple[str, int]]
"""Transport and both endpoints, in a fixed order, so both directions share one key."""

NAMED_BY_RANK = (
    "TLS server name",
    "HTTP Host header",
    "DNS answer in this capture",
    "DNS answers in this capture (several names share this address)",
    "address only",
)


def flow_key(packet: pcap.Packet) -> FlowKey:
    """The connection a packet belongs to, the same in both directions."""
    ends = sorted([(packet.src, packet.sport), (packet.dst, packet.dport)])
    return (packet.transport, ends[0], ends[1])


class Names:
    """Hosts named by the capture's own packets.

    Every packet counts here, owned or not: the first packets of a connection often carry no
    process metadata, yet hold its TLS server name.
    """

    def __init__(self, packets: Iterable[pcap.Packet]) -> None:
        self.by_address: dict[str, list[str]] = {}
        self.by_flow: dict[FlowKey, tuple[str, str]] = {}
        self._hellos: dict[tuple[FlowKey, str, int], bytes] = {}
        for packet in packets:
            if packet.transport == pcap.UDP and packet.sport == 53:
                asked, addresses = pcap.dns_answers(packet.payload)
                for address in addresses:
                    known = self.by_address.setdefault(address, [])
                    known += [asked] if asked not in known else []
            elif packet.payload:
                self._name(packet)

    def _name(self, packet: pcap.Packet) -> None:
        key = flow_key(packet)
        if key in self.by_flow:
            return
        host = pcap.http_host(packet.payload)
        if host:
            self.by_flow[key] = (host, "HTTP Host header")
            return
        side = (key, packet.src, packet.sport)
        data = self._hellos.get(side, b"") + packet.payload
        if packet.transport != pcap.TCP or data[:1] != b"\x16" or len(data) > MAX_HELLO_BYTES:
            return
        sni = pcap.server_name(data)
        if sni:
            self.by_flow[key] = (sni, "TLS server name")
            self._hellos.pop(side, None)
        else:
            self._hellos[side] = data

    def name(self, key: FlowKey, address: str) -> tuple[str, str]:
        """(host, which packets named it) for one connection."""
        if key in self.by_flow:
            return self.by_flow[key]
        found = self.by_address.get(address, [])
        if len(found) == 1:
            return found[0], NAMED_BY_RANK[2]
        if found:
            return " or ".join(found), NAMED_BY_RANK[3]
        return address, NAMED_BY_RANK[4]


@dataclass
class _Flow:
    address: str
    port: int
    transport: str
    first: float
    packets: int = 0
    size: int = 0
    processes: set[str] = field(default_factory=set)


def _owner(meta: Meta, pids: set[int]) -> str:
    """The tool's own process behind a packet, whether it sent it or the kernel did for it."""
    if meta.pid in pids:
        return f"{meta.name} (pid {meta.pid})"
    if meta.epid in pids:
        return f"{meta.ename} (pid {meta.epid})"
    return ""


def _in_window(window: Window, packet: pcap.Packet) -> bool:
    return window.start <= packet.timestamp <= window.end + GRACE_SECONDS


def _owned(window: Window, packets: list[tuple[pcap.Packet, Meta]]) -> dict[FlowKey, _Flow]:
    """Every connection one of the tool's processes owned a packet of, during its window."""
    flows: dict[FlowKey, _Flow] = {}
    for packet, meta in packets:
        owner = _owner(meta, window.pids)
        if not owner or not _in_window(window, packet):
            continue
        key = flow_key(packet)
        if key not in flows:
            address, port = _remote(packet, meta)
            transport = "tcp" if packet.transport == pcap.TCP else "udp"
            flows[key] = _Flow(address, port, transport, packet.timestamp)
        flows[key].processes.add(owner)
    return flows


def tool_capture(
    window: Window, packets: list[tuple[pcap.Packet, Meta]], names: Names
) -> ToolCapture:
    """The connections, DNS lookups and local traffic of one tool's window.

    A connection belongs to the tool when any of its packets does; then every packet of it
    in the window is counted, including those the kernel recorded no process for.
    """
    flows = _owned(window, packets)
    lookups: list[str] = []
    for packet, _meta in packets:
        flow = flows.get(flow_key(packet))
        if flow is None or not _in_window(window, packet):
            continue
        flow.packets += 1
        flow.size += packet.length
        flow.first = min(flow.first, packet.timestamp)
        asked = pcap.dns_question(packet.payload) if flow.port == 53 else ""
        lookups += [asked] if asked and asked not in lookups else []
    remote = {k: f for k, f in flows.items() if f.port != 53 and not is_local(f.address)}
    local = sum(f.packets for f in flows.values() if f.port != 53 and is_local(f.address))
    return ToolCapture(
        tool=window.tool,
        display_name=window.display_name,
        version=window.version,
        command=window.command,
        seconds=round(window.end - window.start, 1),
        pids=sorted(window.pids),
        connections=_by_host(remote, names, window.start),
        lookups=lookups,
        local_packets=local,
        stopped=window.stopped,
        switches=window.switches,
    )


def _by_host(flows: dict[FlowKey, _Flow], names: Names, start: float) -> list[Connection]:
    """One row per host, transport and port, adding up its connections."""
    rows: dict[tuple[str, str, int], Connection] = {}
    for key, flow in sorted(flows.items(), key=lambda item: item[1].first):
        host, named_by = names.name(key, flow.address)
        row = rows.get((host, flow.transport, flow.port))
        if row is None:
            rows[(host, flow.transport, flow.port)] = Connection(
                host=host,
                address=flow.address,
                port=flow.port,
                transport=flow.transport,
                named_by=named_by,
                processes=sorted(flow.processes),
                first_second=round(flow.first - start, 2),
                packets=flow.packets,
                bytes=flow.size,
            )
            continue
        addresses = row.address.split(", ")
        row.address = ", ".join(addresses + [flow.address] * (flow.address not in addresses))
        row.named_by = min(row.named_by, named_by, key=NAMED_BY_RANK.index)
        row.processes = sorted(set(row.processes) | flow.processes)
        row.packets += flow.packets
        row.bytes += flow.size
    return list(rows.values())


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
