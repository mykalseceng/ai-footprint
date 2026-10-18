"""Read packets from a pcapng file and name the hosts they reach, from the packets alone.

The capture file is read directly, so nothing here needs root. A host is named only by
something a packet carried: the TLS server name in a ClientHello, the Host header of a
plain HTTP request, or a DNS answer seen in the same capture. Anything else stays an
address.
"""

import ipaddress
import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

SHB = 0x0A0D0D0A
IDB = 1
SPB = 3
EPB = 6
LEGACY_PB = 2

ETHERNET = 1
NULL = 0
LOOP = 108
RAW = (12, 14, 101)
RAW_IPV4 = 228
RAW_IPV6 = 229
PKTAP = 258

TCP = 6
UDP = 17

_HTTP_HOST = re.compile(rb"\r\nHost:\s*([A-Za-z0-9.\-]+)", re.IGNORECASE)
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")


@dataclass(frozen=True)
class RawPacket:
    """One captured frame: its position in the file, time and link-layer bytes."""

    index: int
    timestamp: float
    linktype: int
    data: bytes


@dataclass(frozen=True)
class Packet:
    """An IPv4 or IPv6 packet carrying TCP or UDP."""

    index: int
    timestamp: float
    src: str
    dst: str
    transport: int
    sport: int
    dport: int
    payload: bytes
    length: int


class PcapError(ValueError):
    """The file is not a pcapng capture this reader understands."""


def _blocks(data: bytes) -> Iterator[tuple[int, bytes, str]]:
    """(block type, body, byte order) for every block, following each section's byte order."""
    offset, order = 0, "<"
    while offset + 12 <= len(data):
        if struct.unpack_from("<I", data, offset)[0] == SHB:
            magic = data[offset + 8 : offset + 12]
            order = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
        kind, total = struct.unpack_from(f"{order}II", data, offset)
        if total < 12 or offset + total > len(data):
            raise PcapError(f"truncated block at byte {offset}")
        yield kind, data[offset + 8 : offset + total - 4], order
        offset += total


def read_packets(path: Path) -> list[RawPacket]:
    """Every packet in a pcapng file, in file order.

    Raises:
        PcapError: The file does not start with a pcapng section header.
    """
    data = path.read_bytes()
    if len(data) < 12 or struct.unpack_from("<I", data, 0)[0] != SHB:
        raise PcapError(f"{path} is not a pcapng file")
    links: list[tuple[int, float]] = []
    packets: list[RawPacket] = []
    for kind, body, order in _blocks(data):
        if kind == SHB:
            links = []
        elif kind == IDB:
            links.append((struct.unpack_from(f"{order}H", body, 0)[0], _resolution(body, order)))
        elif kind in (EPB, LEGACY_PB) and links:
            packets.append(_enhanced(len(packets), body, order, links))
        elif kind == SPB and links:
            length = struct.unpack_from(f"{order}I", body, 0)[0]
            packets.append(RawPacket(len(packets), 0.0, links[0][0], body[4 : 4 + length]))
    return packets


def _resolution(idb: bytes, order: str) -> float:
    """Seconds per timestamp unit from the if_tsresol option (default microseconds)."""
    offset = 8
    while offset + 4 <= len(idb):
        code, length = struct.unpack_from(f"{order}HH", idb, offset)
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = idb[offset + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0**-value
        offset += 4 + (length + 3) // 4 * 4
    return 1e-6


def _enhanced(index: int, body: bytes, order: str, links: list[tuple[int, float]]) -> RawPacket:
    if len(body) < 20:
        raise PcapError(f"packet {index} is too short")
    interface, high, low, captured = struct.unpack_from(f"{order}IIII", body, 0)
    linktype, unit = links[interface] if interface < len(links) else links[0]
    return RawPacket(index, ((high << 32) | low) * unit, linktype, body[20 : 20 + captured])


def _network_layer(linktype: int, data: bytes) -> bytes | None:
    """The IP packet inside a frame, or None for other protocols."""
    if linktype == PKTAP and len(data) >= 8:
        header, inner = struct.unpack_from("<II", data, 0)
        return _network_layer(inner, data[header:])
    if linktype == ETHERNET and len(data) >= 14:
        offset, ethertype = 12, int.from_bytes(data[12:14], "big")
        while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 6:
            offset += 4
            ethertype = int.from_bytes(data[offset : offset + 2], "big")
        return data[offset + 2 :] if ethertype in (0x0800, 0x86DD) else None
    if linktype in (NULL, LOOP) and len(data) >= 4:
        return data[4:]
    if linktype in (*RAW, RAW_IPV4, RAW_IPV6):
        return data
    return None


def decode(raw: RawPacket) -> Packet | None:
    """The TCP or UDP packet in a frame, or None when it carries something else."""
    ip = _network_layer(raw.linktype, raw.data)
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        header = (ip[0] & 0x0F) * 4
        proto, src, dst = ip[9], ip[12:16], ip[16:20]
        length = int.from_bytes(ip[2:4], "big")
    elif version == 6 and len(ip) >= 40:
        header, proto, src, dst = 40, ip[6], ip[8:24], ip[24:40]
        length = 40 + int.from_bytes(ip[4:6], "big")
    else:
        return None
    return _transport(raw, ip[header:], proto, (src, dst), length)


def _transport(
    raw: RawPacket, segment: bytes, proto: int, addresses: tuple[bytes, bytes], length: int
) -> Packet | None:
    if proto == TCP and len(segment) >= 20:
        payload = segment[(segment[12] >> 4) * 4 :]
    elif proto == UDP and len(segment) >= 8:
        payload = segment[8:]
    else:
        return None
    sport, dport = struct.unpack_from(">HH", segment, 0)
    src, dst = (str(ipaddress.ip_address(a)) for a in addresses)
    return Packet(raw.index, raw.timestamp, src, dst, proto, sport, dport, payload, length)


def _dns_name(message: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """A possibly compressed DNS name and the offset just after it."""
    labels = []
    while offset < len(message) and depth < 16:
        size = message[offset]
        if size == 0:
            return ".".join(labels), offset + 1
        if size & 0xC0 == 0xC0:
            pointer = int.from_bytes(message[offset : offset + 2], "big") & 0x3FFF
            rest, _end = _dns_name(message, pointer, depth + 1)
            return ".".join([*labels, rest] if rest else labels), offset + 2
        labels.append(message[offset + 1 : offset + 1 + size].decode("ascii", "replace"))
        offset += 1 + size
    return ".".join(labels), offset


def dns_answers(message: bytes) -> tuple[str, list[str]]:
    """(name asked for, addresses answered) from one DNS response; empty when not one."""
    if len(message) < 12 or not message[2] & 0x80:
        return "", []
    questions, answers = struct.unpack_from(">HH", message, 4)
    if questions < 1:
        return "", []
    asked, offset = _dns_name(message, 12)
    offset += 4
    for _ in range(questions - 1):
        offset = _dns_name(message, offset)[1] + 4
    found = []
    for _ in range(answers):
        offset = _dns_name(message, offset)[1]
        if offset + 10 > len(message):
            break
        kind, _cls, _ttl, size = struct.unpack_from(">HHIH", message, offset)
        data = message[offset + 10 : offset + 10 + size]
        if (kind, size) in ((1, 4), (28, 16)):
            found.append(str(ipaddress.ip_address(data)))
        offset += 10 + size
    return asked, found


def dns_question(message: bytes) -> str:
    """The name a DNS query asks for, or empty when the message is not a query."""
    if len(message) < 12 or message[2] & 0x80:
        return ""
    return _dns_name(message, 12)[0] if struct.unpack_from(">H", message, 4)[0] else ""


def server_name(hello: bytes) -> str:
    """The SNI host in a TLS ClientHello record, or empty when absent or incomplete."""
    if len(hello) < 43 or hello[0] != 0x16 or hello[5] != 0x01:
        return ""
    offset = 43
    offset += 1 + hello[offset] if offset < len(hello) else 0
    if offset + 2 > len(hello):
        return ""
    offset += 2 + int.from_bytes(hello[offset : offset + 2], "big")
    offset += 1 + hello[offset] if offset < len(hello) else 0
    if offset + 2 > len(hello):
        return ""
    end = offset + 2 + int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2
    while offset + 4 <= min(end, len(hello)):
        kind, size = struct.unpack_from(">HH", hello, offset)
        if kind == 0 and offset + 9 <= len(hello):
            length = int.from_bytes(hello[offset + 7 : offset + 9], "big")
            return hello[offset + 9 : offset + 9 + length].decode("ascii", "replace")
        offset += 4 + size
    return ""


def http_host(payload: bytes) -> str:
    """The Host header of a plain HTTP request, or empty."""
    if not payload.startswith(_HTTP_METHODS):
        return ""
    match = _HTTP_HOST.search(payload[:4096])
    return match.group(1).decode("ascii") if match else ""
