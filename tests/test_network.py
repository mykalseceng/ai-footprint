"""Packet capture parsing and attribution, from synthetic pcapng files built here."""

import ipaddress
import struct
from pathlib import Path

import pytest

from ai_footprint import network, pcap

LOCAL, REMOTE, RESOLVER = "192.168.1.5", "104.18.32.47", "192.168.1.1"


def block(kind: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack("<II", kind, total) + body + struct.pack("<I", total)


def pcapng(frames: list[tuple[float, bytes]], linktype: int = pcap.ETHERNET) -> bytes:
    shb = block(pcap.SHB, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(pcap.IDB, struct.pack("<HHI", linktype, 0, 65535))
    out = shb + idb
    for when, frame in frames:
        micros = round(when * 1e6)
        header = struct.pack("<IIIII", 0, micros >> 32, micros & 0xFFFFFFFF, len(frame), len(frame))
        out += block(pcap.EPB, header + frame)
    return out


def ipv4(src: str, dst: str, proto: int, segment: bytes) -> bytes:
    header = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(segment), 0, 0, 64, proto, 0)
    return header + ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + segment


def ether(ip: bytes) -> bytes:
    return b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00" + ip


def tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 0, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def client_hello(host: str) -> bytes:
    name = host.encode()
    sni = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack(">HH", 0x002B, 3) + b"\x02\x03\x04"
    extensions += struct.pack(">HH", 0, len(sni)) + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(name: str) -> bytes:
    return struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + dns_name(name) + b"\x00\x01\x00\x01"


def dns_response(name: str, address: str) -> bytes:
    header = struct.pack(">HHHHHH", 7, 0x8180, 1, 1, 0, 0)
    question = dns_name(name) + b"\x00\x01\x00\x01"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ipaddress.ip_address(address).packed
    return header + question + answer


def meta_line(when: float, proc: str, pid: int, direction: str, eproc: str = "") -> str:
    extra = f", eproc {eproc}" if eproc else ""
    return f"{when:.6f} (en0, proc {proc}:{pid}{extra}, svc BE, {direction}) IP x > y: tcp 0"


def test_server_name_reads_sni_and_rejects_partial_records():
    hello = client_hello("models.dev")
    assert pcap.server_name(hello) == "models.dev"
    assert pcap.server_name(hello[:40]) == ""
    assert pcap.server_name(b"\x17" + hello[1:]) == ""


def test_dns_answers_follow_compression_and_ignore_queries():
    assert pcap.dns_answers(dns_response("opencode.ai", REMOTE)) == ("opencode.ai", [REMOTE])
    assert pcap.dns_answers(dns_query("opencode.ai")) == ("", [])
    assert pcap.dns_question(dns_query("opencode.ai")) == "opencode.ai"
    assert pcap.dns_question(dns_response("opencode.ai", REMOTE)) == ""


def test_http_host_only_from_requests():
    assert pcap.http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") == "example.com"
    assert pcap.http_host(b"HTTP/1.1 200 OK\r\nHost: example.com\r\n") == ""


def test_read_packets_decodes_ethernet_and_loopback_frames(tmp_path: Path):
    frame = ether(ipv4(LOCAL, REMOTE, pcap.TCP, tcp(50000, 443, b"x")))
    path = tmp_path / "c.pcapng"
    path.write_bytes(pcapng([(1000.5, frame)]))
    [raw] = pcap.read_packets(path)
    assert raw.timestamp == pytest.approx(1000.5)
    packet = pcap.decode(raw)
    assert packet is not None
    assert (packet.src, packet.dst, packet.dport, packet.payload) == (LOCAL, REMOTE, 443, b"x")
    loop = struct.pack("<I", 30) + struct.pack(">IHBB", 0x60000000, 20, 6, 64)
    loop += ipaddress.ip_address("::1").packed * 2 + tcp(1, 2)
    path.write_bytes(pcapng([(1.0, loop)], linktype=pcap.NULL))
    decoded = pcap.decode(pcap.read_packets(path)[0])
    assert decoded is not None and decoded.src == "::1"


def test_read_packets_rejects_files_that_are_not_pcapng(tmp_path: Path):
    path = tmp_path / "x.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    with pytest.raises(pcap.PcapError):
        pcap.read_packets(path)


def frame(src: str, dst: str, segment: bytes, proto: int = pcap.TCP) -> bytes:
    return ether(ipv4(src, dst, proto, segment))


def capture(tmp_path: Path) -> tuple[list[pcap.RawPacket], list[network.Meta]]:
    hello = client_hello("models.dev")
    answer = dns_response("api.x.ai", "9.9.9.9")
    frames = [
        (10.0, frame(RESOLVER, LOCAL, udp(53, 6000, answer), pcap.UDP)),
        (10.1, frame(LOCAL, RESOLVER, udp(6001, 53, dns_query("models.dev")), pcap.UDP)),
        (10.2, frame(LOCAL, REMOTE, tcp(50000, 443, hello[:30]))),
        (10.3, frame(LOCAL, REMOTE, tcp(50000, 443, hello[30:]))),
        (10.4, frame(REMOTE, LOCAL, tcp(443, 50000, b"\x16" * 40))),
        (10.5, frame(LOCAL, "9.9.9.9", tcp(50001, 443, b"\x17\x03\x03"))),
        (10.6, frame(LOCAL, "127.0.0.1", tcp(50002, 4096))),
        (10.7, frame(LOCAL, "1.1.1.1", tcp(50003, 443))),
        (99.0, frame(LOCAL, "8.8.4.4", tcp(50004, 443))),
    ]
    path = tmp_path / "c.pcapng"
    path.write_bytes(pcapng(frames))
    lines = [
        meta_line(10.0, "mDNSResponder", 90, "in"),
        meta_line(10.1, "mDNSResponder", 90, "out", eproc="opencode:42"),
        meta_line(10.2, "opencode", 42, "out"),
        meta_line(10.3, "opencode", 42, "out"),
        meta_line(10.4, "opencode", 42, "in"),
        meta_line(10.5, "bun", 43, "out"),
        meta_line(10.6, "opencode", 42, "out"),
        meta_line(10.7, "Google Chrome", 7, "out"),
        meta_line(99.0, "opencode", 42, "out"),
    ]
    raw = pcap.read_packets(path)
    return raw, network.align(raw, network.parse_metadata("\n".join(lines)))


def test_tool_capture_names_hosts_and_keeps_only_the_tools_traffic(tmp_path: Path):
    raw, meta = capture(tmp_path)
    decoded = [(pcap.decode(r), m) for r, m in zip(raw, meta, strict=True)]
    packets = [(p, m) for p, m in decoded if p is not None]
    names = network.Names(p for p, _m in packets)
    window = network.Window("opencode", "OpenCode", "2.0.26", ["opencode"], 10.0, 20.0, {42, 43})
    found = network.tool_capture(window, packets, names)
    assert [(c.host, c.port, c.named_by, c.packets) for c in found.connections] == [
        ("models.dev", 443, "TLS server name", 3),
        ("api.x.ai", 443, "DNS answer in this capture", 1),
    ]
    assert found.connections[0].first_second == pytest.approx(0.2)
    assert found.connections[1].processes == ["bun (pid 43)"]
    assert found.lookups == ["models.dev"]
    assert found.local_packets == 1


def test_helper_processes_outside_the_tree_are_listed_apart(tmp_path: Path):
    raw, meta = capture(tmp_path)
    packets = [(p, m) for r, m in zip(raw, meta, strict=True) if (p := pcap.decode(r))]
    window = network.Window("opencode", "OpenCode", "2.0.26", ["opencode"], 10.0, 20.0, {42})
    [stray] = network.unattributed([window], packets, network.Names(p for p, _m in packets))
    assert (stray.host, stray.processes) == ("api.x.ai", ["bun (pid 43)"])


def test_alignment_fails_when_tcpdump_and_the_file_disagree(tmp_path: Path):
    raw, meta = capture(tmp_path)
    with pytest.raises(network.AlignmentError):
        network.align(raw, meta[:-1])
    shifted = [network.Meta(m.timestamp + 1, m.pid, m.name) for m in meta]
    with pytest.raises(network.AlignmentError):
        network.align(raw, shifted)


def test_metadata_parses_real_tcpdump_lines_including_names_with_parentheses():
    lines = [
        "1792283228.629746 (proc Ollama:1530, out) IP 192.168.0.251.56546 > 185.1.1.1.443: tcp 0",
        "1792283229.692110 (proc Codex (Service):64603, eproc Codex (Service):64603, in) IP "
        "172.253.117.188.5228 > 192.168.0.251.58271: tcp 0",
        "1792283228.986430 (in) IP 192.168.0.82.3000 > 255.255.255.255.2000: UDP, length 4 (x)",
        "  continuation line without a timestamp",
    ]
    meta = network.parse_metadata("\n".join(lines))
    assert meta == [
        network.Meta(1792283228.629746, 1530, "Ollama", 0, "", "out"),
        network.Meta(1792283229.69211, 64603, "Codex (Service)", 64603, "Codex (Service)", "in"),
        network.Meta(1792283228.98643, 0, "", 0, "", "in"),
    ]
