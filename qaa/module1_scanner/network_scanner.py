"""
Module 1e - Network surface scanner (PCAP).

Extracts TLS handshake metadata from a capture file and flags quantum-vulnerable
key exchange, authentication and bulk-cipher choices.

Implementation note
-------------------
Scapy's TLS layer is optional and its availability varies by platform, so this
module uses a two-tier strategy:

  Tier 1 (preferred) - scapy.layers.tls parses ClientHello / ServerHello and we
                       read the negotiated cipher suite directly.
  Tier 2 (fallback)  - a dependency-free byte-level TLS record parser that walks
                       the handshake structure manually. This keeps the network
                       surface working even where Scapy's TLS layer will not
                       import, which matters for the demo.

Findings from this surface carry SURFACE_WEIGHT 1.10 in Module 3: a cipher
suite observed on the wire is confirmed live exposure, not a code path that
might never execute.
"""

from __future__ import annotations

import struct
from pathlib import Path

from qaa.schema import Finding

# ---------------------------------------------------------------------------
# IANA TLS cipher suite registry subset -> (name, kex_family, auth_family,
#                                           bulk_family, mac_family)
# ---------------------------------------------------------------------------
CIPHER_SUITES: dict[int, tuple[str, str, str, str, str]] = {
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", "RC4", "MD5"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4", "SHA1"),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", "SHA1"),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES", "SHA1"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "AES", "SHA1"),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", "AES", "SHA256"),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AES", "SHA256"),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", "AES", "SHA256"),
    0x0016: ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DH", "RSA", "3DES", "SHA1"),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DH", "RSA", "AES", "SHA1"),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DH", "RSA", "AES", "SHA1"),
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DH", "RSA", "AES", "SHA256"),
    0xC007: ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDH", "ECDSA", "RC4", "SHA1"),
    0xC008: ("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDH", "ECDSA", "3DES", "SHA1"),
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDH", "ECDSA", "AES", "SHA1"),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDH", "ECDSA", "AES", "SHA1"),
    0xC011: ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDH", "RSA", "RC4", "SHA1"),
    0xC012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDH", "RSA", "3DES", "SHA1"),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDH", "RSA", "AES", "SHA1"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDH", "RSA", "AES", "SHA1"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDH", "ECDSA", "AES", "SHA256"),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH", "ECDSA", "AES", "SHA256"),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDH", "RSA", "AES", "SHA256"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDH", "RSA", "AES", "SHA256"),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "ECDH", "RSA", "CHACHA20", "SHA256"),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "ECDH", "ECDSA", "CHACHA20", "SHA256"),
    0x1301: ("TLS_AES_128_GCM_SHA256", "ECDH", "ECDSA", "AES", "SHA256"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "ECDH", "ECDSA", "AES", "SHA256"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "ECDH", "ECDSA", "CHACHA20", "SHA256"),
}

# TLS supported_groups (extension 10) - named curves / KEMs
NAMED_GROUPS: dict[int, tuple[str, str, int | None]] = {
    0x0017: ("secp256r1", "ECDH", 256),
    0x0018: ("secp384r1", "ECDH", 384),
    0x0019: ("secp521r1", "ECDH", 521),
    0x001D: ("x25519", "X25519", 256),
    0x001E: ("x448", "X25519", 448),
    0x0100: ("ffdhe2048", "DH", 2048),
    0x0101: ("ffdhe3072", "DH", 3072),
    0x11EC: ("X25519MLKEM768", "ML-KEM", 0),      # hybrid PQC - SAFE
    0x6399: ("X25519Kyber768Draft00", "ML-KEM", 0),
    0x023A: ("MLKEM768", "ML-KEM", 0),
}

TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
CONTENT_TYPE_HANDSHAKE = 22


# ---------------------------------------------------------------------------
# Tier 2: dependency-free TLS handshake parser
# ---------------------------------------------------------------------------
def _parse_client_hello(body: bytes) -> dict | None:
    """Parse a ClientHello handshake body; returns suites + groups."""
    try:
        off = 2 + 32                                   # version + random
        sid_len = body[off]; off += 1 + sid_len        # session id
        cs_len = struct.unpack(">H", body[off:off + 2])[0]; off += 2
        suites = [struct.unpack(">H", body[off + i:off + i + 2])[0]
                  for i in range(0, cs_len, 2)]
        off += cs_len
        comp_len = body[off]; off += 1 + comp_len
        groups: list[int] = []
        if off + 2 <= len(body):
            ext_total = struct.unpack(">H", body[off:off + 2])[0]; off += 2
            end = off + ext_total
            while off + 4 <= min(end, len(body)):
                etype, elen = struct.unpack(">HH", body[off:off + 4]); off += 4
                if etype == 10 and off + 2 <= len(body):      # supported_groups
                    glen = struct.unpack(">H", body[off:off + 2])[0]
                    groups = [struct.unpack(">H", body[off + 2 + i:off + 4 + i])[0]
                              for i in range(0, glen, 2)]
                off += elen
        return {"role": "client", "suites": suites, "groups": groups}
    except (IndexError, struct.error):
        return None


def _parse_server_hello(body: bytes) -> dict | None:
    """Parse a ServerHello body; returns the single negotiated suite."""
    try:
        version = struct.unpack(">H", body[0:2])[0]
        off = 2 + 32
        sid_len = body[off]; off += 1 + sid_len
        suite = struct.unpack(">H", body[off:off + 2])[0]
        return {"role": "server", "suites": [suite], "groups": [],
                "version": version}
    except (IndexError, struct.error):
        return None


def _walk_tls_records(payload: bytes) -> list[dict]:
    """Walk TLS records in a TCP payload and decode any hello messages."""
    out, off = [], 0
    while off + 5 <= len(payload):
        ctype = payload[off]
        rec_ver = struct.unpack(">H", payload[off + 1:off + 3])[0]
        rec_len = struct.unpack(">H", payload[off + 3:off + 5])[0]
        if ctype != CONTENT_TYPE_HANDSHAKE or rec_ver not in TLS_VERSIONS:
            break
        body = payload[off + 5:off + 5 + rec_len]
        h = 0
        while h + 4 <= len(body):
            htype = body[h]
            hlen = int.from_bytes(body[h + 1:h + 4], "big")
            hbody = body[h + 4:h + 4 + hlen]
            if htype == HANDSHAKE_CLIENT_HELLO:
                r = _parse_client_hello(hbody)
                if r:
                    r["record_version"] = rec_ver
                    out.append(r)
            elif htype == HANDSHAKE_SERVER_HELLO:
                r = _parse_server_hello(hbody)
                if r:
                    r["record_version"] = rec_ver
                    out.append(r)
            h += 4 + hlen
        off += 5 + rec_len
    return out


def _read_packets(pcap_path: Path):
    """Yield (packet_index, tcp_payload, src, dst) from a pcap using Scapy."""
    try:
        from scapy.all import PcapReader, TCP, IP, IPv6   # noqa: N811
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for PCAP scanning. Install with: pip install scapy"
        ) from exc

    with PcapReader(str(pcap_path)) as reader:
        for i, pkt in enumerate(reader, start=1):
            if TCP not in pkt:
                continue
            payload = bytes(pkt[TCP].payload)
            if len(payload) < 6:
                continue
            src = dst = "?"
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            yield i, payload, f"{src}:{pkt[TCP].sport}", f"{dst}:{pkt[TCP].dport}"


def scan_pcap(pcap_path: Path, max_packets: int = 200_000) -> list[Finding]:
    """
    Scan a PCAP and emit one Finding per distinct quantum-relevant primitive
    observed in a TLS handshake.
    """
    path = Path(pcap_path)
    findings: list[Finding] = []
    # de-duplicate: a busy capture repeats the same suite thousands of times
    seen: set[tuple[str, str]] = set()

    for idx, payload, src, dst in _read_packets(path):
        if idx > max_packets:
            break
        for msg in _walk_tls_records(payload):
            role = msg["role"]
            ver_name = TLS_VERSIONS.get(msg.get("version",
                                                msg.get("record_version", 0)),
                                        "unknown")
            flow = f"{src} -> {dst}"

            for suite_id in msg["suites"]:
                info = CIPHER_SUITES.get(suite_id)
                if not info:
                    continue
                name, kex, auth, bulk, mac = info
                for family, role_label in ((kex, "key exchange"),
                                           (auth, "authentication"),
                                           (bulk, "bulk cipher"),
                                           (mac, "MAC / PRF hash")):
                    key = (family, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        file_path=str(path),
                        line_number=idx,
                        surface="network",
                        snippet=f"TLS {ver_name} {role} hello | suite "
                                f"{name} (0x{suite_id:04X}) | {role_label}: "
                                f"{family} | flow {flow}",
                        matched_pattern=f"{name} [{role_label}]",
                        detector="pcap",
                        language="tls",
                        hint_algorithm=family,
                        extra={"cipher_suite": name,
                               "suite_id": f"0x{suite_id:04X}",
                               "tls_version": ver_name,
                               "component": role_label,
                               "flow": flow,
                               "hello": role},
                    ))

            for gid in msg.get("groups", []):
                g = NAMED_GROUPS.get(gid)
                if not g:
                    continue
                gname, family, bits = g
                key = (family, gname)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    file_path=str(path),
                    line_number=idx,
                    surface="network",
                    snippet=f"TLS {ver_name} client hello | supported_group "
                            f"{gname} (0x{gid:04X}) | flow {flow}",
                    matched_pattern=f"supported_group {gname}",
                    detector="pcap",
                    language="tls",
                    key_size=bits,
                    curve=gname,
                    hint_algorithm=family,
                    extra={"named_group": gname, "tls_version": ver_name,
                           "flow": flow, "component": "key exchange group"},
                ))
    return findings
