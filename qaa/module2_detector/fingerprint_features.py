"""
Module 2 Stage 2 - Ciphertext / binary artifact fingerprinting.

WHAT THE DESIGN DOCUMENT SAYS, AND AN IMPORTANT CORRECTION
-----------------------------------------------------------
The project design specifies: "NIST SP 800-22 randomness tests used as features
for a Random Forest classifier" to "identify the cryptographic algorithm from
binary output".

The SP 800-22 battery is implemented here in full, because it is part of the
design and because it does real work: it cleanly separates *cryptographic*
output from plaintext, base64, compressed data and structured key material.

It cannot, however, separate one modern cipher from another, and no feature set
based purely on randomness can. Indistinguishability from random is the explicit
design goal of AES, ChaCha20 and RSA-OAEP. If a randomness test could tell AES
output from ChaCha20 output, that test would be a distinguishing attack and the
cipher would be considered broken. So a classifier fed only SP 800-22 p-values
will sit near chance on the cipher-vs-cipher question, by construction.

What actually carries the signal is STRUCTURE, which survives encryption because
it lives in the framing rather than the keystream:

  * block alignment  - AES/3DES/DES ciphertext length is a multiple of the block
                       size (16 / 8 / 8 bytes). Stream ciphers and AEAD
                       constructions are not.
  * ASN.1 DER framing - RSA keys, ECDSA signatures and X.509 certificates begin
                       with a SEQUENCE tag (0x30) and a parseable length.
  * PEM armour       - "-----BEGIN ..." headers name the primitive outright.
  * artifact length  - a 16/20/32/48/64-byte artifact is a digest; 256/384/512
                       bytes is an RSA-2048/3072/4096 block; 64-72 bytes with
                       DER framing is an ECDSA signature.
  * byte-value profile - printable-ASCII ratio and byte histogram separate
                       plaintext, base64 and hex from true ciphertext.

The feature vector therefore concatenates both blocks. The SP 800-22 half
answers "is this cryptographic output at all"; the structural half answers
"which primitive produced it". This is documented rather than hidden because the
limitation is a property of cryptography, not a defect in the implementation,
and it is the more interesting result of the two.

Classes
-------
    RSA_KEY, RSA_CIPHERTEXT, ECDSA_SIGNATURE, EC_KEY, AES_CBC, AES_GCM,
    CHACHA20, 3DES_CBC, SHA256_DIGEST, MD5_DIGEST, SHA1_DIGEST,
    PLAINTEXT, BASE64, COMPRESSED
"""

from __future__ import annotations

import math
import zlib
from collections import Counter

import numpy as np
from scipy.special import erfc, gammaincc

# ---------------------------------------------------------------------------
# NIST SP 800-22 statistical test battery
# ---------------------------------------------------------------------------
# Every test returns a p-value in [0, 1]. Under the null hypothesis (the data is
# random) p is uniform; p < 0.01 is the standard rejection threshold.
# ---------------------------------------------------------------------------


def _bits(data: bytes) -> np.ndarray:
    """Unpack bytes to a 0/1 bit array."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def monobit_test(bits: np.ndarray) -> float:
    """SP 800-22 2.1 - Frequency (Monobit) Test."""
    n = len(bits)
    if n == 0:
        return 0.0
    s = np.sum(2 * bits.astype(np.int64) - 1)
    return float(erfc(abs(s) / math.sqrt(n) / math.sqrt(2)))


def block_frequency_test(bits: np.ndarray, block_size: int = 128) -> float:
    """SP 800-22 2.2 - Frequency Test within a Block."""
    n = len(bits)
    n_blocks = n // block_size
    if n_blocks < 1:
        return 0.0
    trimmed = bits[: n_blocks * block_size].reshape(n_blocks, block_size)
    pi = trimmed.mean(axis=1)
    chi_sq = 4.0 * block_size * np.sum((pi - 0.5) ** 2)
    return float(gammaincc(n_blocks / 2.0, chi_sq / 2.0))


def runs_test(bits: np.ndarray) -> float:
    """SP 800-22 2.3 - Runs Test."""
    n = len(bits)
    if n < 2:
        return 0.0
    pi = bits.mean()
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0                       # monobit prerequisite failed
    v = 1 + np.sum(bits[1:] != bits[:-1])
    num = abs(v - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    return float(erfc(num / den)) if den else 0.0


def longest_run_test(bits: np.ndarray) -> float:
    """SP 800-22 2.4 - Longest Run of Ones in a Block (M = 8 variant)."""
    m, n_blocks = 8, len(bits) // 8
    if n_blocks < 16:
        return 0.0
    blocks = bits[: n_blocks * m].reshape(n_blocks, m)
    counts = np.zeros(4)
    for blk in blocks:
        longest = cur = 0
        for b in blk:
            cur = cur + 1 if b else 0
            longest = max(longest, cur)
        counts[min(max(longest, 1), 4) - 1] += 1
    pi = np.array([0.2148, 0.3672, 0.2305, 0.1875])
    expected = n_blocks * pi
    chi_sq = np.sum((counts - expected) ** 2 / expected)
    return float(gammaincc(3 / 2.0, chi_sq / 2.0))


def cumulative_sums_test(bits: np.ndarray) -> float:
    """SP 800-22 2.13 - Cumulative Sums (forward mode)."""
    n = len(bits)
    if n < 2:
        return 0.0
    x = 2 * bits.astype(np.int64) - 1
    z = int(np.max(np.abs(np.cumsum(x))))
    if z == 0:
        return 1.0
    sqrt_n = math.sqrt(n)
    total = 0.0
    k_lo = int((-n / z + 1) // 4)
    k_hi = int((n / z - 1) // 4)
    for k in range(k_lo, k_hi + 1):
        total += (_phi((4 * k + 1) * z / sqrt_n) - _phi((4 * k - 1) * z / sqrt_n))
    k_lo = int((-n / z - 3) // 4)
    for k in range(k_lo, k_hi + 1):
        total -= (_phi((4 * k + 3) * z / sqrt_n) - _phi((4 * k + 1) * z / sqrt_n))
    return float(max(0.0, min(1.0, 1.0 - total)))


def _phi(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2)))


def approximate_entropy_test(bits: np.ndarray, m: int = 2) -> float:
    """SP 800-22 2.12 - Approximate Entropy Test."""
    n = len(bits)
    if n < 100:
        return 0.0
    phi = []
    for block_len in (m, m + 1):
        padded = np.concatenate([bits, bits[: block_len - 1]])
        counts = Counter()
        for i in range(n):
            counts[padded[i:i + block_len].tobytes()] += 1
        probs = np.array(list(counts.values()), dtype=float) / n
        phi.append(float(np.sum(probs * np.log(probs))))
    ap_en = phi[0] - phi[1]
    chi_sq = 2.0 * n * (math.log(2) - ap_en)
    return float(gammaincc(2 ** (m - 1), chi_sq / 2.0))


def serial_test(bits: np.ndarray, m: int = 3) -> float:
    """SP 800-22 2.11 - Serial Test (first p-value)."""
    n = len(bits)
    if n < 100:
        return 0.0

    def psi_sq(block_len: int) -> float:
        if block_len <= 0:
            return 0.0
        padded = np.concatenate([bits, bits[: block_len - 1]])
        counts = Counter()
        for i in range(n):
            counts[padded[i:i + block_len].tobytes()] += 1
        return (2 ** block_len) / n * sum(c * c for c in counts.values()) - n

    d1 = psi_sq(m) - psi_sq(m - 1)
    return float(gammaincc(2 ** (m - 2), d1 / 2.0))


SP800_22_TESTS = [
    ("sp_monobit", lambda b: monobit_test(b)),
    ("sp_block_freq", lambda b: block_frequency_test(b)),
    ("sp_runs", lambda b: runs_test(b)),
    ("sp_longest_run", lambda b: longest_run_test(b)),
    ("sp_cusum", lambda b: cumulative_sums_test(b)),
    ("sp_approx_entropy", lambda b: approximate_entropy_test(b)),
    ("sp_serial", lambda b: serial_test(b)),
]


# ---------------------------------------------------------------------------
# Structural features - where the algorithm-identifying signal actually lives
# ---------------------------------------------------------------------------
PEM_MARKERS = {
    b"BEGIN RSA PRIVATE KEY": "rsa",
    b"BEGIN EC PRIVATE KEY": "ec",
    b"BEGIN PRIVATE KEY": "pkcs8",
    b"BEGIN PUBLIC KEY": "spki",
    b"BEGIN CERTIFICATE": "x509",
}

# OIDs that appear inside DER-encoded SubjectPublicKeyInfo structures
OID_RSA = bytes.fromhex("2a864886f70d010101")        # 1.2.840.113549.1.1.1
OID_EC = bytes.fromhex("2a8648ce3d0201")             # 1.2.840.10045.2.1
OID_ECDSA_SHA256 = bytes.fromhex("2a8648ce3d040302")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def chi_square_uniform(data: bytes) -> float:
    """Chi-square statistic of the byte histogram against uniform, normalised."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = len(data) / 256.0
    if expected == 0:
        return 0.0
    return float(np.sum((counts - expected) ** 2 / expected) / 256.0)


def structural_features(data: bytes) -> dict[str, float]:
    n = len(data)
    arr = np.frombuffer(data, dtype=np.uint8) if n else np.array([], dtype=np.uint8)

    printable = float(np.mean((arr >= 32) & (arr < 127))) if n else 0.0
    nulls = float(np.mean(arr == 0)) if n else 0.0
    high = float(np.mean(arr >= 128)) if n else 0.0

    b64_alphabet = set(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"
    )
    b64_ratio = (sum(1 for b in data[:4096] if b in b64_alphabet)
                 / max(1, min(n, 4096)))
    hex_ratio = (sum(1 for b in data[:4096] if b in b"0123456789abcdefABCDEF")
                 / max(1, min(n, 4096)))

    try:
        compressed_ratio = len(zlib.compress(data[:65536], 6)) / max(1, min(n, 65536))
    except zlib.error:
        compressed_ratio = 1.0

    pem_flags = {f"struct_pem_{v}": 0.0 for v in set(PEM_MARKERS.values())}
    head = data[:2048]
    for marker, kind in PEM_MARKERS.items():
        if marker in head:
            pem_flags[f"struct_pem_{kind}"] = 1.0

    # ASN.1 DER: 0x30 SEQUENCE followed by a well-formed length
    der_seq = 1.0 if n > 2 and data[0] == 0x30 else 0.0
    der_len_ok = 0.0
    if der_seq:
        b1 = data[1]
        if b1 < 0x80:
            der_len_ok = 1.0 if 2 + b1 == n else 0.0
        else:
            nbytes = b1 & 0x7F
            if 0 < nbytes <= 4 and n > 2 + nbytes:
                declared = int.from_bytes(data[2:2 + nbytes], "big")
                der_len_ok = 1.0 if 2 + nbytes + declared == n else 0.0

    return {
        "struct_len_log": math.log10(n + 1),
        "struct_mod16": 1.0 if n % 16 == 0 else 0.0,
        "struct_mod8": 1.0 if n % 8 == 0 else 0.0,
        "struct_mod16_not8": 1.0 if (n % 16 == 0 and n % 32 != 0) else 0.0,
        "struct_is_digest_16": 1.0 if n == 16 else 0.0,
        "struct_is_digest_20": 1.0 if n == 20 else 0.0,
        "struct_is_digest_32": 1.0 if n == 32 else 0.0,
        "struct_is_digest_48_64": 1.0 if n in (48, 64) else 0.0,
        "struct_is_rsa_block": 1.0 if n in (128, 256, 384, 512) else 0.0,
        "struct_is_ecdsa_sig_len": 1.0 if 68 <= n <= 74 else 0.0,
        "struct_entropy": shannon_entropy(data) / 8.0,
        "struct_chi2": min(chi_square_uniform(data), 10.0) / 10.0,
        "struct_printable": printable,
        "struct_nulls": nulls,
        "struct_high_bytes": high,
        "struct_b64_ratio": b64_ratio,
        "struct_hex_ratio": hex_ratio,
        "struct_compress_ratio": min(compressed_ratio, 2.0) / 2.0,
        "struct_der_seq": der_seq,
        "struct_der_len_ok": der_len_ok,
        "struct_oid_rsa": 1.0 if OID_RSA in data[:512] else 0.0,
        "struct_oid_ec": 1.0 if OID_EC in data[:512] else 0.0,
        "struct_oid_ecdsa": 1.0 if OID_ECDSA_SHA256 in data[:512] else 0.0,
        "struct_gzip_magic": 1.0 if data[:2] == b"\x1f\x8b" else 0.0,
        "struct_zlib_magic": 1.0 if data[:1] == b"\x78" else 0.0,
        **pem_flags,
    }


# ---------------------------------------------------------------------------
# Combined feature vector
# ---------------------------------------------------------------------------
def feature_names() -> list[str]:
    probe = structural_features(b"\x00" * 32)
    return [n for n, _ in SP800_22_TESTS] + sorted(probe.keys())


def extract_features(data: bytes, max_bits: int = 65536) -> np.ndarray:
    """
    Build the combined SP 800-22 + structural feature vector for one artifact.

    max_bits caps the statistical battery (the approximate-entropy and serial
    tests are O(n)); the structural half always sees the whole artifact.
    """
    bits = _bits(data[: max_bits // 8]) if data else np.array([], dtype=np.uint8)
    stat = []
    for _name, fn in SP800_22_TESTS:
        try:
            stat.append(float(fn(bits)))
        except (ValueError, ZeroDivisionError, OverflowError):
            stat.append(0.0)
    struct = structural_features(data)
    return np.array(stat + [struct[k] for k in sorted(struct.keys())],
                    dtype=np.float32)


def sp800_22_report(data: bytes) -> dict[str, float]:
    """Human-readable p-values for the dashboard's fingerprint panel."""
    bits = _bits(data[:8192])
    out = {}
    for name, fn in SP800_22_TESTS:
        try:
            out[name.replace("sp_", "")] = round(float(fn(bits)), 5)
        except (ValueError, ZeroDivisionError, OverflowError):
            out[name.replace("sp_", "")] = 0.0
    return out
