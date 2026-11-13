"""
Module 1c - Configuration surface scanner.

Targets nginx.conf, apache/httpd, .env, docker-compose.yml, openssl.cnf,
sshd_config and generic .ini/.yaml/.properties files.

What it flags:
  * TLS protocol versions (SSLv3, TLSv1.0, TLSv1.1 are quantum-irrelevant but
    are reported because they force weak key exchange)
  * Cipher suite strings naming a Shor-vulnerable key exchange or a broken cipher
  * Explicit key-size declarations below the NIST floor
  * Certificate / key path declarations, which tell the auditor that an
    asymmetric key exists on this host even if no algorithm is named
"""

from __future__ import annotations

import re
from pathlib import Path

from qaa.schema import Finding

CONFIG_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ---- TLS protocol versions -----------------------------------------
    (re.compile(r'ssl_protocols[^;\n]*\b(SSLv2|SSLv3|TLSv1(\.[01])?)\b', re.I),
     "ECDH", "nginx: legacy TLS protocol enabled"),
    (re.compile(r'SSLProtocol[^\n]*\b(SSLv2|SSLv3|TLSv1(\.[01])?)\b', re.I),
     "ECDH", "apache: legacy TLS protocol enabled"),
    (re.compile(r'MinProtocol\s*=\s*TLSv1(\.[01])?\b', re.I),
     "ECDH", "openssl.cnf: minimum protocol too low"),
    # ---- Cipher suite strings ------------------------------------------
    (re.compile(r'\bECDHE?[-_]RSA[-_]', re.I), "RSA", "cipher suite: RSA authentication"),
    (re.compile(r'\bECDHE?[-_]ECDSA[-_]', re.I), "ECDSA", "cipher suite: ECDSA authentication"),
    (re.compile(r'\bTLS_ECDHE_', re.I), "ECDH", "cipher suite: ECDHE key exchange"),
    (re.compile(r'\bDHE[-_](RSA|DSS)[-_]', re.I), "DH", "cipher suite: finite-field DHE"),
    (re.compile(r'\b(TLS_RSA_WITH|AES\d+-SHA)\b', re.I), "RSA", "cipher suite: static RSA key transport"),
    (re.compile(r'\b(DES-CBC3|3DES|TRIPLE_?DES|DESede)\b', re.I), "3DES", "cipher suite: Triple-DES"),
    (re.compile(r'\b(RC4|ARCFOUR)\b', re.I), "RC4", "cipher suite: RC4"),
    (re.compile(r'[-_]MD5\b', re.I), "MD5", "cipher suite: MD5 MAC"),
    (re.compile(r'[-_]SHA\b(?!\d)', re.I), "SHA1", "cipher suite: SHA-1 MAC"),
    (re.compile(r'\bssl_ecdh_curve\s+\S+', re.I), "ECDH", "nginx: ECDH curve pinned"),
    (re.compile(r'\bCurves\s*=\s*\S+', re.I), "ECDH", "openssl.cnf: EC curve list"),
    # ---- ssh ------------------------------------------------------------
    (re.compile(r'\bKexAlgorithms[^\n]*\b(diffie-hellman|ecdh|curve25519)', re.I),
     "ECDH", "sshd: quantum-vulnerable key exchange"),
    (re.compile(r'\bHostKeyAlgorithms[^\n]*\b(ssh-rsa|ecdsa-sha2|ssh-ed25519)', re.I),
     "RSA", "sshd: quantum-vulnerable host key"),
    (re.compile(r'\bCiphers[^\n]*\b(3des|arcfour)', re.I), "3DES", "sshd: legacy cipher"),
    # ---- key material / key size ----------------------------------------
    (re.compile(r'(ssl_certificate_key|SSLCertificateKeyFile)\s+\S+', re.I),
     "RSA", "TLS private key declared on this host"),
    (re.compile(r'\b(RSA_KEY_SIZE|KEY_SIZE|default_bits|RSA_BITS)\s*[:=]\s*(512|768|1024|2048)\b', re.I),
     "RSA", "explicit RSA key size declaration"),
    (re.compile(r'\b(JWT_ALGORITHM|JWT_ALG|ALGORITHM)\s*[:=]\s*["\']?(RS|PS)(256|384|512)', re.I),
     "RSA", ".env: RSA-signed JWT"),
    (re.compile(r'\b(JWT_ALGORITHM|JWT_ALG|ALGORITHM)\s*[:=]\s*["\']?ES(256|384|512)', re.I),
     "ECDSA", ".env: ECDSA-signed JWT"),
    (re.compile(r'\b(HASH_ALGO|HASH_ALGORITHM|PASSWORD_HASH)\s*[:=]\s*["\']?(md5|MD5)', re.I),
     "MD5", ".env: MD5 password hashing"),
    (re.compile(r'\b(HASH_ALGO|HASH_ALGORITHM)\s*[:=]\s*["\']?(sha1|SHA1)', re.I),
     "SHA1", ".env: SHA-1 hashing"),
    (re.compile(r'\b(ENCRYPTION_ALGO|CIPHER)\s*[:=]\s*["\']?(aes-?128|AES128)', re.I),
     "AES", ".env: AES-128 configured"),
    (re.compile(r'\b(ENCRYPTION_ALGO|CIPHER)\s*[:=]\s*["\']?(des|DES|3des)', re.I),
     "3DES", ".env: DES-family cipher configured"),
]

KEYSIZE_RE = re.compile(r'\b(512|768|1024|2048|3072|4096)\b')
CURVE_RE = re.compile(r'\b(secp\d+[rk]1|prime256v1|P-\d{3}|X25519|x25519)\b', re.I)
CURVE_BITS = {"256": 256, "384": 384, "521": 521, "224": 224, "192": 192}


def scan_config_file(path: Path) -> list[Finding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    lines = raw.splitlines()
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        for pattern, family, note in CONFIG_PATTERNS:
            if pattern.search(line):
                if (idx, family) in seen:
                    continue
                seen.add((idx, family))

                key_size = None
                curve = None
                cm = CURVE_RE.search(line)
                if cm:
                    curve = cm.group(0)
                    d = re.search(r'(192|224|256|384|521)', curve)
                    if d:
                        key_size = CURVE_BITS[d.group(0)]
                    elif curve.lower() == "x25519":
                        key_size = 256
                if key_size is None:
                    km = KEYSIZE_RE.search(line)
                    if km:
                        key_size = int(km.group(0))

                findings.append(Finding(
                    file_path=str(path),
                    line_number=idx,
                    surface="config",
                    snippet=line.strip(),
                    matched_pattern=note,
                    detector="config",
                    language=path.suffix.lstrip(".") or path.name,
                    key_size=key_size,
                    curve=curve,
                    hint_algorithm=family,
                    extra={"config_file": path.name},
                ))
    return findings
