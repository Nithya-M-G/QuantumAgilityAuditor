"""
Module 1d - Dependency manifest scanner.

Parses requirements.txt, pyproject.toml, Pipfile, package.json, pom.xml,
build.gradle, go.mod, Cargo.toml and composer.json, and flags declared
cryptographic libraries.

Dependency findings are intentionally weighted *down* in Module 3
(SURFACE_WEIGHT["dependency"] = 0.85) because a declared library proves the
capability exists, not that a vulnerable primitive is actually reachable. They
still matter: they seed the CBOM and they catch crypto that lives entirely
inside a transitive package.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from qaa.schema import Finding

# library name -> (family, note)
CRYPTO_LIBRARIES: dict[str, tuple[str, str]] = {
    # --- Python ---------------------------------------------------------
    "pycryptodome": ("RSA", "Python: full classical crypto suite"),
    "pycryptodomex": ("RSA", "Python: full classical crypto suite"),
    "pycrypto": ("RSA", "Python: UNMAINTAINED crypto library (CVE-2013-7459)"),
    "cryptography": ("RSA", "Python: pyca/cryptography"),
    "pyopenssl": ("RSA", "Python: OpenSSL bindings"),
    "rsa": ("RSA", "Python: pure-Python RSA"),
    "ecdsa": ("ECDSA", "Python: pure-Python ECDSA"),
    "pynacl": ("X25519", "Python: libsodium (Curve25519/Ed25519)"),
    "paramiko": ("RSA", "Python: SSH client, RSA/ECDSA host keys"),
    "pyjwt": ("RSA", "Python: JWT, commonly RS256"),
    "m2crypto": ("RSA", "Python: OpenSSL bindings"),
    "cryptodome": ("RSA", "Python: crypto suite"),
    "oqs": ("ML-KEM", "Python: liboqs - POST-QUANTUM (safe)"),
    "liboqs-python": ("ML-KEM", "Python: liboqs - POST-QUANTUM (safe)"),
    "pqcrypto": ("ML-KEM", "Python: PQC primitives - POST-QUANTUM (safe)"),
    "kyber-py": ("ML-KEM", "Python: Kyber - POST-QUANTUM (safe)"),
    # --- JavaScript ------------------------------------------------------
    "node-forge": ("RSA", "JS: pure-JS TLS/RSA/DES implementation"),
    "crypto-js": ("3DES", "JS: includes DES/TripleDES/RC4/MD5"),
    "jsrsasign": ("RSA", "JS: RSA/ECDSA PKI toolkit"),
    "elliptic": ("ECDSA", "JS: secp256k1/EC operations"),
    "jsonwebtoken": ("RSA", "JS: JWT, commonly RS256/ES256"),
    "tweetnacl": ("X25519", "JS: Curve25519/Ed25519"),
    "bcrypt": ("SHA256", "JS: password hashing (not quantum-relevant)"),
    "sshpk": ("RSA", "JS: SSH key parsing"),
    "node-rsa": ("RSA", "JS: RSA"),
    "md5": ("MD5", "JS: MD5 hashing package"),
    "sha1": ("SHA1", "JS: SHA-1 hashing package"),
    # --- Java ------------------------------------------------------------
    "bcprov-jdk15on": ("RSA", "Java: BouncyCastle provider"),
    "bcprov-jdk18on": ("RSA", "Java: BouncyCastle provider"),
    "bcpkix-jdk15on": ("RSA", "Java: BouncyCastle PKIX"),
    "bouncycastle": ("RSA", "Java: BouncyCastle"),
    "jjwt": ("RSA", "Java: JWT library"),
    "java-jwt": ("RSA", "Java: Auth0 JWT"),
    "commons-codec": ("MD5", "Java: DigestUtils exposes MD5/SHA-1"),
    "jsch": ("RSA", "Java: SSH, RSA/DSA host keys"),
    "sshj": ("RSA", "Java: SSH"),
    # --- Go / Rust / PHP ---------------------------------------------------
    "golang.org/x/crypto": ("X25519", "Go: extended crypto (Curve25519, SSH)"),
    "github.com/golang-jwt/jwt": ("RSA", "Go: JWT"),
    "openssl": ("RSA", "Rust/PHP: OpenSSL bindings"),
    "ring": ("ECDSA", "Rust: ring crypto primitives"),
    "rsa": ("RSA", "Rust: RSA crate"),
    "firebase/php-jwt": ("RSA", "PHP: JWT"),
    "phpseclib/phpseclib": ("RSA", "PHP: pure-PHP RSA/SSH"),
}

# Versions known to matter for the report (illustrative, not exhaustive)
VERSION_NOTES = {
    "pycrypto": "Unmaintained since 2014. Migrate to pycryptodome first.",
}


def _emit(path: Path, lineno: int, lib: str, version: str | None,
          raw_line: str) -> Finding | None:
    key = lib.lower().strip()
    if key not in CRYPTO_LIBRARIES:
        return None
    family, note = CRYPTO_LIBRARIES[key]
    extra = {"library": lib, "version": version or "unspecified",
             "manifest": path.name}
    if key in VERSION_NOTES:
        extra["advisory"] = VERSION_NOTES[key]
    return Finding(
        file_path=str(path),
        line_number=lineno,
        surface="dependency",
        snippet=raw_line.strip()[:200],
        matched_pattern=note,
        detector="dependency",
        language=path.suffix.lstrip(".") or path.name,
        hint_algorithm=family,
        extra=extra,
    )


def _scan_line_manifest(path: Path, lines: list[str]) -> list[Finding]:
    """requirements.txt / Pipfile / go.mod / build.gradle / Cargo.toml."""
    out = []
    pat = re.compile(r'^\s*["\']?([A-Za-z0-9_.\-/]+)["\']?\s*'
                     r'(?:[=<>~!^:]+\s*["\']?v?([0-9][0-9A-Za-z.\-+]*))?')
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        # gradle style: implementation 'group:artifact:version'
        g = re.search(r'["\']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):'
                      r'([0-9][0-9A-Za-z.\-]*)["\']', s)
        if g:
            f = _emit(path, i, g.group(2), g.group(3), line)
            if f:
                out.append(f)
                continue
        m = pat.match(s)
        if m:
            f = _emit(path, i, m.group(1), m.group(2), line)
            if f:
                out.append(f)
    return out


def _scan_package_json(path: Path, raw: str) -> list[Finding]:
    out = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _scan_line_manifest(path, raw.splitlines())
    lines = raw.splitlines()
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for lib, ver in (data.get(section) or {}).items():
            lineno = next((i for i, l in enumerate(lines, 1)
                           if f'"{lib}"' in l), 1)
            f = _emit(path, lineno, lib, str(ver),
                      lines[lineno - 1] if lineno <= len(lines) else lib)
            if f:
                out.append(f)
    return out


def _scan_pom_xml(path: Path, raw: str) -> list[Finding]:
    out = []
    lines = raw.splitlines()
    for m in re.finditer(
        r'<artifactId>\s*([^<]+?)\s*</artifactId>\s*(?:<version>\s*([^<]+?)\s*</version>)?',
        raw, re.S,
    ):
        lib = m.group(1)
        lineno = raw[: m.start()].count("\n") + 1
        f = _emit(path, lineno, lib, m.group(2),
                  lines[lineno - 1] if lineno <= len(lines) else lib)
        if f:
            out.append(f)
    return out


def _scan_pyproject(path: Path, raw: str) -> list[Finding]:
    out = []
    lines = raw.splitlines()
    for i, line in enumerate(lines, start=1):
        m = re.match(r'\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*[=]\s*["\']([^"\']+)["\']', line)
        if m:
            f = _emit(path, i, m.group(1), m.group(2), line)
            if f:
                out.append(f)
                continue
        m2 = re.search(r'["\']([A-Za-z0-9_.\-]+)\s*[><=~!]+\s*([0-9][^"\']*)["\']', line)
        if m2:
            f = _emit(path, i, m2.group(1), m2.group(2), line)
            if f:
                out.append(f)
    return out


def scan_dependency_file(path: Path) -> list[Finding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    name = path.name.lower()
    if name in ("package.json", "package-lock.json"):
        return _scan_package_json(path, raw)
    if name == "pom.xml":
        return _scan_pom_xml(path, raw)
    if name in ("pyproject.toml", "cargo.toml", "pipfile"):
        return _scan_pyproject(path, raw)
    if name == "composer.json":
        return _scan_package_json(path, raw)
    return _scan_line_manifest(path, raw.splitlines())
