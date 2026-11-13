"""
Module 1b - Regex scanner for non-Python source files.

Python gets a real AST. Java, JavaScript, C/C++, Go, C# and Rust get a curated
pattern base instead. To keep the false-positive rate down the patterns are
*API-shaped* rather than *keyword-shaped*: we match `Cipher.getInstance("DES/...")`
and `crypto.createCipheriv('des-ede3-cbc', ...)`, not the bare token "DES".

Comment stripping runs first so that "// TODO: replace RSA" never becomes a
finding.
"""

from __future__ import annotations

import re
from pathlib import Path

from qaa.schema import Finding

EXT_LANGUAGE = {
    ".java": "java", ".js": "javascript", ".ts": "typescript",
    ".cpp": "cpp", ".c": "c", ".h": "c", ".go": "go",
    ".cs": "csharp", ".rb": "ruby", ".php": "php", ".rs": "rust",
}

# (compiled pattern, family, note)
PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ---- Java / JCA ----------------------------------------------------
    (re.compile(r'KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"RSA"', re.I), "RSA", "JCA RSA keypair"),
    (re.compile(r'Cipher\s*\.\s*getInstance\s*\(\s*"RSA', re.I), "RSA", "JCA RSA cipher"),
    (re.compile(r'Signature\s*\.\s*getInstance\s*\(\s*"[A-Za-z0-9]*with?RSA"', re.I), "RSA", "JCA RSA signature"),
    (re.compile(r'KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"EC(DSA)?"', re.I), "ECDSA", "JCA EC keypair"),
    (re.compile(r'Signature\s*\.\s*getInstance\s*\(\s*"[A-Za-z0-9]*with?ECDSA"', re.I), "ECDSA", "JCA ECDSA signature"),
    (re.compile(r'KeyAgreement\s*\.\s*getInstance\s*\(\s*"ECDH"', re.I), "ECDH", "JCA ECDH agreement"),
    (re.compile(r'KeyAgreement\s*\.\s*getInstance\s*\(\s*"DiffieHellman"', re.I), "DH", "JCA DH agreement"),
    (re.compile(r'KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"DSA"', re.I), "DSA", "JCA DSA keypair"),
    (re.compile(r'Cipher\s*\.\s*getInstance\s*\(\s*"DESede', re.I), "3DES", "JCA Triple-DES"),
    (re.compile(r'Cipher\s*\.\s*getInstance\s*\(\s*"DES[/"]', re.I), "DES", "JCA single DES"),
    (re.compile(r'Cipher\s*\.\s*getInstance\s*\(\s*"(RC4|ARCFOUR)', re.I), "RC4", "JCA RC4"),
    (re.compile(r'Cipher\s*\.\s*getInstance\s*\(\s*"AES', re.I), "AES", "JCA AES"),
    (re.compile(r'MessageDigest\s*\.\s*getInstance\s*\(\s*"MD5"', re.I), "MD5", "JCA MD5"),
    (re.compile(r'MessageDigest\s*\.\s*getInstance\s*\(\s*"SHA-?1"', re.I), "SHA1", "JCA SHA-1"),
    (re.compile(r'MessageDigest\s*\.\s*getInstance\s*\(\s*"SHA-?(256|384|512)"', re.I), "SHA256", "JCA SHA-2"),
    (re.compile(r'\bDigestUtils\s*\.\s*md5(Hex)?\s*\(', re.I), "MD5", "Commons-Codec MD5"),
    (re.compile(r'\bDigestUtils\s*\.\s*sha1(Hex)?\s*\(', re.I), "SHA1", "Commons-Codec SHA-1"),
    # ---- BouncyCastle ---------------------------------------------------
    (re.compile(r'\bRSAKeyPairGenerator\b|\bRSAEngine\b'), "RSA", "BouncyCastle RSA"),
    (re.compile(r'\bECKeyPairGenerator\b|\bECDSASigner\b'), "ECDSA", "BouncyCastle ECDSA"),
    (re.compile(r'\bDESedeEngine\b'), "3DES", "BouncyCastle 3DES"),
    (re.compile(r'\bRC4Engine\b'), "RC4", "BouncyCastle RC4"),
    # ---- Node.js --------------------------------------------------------
    (re.compile(r'generateKeyPair(Sync)?\s*\(\s*[\'"]rsa[\'"]', re.I), "RSA", "Node RSA keypair"),
    (re.compile(r'generateKeyPair(Sync)?\s*\(\s*[\'"]ec[\'"]', re.I), "ECDSA", "Node EC keypair"),
    (re.compile(r'generateKeyPair(Sync)?\s*\(\s*[\'"]ed25519[\'"]', re.I), "ED25519", "Node Ed25519"),
    (re.compile(r'generateKeyPair(Sync)?\s*\(\s*[\'"]x25519[\'"]', re.I), "X25519", "Node X25519"),
    (re.compile(r'crypto\s*\.\s*createECDH\s*\(', re.I), "ECDH", "Node ECDH"),
    (re.compile(r'crypto\s*\.\s*createDiffieHellman\s*\(', re.I), "DH", "Node DH"),
    (re.compile(r'createCipheriv\s*\(\s*[\'"]des-ede3', re.I), "3DES", "Node 3DES"),
    (re.compile(r'createCipheriv\s*\(\s*[\'"]des-(cbc|ecb)', re.I), "DES", "Node DES"),
    (re.compile(r'createCipheriv\s*\(\s*[\'"]rc4', re.I), "RC4", "Node RC4"),
    (re.compile(r'createCipheriv\s*\(\s*[\'"]aes-\d+', re.I), "AES", "Node AES"),
    (re.compile(r'createCipheriv\s*\(\s*[\'"]chacha20', re.I), "CHACHA20", "Node ChaCha20"),
    (re.compile(r'createHash\s*\(\s*[\'"]md5[\'"]', re.I), "MD5", "Node MD5"),
    (re.compile(r'createHash\s*\(\s*[\'"]sha1[\'"]', re.I), "SHA1", "Node SHA-1"),
    (re.compile(r'createHash\s*\(\s*[\'"]sha(256|384|512)[\'"]', re.I), "SHA256", "Node SHA-2"),
    (re.compile(r'\bjwt\s*\.\s*sign\s*\([^)]*RS256', re.I), "RSA", "JWT RS256"),
    (re.compile(r'\bjwt\s*\.\s*sign\s*\([^)]*ES256', re.I), "ECDSA", "JWT ES256"),
    # ---- OpenSSL C/C++ --------------------------------------------------
    (re.compile(r'\bRSA_generate_key(_ex)?\s*\('), "RSA", "OpenSSL RSA keygen"),
    (re.compile(r'\bRSA_(public|private)_(encrypt|decrypt)\s*\('), "RSA", "OpenSSL RSA op"),
    (re.compile(r'\bEC_KEY_(generate_key|new_by_curve_name)\s*\('), "ECC", "OpenSSL EC keygen"),
    (re.compile(r'\bECDSA_(sign|do_sign|verify)\s*\('), "ECDSA", "OpenSSL ECDSA"),
    (re.compile(r'\bECDH_compute_key\s*\('), "ECDH", "OpenSSL ECDH"),
    (re.compile(r'\bDH_generate_key\s*\('), "DH", "OpenSSL DH"),
    (re.compile(r'\bDSA_generate_key\s*\('), "DSA", "OpenSSL DSA"),
    (re.compile(r'\bEVP_des_ede3'), "3DES", "OpenSSL 3DES"),
    (re.compile(r'\bEVP_des_(cbc|ecb)\b'), "DES", "OpenSSL DES"),
    (re.compile(r'\bEVP_rc4\b'), "RC4", "OpenSSL RC4"),
    (re.compile(r'\bEVP_aes_\d+_'), "AES", "OpenSSL AES"),
    (re.compile(r'\bMD5(_Init|_Update|_Final)?\s*\('), "MD5", "OpenSSL MD5"),
    (re.compile(r'\bSHA1(_Init|_Update|_Final)?\s*\('), "SHA1", "OpenSSL SHA-1"),
    # ---- Go --------------------------------------------------------------
    (re.compile(r'\brsa\s*\.\s*GenerateKey\s*\('), "RSA", "Go crypto/rsa"),
    (re.compile(r'\becdsa\s*\.\s*(GenerateKey|Sign)\s*\('), "ECDSA", "Go crypto/ecdsa"),
    (re.compile(r'\bed25519\s*\.\s*GenerateKey\s*\('), "ED25519", "Go crypto/ed25519"),
    (re.compile(r'\bdes\s*\.\s*NewTripleDESCipher\s*\('), "3DES", "Go 3DES"),
    (re.compile(r'\bdes\s*\.\s*NewCipher\s*\('), "DES", "Go DES"),
    (re.compile(r'\bmd5\s*\.\s*(New|Sum)\s*\('), "MD5", "Go MD5"),
    (re.compile(r'\bsha1\s*\.\s*(New|Sum)\s*\('), "SHA1", "Go SHA-1"),
    (re.compile(r'\baes\s*\.\s*NewCipher\s*\('), "AES", "Go AES"),
    # ---- C# / .NET --------------------------------------------------------
    (re.compile(r'\bnew\s+RSACryptoServiceProvider\s*\('), "RSA", ".NET RSA"),
    (re.compile(r'\bECDsa\s*\.\s*Create\s*\('), "ECDSA", ".NET ECDSA"),
    (re.compile(r'\bnew\s+TripleDESCryptoServiceProvider\s*\('), "3DES", ".NET 3DES"),
    (re.compile(r'\bnew\s+MD5CryptoServiceProvider\s*\(|\bMD5\s*\.\s*Create\s*\('), "MD5", ".NET MD5"),
    (re.compile(r'\bSHA1\s*\.\s*Create\s*\('), "SHA1", ".NET SHA-1"),
    # ---- Post-quantum (already-migrated, scored as safe) -------------------
    (re.compile(r'\bML[-_]?KEM\b|\bKyber\d*\b', re.I), "ML-KEM", "PQC KEM in use"),
    (re.compile(r'\bML[-_]?DSA\b|\bDilithium\d*\b', re.I), "ML-DSA", "PQC signature in use"),
    (re.compile(r'\bSLH[-_]?DSA\b|\bSPHINCS\+?\b', re.I), "SLH-DSA", "PQC hash signature"),
]

# Key size and curve extraction on the matched line
KEYSIZE_RE = re.compile(r'\b(512|768|1024|2048|3072|4096|7680|8192)\b')
CURVE_RE = re.compile(r'\b(secp(192|224|256|384|521)[rk]1|prime256v1|P-(256|384|521)|'
                      r'brainpoolP\d+r1)\b', re.I)
CURVE_BITS = {"192": 192, "224": 224, "256": 256, "384": 384, "521": 521}

# Comment stripping (line comments + block comments), applied before matching
BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
LINE_COMMENT = re.compile(r'(^|[^:"\'])//.*?$|^\s*#.*?$', re.M)


def _blank_comments(text: str) -> str:
    """Replace comment bodies with spaces, preserving line numbering."""
    def _blank(m: re.Match) -> str:
        return re.sub(r'[^\n]', ' ', m.group(0))
    text = BLOCK_COMMENT.sub(_blank, text)
    text = LINE_COMMENT.sub(_blank, text)
    return text


def scan_text_source(path: Path, language: str | None = None) -> list[Finding]:
    """Regex-scan one non-Python source file."""
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    language = language or EXT_LANGUAGE.get(path.suffix.lower(), "unknown")
    cleaned = _blank_comments(raw)
    raw_lines = raw.splitlines()
    clean_lines = cleaned.splitlines()

    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for idx, line in enumerate(clean_lines, start=1):
        if not line.strip():
            continue
        for pattern, family, note in PATTERNS:
            if pattern.search(line):
                if (idx, family) in seen:
                    continue
                seen.add((idx, family))
                original = raw_lines[idx - 1] if idx <= len(raw_lines) else line

                key_size = None
                curve = None
                cm = CURVE_RE.search(original)
                if cm:
                    curve = cm.group(0)
                    digits = re.search(r'(192|224|256|384|521)', curve)
                    if digits:
                        key_size = CURVE_BITS[digits.group(0)]
                if key_size is None:
                    km = KEYSIZE_RE.search(original)
                    if km:
                        key_size = int(km.group(0))
                if family == "AES" and key_size is None:
                    am = re.search(r'aes[-_]?(128|192|256)', original, re.I)
                    if am:
                        key_size = int(am.group(1))

                lo = max(0, idx - 2)
                hi = min(len(raw_lines), idx + 1)
                findings.append(Finding(
                    file_path=str(path),
                    line_number=idx,
                    surface="source_code",
                    snippet="\n".join(raw_lines[lo:hi]),
                    matched_pattern=note,
                    detector="regex",
                    language=language,
                    key_size=key_size,
                    curve=curve,
                    hint_algorithm=family,
                ))
    return findings
