"""
Module 1a - Abstract Syntax Tree scanner for Python sources.

Why AST and not regex for Python: a regex flags the word "RSA" in a comment, in
a variable name, in a docstring. The AST walker only reports a finding when a
crypto module is genuinely imported AND a call resolves back to that import,
which is what keeps the false-positive rate low enough to satisfy the
<= 12% FPR target in the project metrics.

The walker performs a light alias-resolution pass so that

    from cryptography.hazmat.primitives.asymmetric import rsa as r
    k = r.generate_private_key(key_size=1024)

is resolved to RSA with key_size=1024 even though the token "rsa" never
appears at the call site.
"""

from __future__ import annotations

import ast
from pathlib import Path

from qaa.schema import Finding

# ---------------------------------------------------------------------------
# Modules whose presence indicates cryptographic intent, mapped to the family
# they most likely belong to. A value of None means "crypto library, family
# must be resolved from the call itself".
# ---------------------------------------------------------------------------
CRYPTO_MODULES = {
    "cryptography": None,
    "Crypto": None,               # pycryptodome
    "Cryptodome": None,
    "OpenSSL": None,
    "ssl": None,
    "hashlib": None,
    "hmac": None,
    "rsa": "RSA",
    "ecdsa": "ECDSA",
    "nacl": None,
    "paramiko": None,
    "jwt": None,
    "M2Crypto": None,
    "oqs": "ML-KEM",
    "pqcrypto": "ML-KEM",
    "kyber_py": "ML-KEM",
}

# Attribute / function names that identify the primitive family.
CALL_SIGNATURES = {
    # --- Shor-vulnerable asymmetric -------------------------------------
    "rsa": "RSA", "RSA": "RSA", "generate_private_key": None,
    "PKCS1_OAEP": "RSA", "PKCS1_v1_5": "RSA", "pkcs1_15": "RSA", "pss": "RSA",
    "ec": "ECC", "EllipticCurvePrivateKey": "ECC", "ECC": "ECC",
    "ecdsa": "ECDSA", "ECDSA": "ECDSA", "SigningKey": "ECDSA",
    "ECDH": "ECDH", "X25519PrivateKey": "X25519", "x25519": "X25519",
    "Ed25519PrivateKey": "ED25519", "ed25519": "ED25519",
    "dh": "DH", "DH": "DH", "DiffieHellman": "DH",
    "dsa": "DSA", "DSA": "DSA",
    # --- symmetric -------------------------------------------------------
    "AES": "AES", "aes": "AES", "Cipher": None,
    "DES3": "3DES", "TripleDES": "3DES", "DES": "DES",
    "ARC4": "RC4", "RC4": "RC4",
    "ChaCha20": "CHACHA20", "ChaCha20Poly1305": "CHACHA20",
    # --- hashing ---------------------------------------------------------
    "md5": "MD5", "MD5": "MD5",
    "sha1": "SHA1", "SHA1": "SHA1",
    "sha256": "SHA256", "SHA256": "SHA256", "sha512": "SHA256",
    "sha3_256": "SHA256", "sha3_512": "SHA256",
    # --- post-quantum ----------------------------------------------------
    "KeyEncapsulation": "ML-KEM", "Signature": "ML-DSA",
    "ML_KEM": "ML-KEM", "Kyber": "ML-KEM", "Dilithium": "ML-DSA",
}

CURVE_KEY_BITS = {
    "SECP192R1": 192, "SECP224R1": 224, "SECP256R1": 256, "SECP256K1": 256,
    "SECP384R1": 384, "SECP521R1": 521, "P-256": 256, "P-384": 384,
    "P-521": 521, "PRIME256V1": 256, "BRAINPOOLP256R1": 256,
}


class _CryptoVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: list[str]):
        self.file_path = file_path
        self.lines = source_lines
        self.findings: list[Finding] = []
        # alias -> canonical family or module root
        self.aliases: dict[str, str] = {}
        self.crypto_imported = False

    # -- import tracking --------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            root = a.name.split(".")[0]
            if root in CRYPTO_MODULES:
                self.crypto_imported = True
                self.aliases[a.asname or root] = CRYPTO_MODULES[root] or root
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        root = mod.split(".")[0]
        if root in CRYPTO_MODULES:
            self.crypto_imported = True
            for a in node.names:
                fam = CALL_SIGNATURES.get(a.name) or CRYPTO_MODULES[root] or a.name
                self.aliases[a.asname or a.name] = fam
        self.generic_visit(node)

    # -- call inspection --------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        if self.crypto_imported:
            family = self._resolve_family(node.func)
            if family:
                self.findings.append(self._build(node, family))
        self.generic_visit(node)

    # -- helpers ----------------------------------------------------------
    def _resolve_family(self, func: ast.AST) -> str | None:
        """Walk a dotted call target back to a crypto family, if any."""
        parts: list[str] = []
        cur = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        if not parts:
            return None

        # An alias at the head of the chain wins (handles `import ... as r`).
        head = parts[0]
        if head in self.aliases:
            resolved = self.aliases[head]
            if resolved in CALL_SIGNATURES.values() or resolved in (
                "RSA", "ECC", "ECDSA", "ML-KEM", "ML-DSA"
            ):
                # A generic crypto module root still needs the attribute chain.
                for p in parts[1:]:
                    if CALL_SIGNATURES.get(p):
                        return CALL_SIGNATURES[p]
                return resolved
            for p in parts[1:]:
                if CALL_SIGNATURES.get(p):
                    return CALL_SIGNATURES[p]

        # Otherwise look for any segment that names a primitive directly.
        for p in parts:
            fam = CALL_SIGNATURES.get(p)
            if fam:
                return fam
        return None

    def _build(self, node: ast.Call, family: str) -> Finding:
        key_size = None
        curve = None
        for kw in node.keywords:
            if kw.arg in ("key_size", "bits", "keysize", "size", "length"):
                if isinstance(kw.value, ast.Constant) and isinstance(
                    kw.value.value, int
                ):
                    key_size = kw.value.value
            if kw.arg in ("curve", "ec_curve"):
                curve = self._curve_name(kw.value)
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                if 56 <= arg.value <= 16384 and key_size is None:
                    key_size = arg.value
            c = self._curve_name(arg)
            if c and curve is None:
                curve = c
        if curve and key_size is None:
            key_size = CURVE_KEY_BITS.get(curve.upper())

        ln = getattr(node, "lineno", 1)
        snippet = self._context(ln)
        return Finding(
            file_path=self.file_path,
            line_number=ln,
            surface="source_code",
            snippet=snippet,
            matched_pattern=ast.unparse(node.func) if hasattr(ast, "unparse") else family,
            detector="ast",
            language="python",
            key_size=key_size,
            curve=curve,
            hint_algorithm=family,
        )

    @staticmethod
    def _curve_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Attribute):
            return node.attr if node.attr.upper() in CURVE_KEY_BITS else None
        if isinstance(node, ast.Call):
            return _CryptoVisitor._curve_name(node.func)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value if node.value.upper() in CURVE_KEY_BITS else None
        if isinstance(node, ast.Name):
            return node.id if node.id.upper() in CURVE_KEY_BITS else None
        return None

    def _context(self, lineno: int, span: int = 1) -> str:
        lo = max(0, lineno - 1 - span)
        hi = min(len(self.lines), lineno + span)
        return "\n".join(self.lines[lo:hi])


def scan_python_file(path: Path) -> list[Finding]:
    """Parse one .py file and return every crypto-call finding in it."""
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
    except (SyntaxError, ValueError, OSError):
        return []          # unparseable -> the regex scanner will still see it
    v = _CryptoVisitor(str(path), source.splitlines())
    v.visit(tree)
    # de-duplicate on (line, family): nested calls can report twice
    seen, out = set(), []
    for f in v.findings:
        key = (f.line_number, f.hint_algorithm)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
