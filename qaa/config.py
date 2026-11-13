"""
Central configuration and cryptographic knowledge base for the Quantum-Agility Auditor.

Everything that is "domain knowledge" rather than "logic" lives here so that the
rest of the codebase stays algorithmic and the knowledge base stays auditable.

References
----------
NIST FIPS 203 (ML-KEM / Kyber)     - Module-Lattice Key Encapsulation
NIST FIPS 204 (ML-DSA / Dilithium) - Module-Lattice Digital Signature
NIST FIPS 205 (SLH-DSA / SPHINCS+) - Stateless Hash-Based Digital Signature
NIST SP 800-131A Rev.2             - Transitioning cryptographic algorithms
NIST SP 800-22                     - Statistical test suite for RNG / ciphertext
NSA CNSA 2.0                       - Migration timelines
"""

from pathlib import Path

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_DIR = PROJECT_ROOT / "models"
SAMPLES_DIR = PROJECT_ROOT / "samples"

for _d in (DATA_DIR, MODEL_DIR):
    _d.mkdir(parents=True, exist_ok=True)

NLP_MODEL_PATH = MODEL_DIR / "nlp_classifier.joblib"
FP_MODEL_PATH = MODEL_DIR / "fingerprint_classifier.joblib"
NLP_METRICS_PATH = MODEL_DIR / "nlp_metrics.json"
FP_METRICS_PATH = MODEL_DIR / "fingerprint_metrics.json"

# --------------------------------------------------------------------------
# Quantum threat classification
# --------------------------------------------------------------------------
# SHOR   -> asymmetric primitive, fully broken by Shor's algorithm
# GROVER -> symmetric / hash primitive, security halved by Grover's algorithm
# BROKEN -> already classically broken, independent of quantum
# PQC    -> NIST post-quantum standard, safe
# SAFE   -> classically and quantum-adequate at the given parameters

THREAT_SHOR = "SHOR"
THREAT_GROVER = "GROVER"
THREAT_BROKEN = "CLASSICALLY_BROKEN"
THREAT_PQC = "POST_QUANTUM_SAFE"
THREAT_SAFE = "QUANTUM_ADEQUATE"

# --------------------------------------------------------------------------
# Cryptographic purpose taxonomy (drives context-aware recommendation)
# --------------------------------------------------------------------------
PURPOSE_KEY_EXCHANGE = "key_exchange"
PURPOSE_SIGNATURE = "digital_signature"
PURPOSE_ENCRYPTION = "bulk_encryption"
PURPOSE_HASHING = "hashing"
PURPOSE_KDF = "key_derivation"
PURPOSE_MAC = "message_authentication"
PURPOSE_RANDOM = "randomness"

# --------------------------------------------------------------------------
# ALGORITHM KNOWLEDGE BASE
# --------------------------------------------------------------------------
# base_severity : 0-10 intrinsic severity BEFORE contextual multipliers
# min_safe_key  : key size below which +2 severity penalty applies
# --------------------------------------------------------------------------
ALGORITHM_DB = {
    "RSA": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_KEY_EXCHANGE,
        "base_severity": 9.0,
        "min_safe_key": 3072,
        "description": "Integer-factorisation public-key cryptosystem; broken in "
                       "polynomial time by Shor's algorithm.",
        "nist_status": "Disallowed after 2030 (NIST IR 8547 draft)",
    },
    "ECC": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_KEY_EXCHANGE,
        "base_severity": 9.5,
        "min_safe_key": 384,
        "description": "Elliptic-curve discrete logarithm; broken by Shor with far "
                       "fewer logical qubits than equivalent-strength RSA.",
        "nist_status": "Disallowed after 2030 (NIST IR 8547 draft)",
    },
    "ECDSA": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_SIGNATURE,
        "base_severity": 9.5,
        "min_safe_key": 384,
        "description": "Elliptic-curve signature scheme; private key recoverable "
                       "from any public key via Shor.",
        "nist_status": "Disallowed after 2030",
    },
    "ECDH": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_KEY_EXCHANGE,
        "base_severity": 9.5,
        "min_safe_key": 384,
        "description": "Elliptic-curve Diffie-Hellman key agreement; the canonical "
                       "Harvest-Now-Decrypt-Later target.",
        "nist_status": "Disallowed after 2030",
    },
    "DH": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_KEY_EXCHANGE,
        "base_severity": 9.0,
        "min_safe_key": 3072,
        "description": "Finite-field Diffie-Hellman; discrete log broken by Shor.",
        "nist_status": "Disallowed after 2030",
    },
    "DSA": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_SIGNATURE,
        "base_severity": 9.0,
        "min_safe_key": 3072,
        "description": "Finite-field discrete-log signature scheme.",
        "nist_status": "Deprecated for signature generation",
    },
    "ED25519": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_SIGNATURE,
        "base_severity": 9.0,
        "min_safe_key": 256,
        "description": "Edwards-curve signature; elliptic-curve discrete log, "
                       "therefore Shor-vulnerable despite modern design.",
        "nist_status": "Disallowed after 2030",
    },
    "X25519": {
        "threat": THREAT_SHOR,
        "purpose": PURPOSE_KEY_EXCHANGE,
        "base_severity": 9.5,
        "min_safe_key": 256,
        "description": "Montgomery-curve key agreement used in TLS 1.3 and Signal; "
                       "Shor-vulnerable.",
        "nist_status": "Hybrid X25519+ML-KEM-768 recommended now",
    },
    "AES": {
        "threat": THREAT_GROVER,
        "purpose": PURPOSE_ENCRYPTION,
        "base_severity": 3.0,
        "min_safe_key": 256,
        "description": "Symmetric block cipher; Grover halves effective key length, "
                       "so AES-128 gives ~64-bit quantum security.",
        "nist_status": "AES-256 approved for CNSA 2.0",
    },
    "3DES": {
        "threat": THREAT_BROKEN,
        "purpose": PURPOSE_ENCRYPTION,
        "base_severity": 8.0,
        "min_safe_key": 999999,
        "description": "Triple DES; 64-bit block enables Sweet32 birthday attacks. "
                       "Disallowed by NIST since 2023.",
        "nist_status": "Disallowed (SP 800-131A Rev.2)",
    },
    "DES": {
        "threat": THREAT_BROKEN,
        "purpose": PURPOSE_ENCRYPTION,
        "base_severity": 10.0,
        "min_safe_key": 999999,
        "description": "56-bit key, brute-forceable classically in hours.",
        "nist_status": "Disallowed",
    },
    "RC4": {
        "threat": THREAT_BROKEN,
        "purpose": PURPOSE_ENCRYPTION,
        "base_severity": 9.5,
        "min_safe_key": 999999,
        "description": "Stream cipher with biased keystream; prohibited in TLS by "
                       "RFC 7465.",
        "nist_status": "Prohibited",
    },
    "MD5": {
        "threat": THREAT_BROKEN,
        "purpose": PURPOSE_HASHING,
        "base_severity": 9.0,
        "min_safe_key": 999999,
        "description": "Practical chosen-prefix collisions; unusable for integrity.",
        "nist_status": "Disallowed for digital signatures",
    },
    "SHA1": {
        "threat": THREAT_BROKEN,
        "purpose": PURPOSE_HASHING,
        "base_severity": 8.0,
        "min_safe_key": 999999,
        "description": "SHAttered / chosen-prefix collisions demonstrated.",
        "nist_status": "Disallowed after 2030 (SP 800-131A)",
    },
    "SHA256": {
        "threat": THREAT_GROVER,
        "purpose": PURPOSE_HASHING,
        "base_severity": 2.0,
        "min_safe_key": 256,
        "description": "Grover gives ~128-bit preimage resistance; acceptable but "
                       "SHA-384/SHA-3 preferred for long-lived data.",
        "nist_status": "Approved",
    },
    "CHACHA20": {
        "threat": THREAT_GROVER,
        "purpose": PURPOSE_ENCRYPTION,
        "base_severity": 2.0,
        "min_safe_key": 256,
        "description": "256-bit stream cipher; ~128-bit quantum security. Adequate.",
        "nist_status": "Not FIPS-approved but cryptographically sound",
    },
    "ML-KEM": {
        "threat": THREAT_PQC,
        "purpose": PURPOSE_KEY_EXCHANGE,
        "base_severity": 0.0,
        "min_safe_key": 0,
        "description": "NIST FIPS 203 standardised lattice KEM (Kyber).",
        "nist_status": "FIPS 203 - Approved",
    },
    "ML-DSA": {
        "threat": THREAT_PQC,
        "purpose": PURPOSE_SIGNATURE,
        "base_severity": 0.0,
        "min_safe_key": 0,
        "description": "NIST FIPS 204 standardised lattice signature (Dilithium).",
        "nist_status": "FIPS 204 - Approved",
    },
    "SLH-DSA": {
        "threat": THREAT_PQC,
        "purpose": PURPOSE_SIGNATURE,
        "base_severity": 0.0,
        "min_safe_key": 0,
        "description": "NIST FIPS 205 stateless hash-based signature (SPHINCS+).",
        "nist_status": "FIPS 205 - Approved",
    },
    "NONE": {
        "threat": THREAT_SAFE,
        "purpose": PURPOSE_RANDOM,
        "base_severity": 0.0,
        "min_safe_key": 0,
        "description": "No cryptographic primitive detected.",
        "nist_status": "N/A",
    },
}

# Label set used by the Module-2 NLP classifier (order is stable / canonical)
NLP_LABELS = [
    "RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "AES", "3DES",
    "DES", "RC4", "MD5", "SHA1", "SHA256", "CHACHA20", "ML-KEM", "NONE",
]

# --------------------------------------------------------------------------
# MIGRATION MAP - context-aware NIST replacement (Module 3)
# --------------------------------------------------------------------------
# Keyed by (purpose, security_tier). Tier is derived from data sensitivity.
MIGRATION_MAP = {
    (PURPOSE_KEY_EXCHANGE, "standard"): {
        "replacement": "ML-KEM-768",
        "standard": "NIST FIPS 203",
        "hybrid": "X25519 + ML-KEM-768 (hybrid, recommended during transition)",
        "library": "liboqs-python / oqs-provider for OpenSSL 3.x",
        "nist_level": "Category 3 (~AES-192)",
    },
    (PURPOSE_KEY_EXCHANGE, "high"): {
        "replacement": "ML-KEM-1024",
        "standard": "NIST FIPS 203",
        "hybrid": "X25519 + ML-KEM-1024",
        "library": "liboqs-python / oqs-provider",
        "nist_level": "Category 5 (~AES-256)",
    },
    (PURPOSE_SIGNATURE, "standard"): {
        "replacement": "ML-DSA-65",
        "standard": "NIST FIPS 204",
        "hybrid": "ECDSA-P256 + ML-DSA-65 (composite)",
        "library": "liboqs-python",
        "nist_level": "Category 3",
    },
    (PURPOSE_SIGNATURE, "high"): {
        "replacement": "ML-DSA-87",
        "standard": "NIST FIPS 204",
        "hybrid": "ML-DSA-87, or SLH-DSA-SHA2-256s where firmware signing "
                  "requires conservative hash-based security",
        "library": "liboqs-python",
        "nist_level": "Category 5",
    },
    (PURPOSE_ENCRYPTION, "standard"): {
        "replacement": "AES-256-GCM",
        "standard": "NIST FIPS 197 / SP 800-38D",
        "hybrid": "N/A - symmetric primitives need only a key-size increase",
        "library": "cryptography (Python) / javax.crypto (Java)",
        "nist_level": "~128-bit post-Grover security",
    },
    (PURPOSE_ENCRYPTION, "high"): {
        "replacement": "AES-256-GCM",
        "standard": "NIST FIPS 197 / SP 800-38D",
        "hybrid": "N/A",
        "library": "cryptography / javax.crypto",
        "nist_level": "~128-bit post-Grover security",
    },
    (PURPOSE_HASHING, "standard"): {
        "replacement": "SHA-256",
        "standard": "NIST FIPS 180-4",
        "hybrid": "N/A",
        "library": "hashlib / java.security.MessageDigest",
        "nist_level": "~128-bit post-Grover preimage resistance",
    },
    (PURPOSE_HASHING, "high"): {
        "replacement": "SHA3-512",
        "standard": "NIST FIPS 202",
        "hybrid": "N/A",
        "library": "hashlib.sha3_512",
        "nist_level": "~256-bit post-Grover preimage resistance",
    },
}

# --------------------------------------------------------------------------
# PERFORMANCE PENALTY MODEL (Module 3)
# --------------------------------------------------------------------------
# Public benchmark data: operations/sec and transmitted bytes, relative to the
# classical primitive being replaced. Sources: NIST PQC Round-3 report,
# liboqs speed benchmarks, Cloudflare/Google TLS PQC deployment measurements.
PERFORMANCE_MODEL = {
    "ML-KEM-768": {
        "vs": "X25519 / RSA-2048 key exchange",
        "cpu_delta_pct": -35,      # negative = FASTER than the classical baseline
        "bytes_public_key": 1184,
        "bytes_ciphertext": 1088,
        "baseline_bytes": 32,
        "handshake_note": "Adds ~2.3 KB per TLS handshake; Chrome/Cloudflare "
                          "measured median handshake impact under 4 ms.",
    },
    "ML-KEM-1024": {
        "vs": "X25519 / RSA-3072 key exchange",
        "cpu_delta_pct": -20,
        "bytes_public_key": 1568,
        "bytes_ciphertext": 1568,
        "baseline_bytes": 32,
        "handshake_note": "Adds ~3.1 KB per handshake.",
    },
    "ML-DSA-65": {
        "vs": "ECDSA-P256 signature",
        "cpu_delta_pct": +15,
        "bytes_public_key": 1952,
        "bytes_signature": 3309,
        "baseline_bytes": 64,
        "handshake_note": "Signature is ~50x larger than ECDSA. Certificate "
                          "chains grow substantially; watch MTU and QUIC "
                          "amplification limits.",
    },
    "ML-DSA-87": {
        "vs": "ECDSA-P384 signature",
        "cpu_delta_pct": +40,
        "bytes_public_key": 2592,
        "bytes_signature": 4627,
        "baseline_bytes": 96,
        "handshake_note": "Largest lattice signature; reserve for long-lived "
                          "roots of trust.",
    },
    "SLH-DSA-SHA2-256s": {
        "vs": "RSA-4096 / ECDSA firmware signing",
        "cpu_delta_pct": +8000,
        "bytes_public_key": 64,
        "bytes_signature": 29792,
        "baseline_bytes": 512,
        "handshake_note": "Very slow signing and a ~30 KB signature, but tiny "
                          "keys and conservative hash-based security. Suited to "
                          "infrequent, high-assurance firmware signing only.",
    },
    "AES-256-GCM": {
        "vs": "AES-128 / 3DES",
        "cpu_delta_pct": +40,
        "bytes_public_key": 0,
        "bytes_ciphertext": 0,
        "baseline_bytes": 0,
        "handshake_note": "AES-256 runs ~40% slower than AES-128 in software; "
                          "negligible with AES-NI hardware acceleration.",
    },
    "SHA-256": {
        "vs": "MD5 / SHA-1",
        "cpu_delta_pct": +60,
        "bytes_public_key": 0,
        "baseline_bytes": 0,
        "handshake_note": "Digest grows from 16/20 bytes to 32 bytes.",
    },
    "SHA3-512": {
        "vs": "SHA-256",
        "cpu_delta_pct": +110,
        "bytes_public_key": 0,
        "baseline_bytes": 0,
        "handshake_note": "Keccak is slower than SHA-2 in software but immune to "
                          "length-extension.",
    },
}

# --------------------------------------------------------------------------
# RISK SCORING PARAMETERS (Module 3) - exactly as specified in the design
# --------------------------------------------------------------------------
UNDERSIZED_KEY_PENALTY = 2.0        # base += 2 when key_size < min_safe_key
SENSITIVITY_MULTIPLIER = {
    "public": 0.8,
    "internal": 1.0,
    "financial": 1.5,
    "medical": 1.5,
    "government": 1.5,
    "defence": 1.6,
}
HNDL_MULTIPLIER = 1.3               # applied when lifespan > HNDL_LIFESPAN_YEARS
HNDL_LIFESPAN_YEARS = 5
SURFACE_WEIGHT = {                  # exposure weighting by where it was found
    "source_code": 1.00,
    "network": 1.10,                # observed on the wire = actively exploitable
    "config": 1.05,
    "dependency": 0.85,             # declared, not proven to be reachable
    "binary": 1.00,
}

RISK_CRITICAL_THRESHOLD = 8.0
RISK_HIGH_THRESHOLD = 5.0
RISK_MEDIUM_THRESHOLD = 2.0

# Effort estimation for the roadmap
EFFORT_MODEL = {
    PURPOSE_KEY_EXCHANGE: ("High", "Protocol-level change; both endpoints must "
                                   "support the new KEM. Plan a hybrid rollout."),
    PURPOSE_SIGNATURE: ("High", "Requires PKI re-issuance and verifier updates "
                                "across the whole trust chain."),
    PURPOSE_ENCRYPTION: ("Low", "Key-size / mode change local to the call site."),
    PURPOSE_HASHING: ("Medium", "Digest length changes; stored hashes must be "
                                "re-computed or dual-tracked."),
    PURPOSE_KDF: ("Medium", "Derived key lengths change downstream."),
    PURPOSE_MAC: ("Low", "Drop-in primitive replacement."),
    PURPOSE_RANDOM: ("Low", "Swap the entropy source."),
}

# --------------------------------------------------------------------------
# Scanner file-type routing (Module 1)
# --------------------------------------------------------------------------
SOURCE_EXTENSIONS = {".py", ".java", ".js", ".ts", ".cpp", ".c", ".h", ".go",
                     ".cs", ".rb", ".php", ".rs"}
CONFIG_FILENAMES = {"nginx.conf", "httpd.conf", "apache2.conf", ".env",
                    "docker-compose.yml", "docker-compose.yaml", "ssl.conf",
                    "openssl.cnf", "sshd_config", "web.config", "server.xml"}
CONFIG_EXTENSIONS = {".conf", ".cnf", ".ini", ".yml", ".yaml", ".toml",
                     ".properties", ".env"}
DEPENDENCY_FILENAMES = {"requirements.txt", "package.json", "package-lock.json",
                        "pom.xml", "build.gradle", "build.gradle.kts",
                        "Pipfile", "pyproject.toml", "Gemfile", "go.mod",
                        "Cargo.toml", "composer.json"}
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

MAX_FILE_BYTES = 2_000_000          # skip anything larger; avoids binary blobs
