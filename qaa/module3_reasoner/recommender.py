"""
Module 3b - Context-aware NIST recommendation, performance penalty estimation,
and replacement code snippet generation.

The recommendation is keyed on the *cryptographic purpose* rather than on the
algorithm name, which is what makes it context-aware. RSA used for key transport
migrates to ML-KEM (FIPS 203); RSA used to sign a JWT migrates to ML-DSA
(FIPS 204). A name-keyed mapping cannot make that distinction and would emit the
wrong standard for one of the two cases.
"""

from __future__ import annotations

from qaa.config import (
    ALGORITHM_DB,
    EFFORT_MODEL,
    MIGRATION_MAP,
    PERFORMANCE_MODEL,
    PURPOSE_ENCRYPTION,
    PURPOSE_HASHING,
    PURPOSE_KEY_EXCHANGE,
    PURPOSE_SIGNATURE,
)
from qaa.schema import RiskAssessment, SBOMEntry, ScanContext

HIGH_TIER_SENSITIVITY = {"financial", "medical", "government", "defence"}


def _tier(ctx: ScanContext) -> str:
    """High tier when the data is sensitive or the system is long-lived."""
    if ctx.data_sensitivity in HIGH_TIER_SENSITIVITY:
        return "high"
    if ctx.system_lifespan_years > 10:
        return "high"
    return "standard"


def recommend(entry: SBOMEntry, ctx: ScanContext) -> dict:
    """Return the NIST-aligned replacement for one CBOM entry."""
    meta = ALGORITHM_DB.get(entry.algorithm, ALGORITHM_DB["NONE"])
    purpose = entry.purpose or meta["purpose"]
    tier = _tier(ctx)

    rec = MIGRATION_MAP.get((purpose, tier))
    if rec is None:
        rec = MIGRATION_MAP.get((purpose, "standard")) or MIGRATION_MAP[
            (PURPOSE_ENCRYPTION, "standard")
        ]
    return dict(rec)


def performance_penalty(replacement: str) -> tuple[float, str]:
    """Expected overhead of a replacement, from published benchmark data."""
    p = PERFORMANCE_MODEL.get(replacement)
    if not p:
        return 0.0, "No published benchmark data for this replacement."
    delta = float(p["cpu_delta_pct"])
    direction = "faster than" if delta < 0 else "slower than"
    note = (f"CPU: ~{abs(delta):.0f}% {direction} {p['vs']}. "
            f"{p['handshake_note']}")
    if p.get("bytes_signature"):
        note += (f" Signature size {p['bytes_signature']} B vs "
                 f"{p['baseline_bytes']} B baseline.")
    elif p.get("bytes_ciphertext"):
        note += (f" Wire cost {p['bytes_public_key']} B public key + "
                 f"{p['bytes_ciphertext']} B ciphertext vs "
                 f"{p['baseline_bytes']} B baseline.")
    return delta, note


# ---------------------------------------------------------------------------
# Replacement code snippet templates
# ---------------------------------------------------------------------------
SNIPPETS: dict[tuple[str, str], str] = {
    (PURPOSE_KEY_EXCHANGE, "python"): '''# BEFORE - {old} key exchange (Shor-vulnerable)
# AFTER  - {new} per NIST {std}
#   pip install liboqs-python
import oqs

# --- Responder: generate an encapsulation keypair -------------------------
with oqs.KeyEncapsulation("{new}") as responder:
    public_key = responder.generate_keypair()

    # --- Initiator: encapsulate against the responder's public key --------
    with oqs.KeyEncapsulation("{new}") as initiator:
        ciphertext, shared_secret_initiator = initiator.encap_secret(public_key)

    shared_secret_responder = responder.decap_secret(ciphertext)

assert shared_secret_initiator == shared_secret_responder
# Transitional deployment: run {hybrid}
# so the session stays secure if either primitive is later broken.''',

    (PURPOSE_KEY_EXCHANGE, "java"): '''// BEFORE - {old} key exchange (Shor-vulnerable)
// AFTER  - {new} per NIST {std}
//   BouncyCastle 1.78+ : org.bouncycastle:bcprov-jdk18on
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
kpg.initialize(MLKEMParameterSpec.{spec});
KeyPair kp = kpg.generateKeyPair();

KeyGenerator kemGen = KeyGenerator.getInstance("ML-KEM", "BC");
kemGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"));
SecretKeyWithEncapsulation encapsulated =
        (SecretKeyWithEncapsulation) kemGen.generateKey();
byte[] sharedSecret = encapsulated.getEncoded();
// Transitional deployment: {hybrid}''',

    (PURPOSE_KEY_EXCHANGE, "javascript"): '''// BEFORE - {old} key exchange (Shor-vulnerable)
// AFTER  - {new} per NIST {std}
//   npm install mlkem
const {{ MlKem768 }} = require('mlkem');

const kem = new MlKem768();
const [encapsulationKey, decapsulationKey] = await kem.generateKeyPair();

// Initiator side
const [ciphertext, sharedSecretA] = await kem.encap(encapsulationKey);
// Responder side
const sharedSecretB = await kem.decap(ciphertext, decapsulationKey);
// Transitional deployment: {hybrid}''',

    (PURPOSE_SIGNATURE, "python"): '''# BEFORE - {old} signature (Shor-vulnerable)
# AFTER  - {new} per NIST {std}
#   pip install liboqs-python
import oqs

message = b"payload to authenticate"

with oqs.Signature("{new}") as signer:
    public_key = signer.generate_keypair()
    signature = signer.sign(message)

with oqs.Signature("{new}") as verifier:
    assert verifier.verify(message, signature, public_key)

# NOTE: {new} signatures are substantially larger than {old}.
# Check certificate chain sizes, MTU limits and any fixed-width
# database columns holding signatures before rolling this out.''',

    (PURPOSE_SIGNATURE, "java"): '''// BEFORE - {old} signature (Shor-vulnerable)
// AFTER  - {new} per NIST {std}
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
kpg.initialize(MLDSAParameterSpec.{spec});
KeyPair kp = kpg.generateKeyPair();

Signature signer = Signature.getInstance("ML-DSA", "BC");
signer.initSign(kp.getPrivate());
signer.update(message);
byte[] signature = signer.sign();

Signature verifier = Signature.getInstance("ML-DSA", "BC");
verifier.initVerify(kp.getPublic());
verifier.update(message);
boolean ok = verifier.verify(signature);''',

    (PURPOSE_SIGNATURE, "javascript"): '''// BEFORE - {old} signature (Shor-vulnerable)
// AFTER  - {new} per NIST {std}
//   npm install @noble/post-quantum
const {{ ml_dsa65 }} = require('@noble/post-quantum/ml-dsa');

const seed = crypto.getRandomValues(new Uint8Array(32));
const keys = ml_dsa65.keygen(seed);
const signature = ml_dsa65.sign(keys.secretKey, message);
const valid = ml_dsa65.verify(keys.publicKey, message, signature);''',

    (PURPOSE_ENCRYPTION, "python"): '''# BEFORE - {old} (Grover-weakened or classically broken)
# AFTER  - {new}, per {std}
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)   # 256-bit: ~128-bit post-Grover
aesgcm = AESGCM(key)
nonce = os.urandom(12)                      # never reuse a nonce with a key

ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
recovered = aesgcm.decrypt(nonce, ciphertext, associated_data)''',

    (PURPOSE_ENCRYPTION, "java"): '''// BEFORE - {old} (Grover-weakened or classically broken)
// AFTER  - {new}, per {std}
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256);
SecretKey key = keyGen.generateKey();

byte[] nonce = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(nonce);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
byte[] ciphertext = cipher.doFinal(plaintext);''',

    (PURPOSE_ENCRYPTION, "javascript"): '''// BEFORE - {old} (Grover-weakened or classically broken)
// AFTER  - {new}, per {std}
const crypto = require('crypto');

const key = crypto.randomBytes(32);   // 256-bit
const nonce = crypto.randomBytes(12);

const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const authTag = cipher.getAuthTag();''',

    (PURPOSE_HASHING, "python"): '''# BEFORE - {old} (collision-broken or Grover-weakened)
# AFTER  - {new}, per {std}
import hashlib

digest = hashlib.sha3_512(payload).hexdigest()   # or sha256 for standard tier

# MIGRATION NOTE: the digest length changes, so any stored hashes must be
# recomputed or dual-tracked during the transition. Fixed-width database
# columns holding the old digest need widening first.''',

    (PURPOSE_HASHING, "java"): '''// BEFORE - {old} (collision-broken or Grover-weakened)
// AFTER  - {new}, per {std}
MessageDigest digest = MessageDigest.getInstance("SHA3-512");
byte[] out = digest.digest(payload);
// Digest length changes - widen any fixed-width storage before migrating.''',

    (PURPOSE_HASHING, "javascript"): '''// BEFORE - {old} (collision-broken or Grover-weakened)
// AFTER  - {new}, per {std}
const crypto = require('crypto');
const digest = crypto.createHash('sha3-512').update(payload).digest('hex');''',
}

# BouncyCastle parameter-spec constant names
BC_SPEC = {
    "ML-KEM-768": "ml_kem_768", "ML-KEM-1024": "ml_kem_1024",
    "ML-DSA-65": "ml_dsa_65", "ML-DSA-87": "ml_dsa_87",
}

LANGUAGE_ALIAS = {
    "python": "python", "java": "java", "javascript": "javascript",
    "typescript": "javascript", "js": "javascript", "ts": "javascript",
    "cpp": "python", "c": "python", "go": "python", "csharp": "java",
    "rust": "python", "php": "javascript", "tls": "python",
}


def generate_snippet(entry: SBOMEntry, rec: dict) -> tuple[str, str]:
    """Produce replacement initialisation code for the finding's language."""
    lang = LANGUAGE_ALIAS.get((entry.finding.language or "").lower(), "python")
    purpose = entry.purpose

    template = SNIPPETS.get((purpose, lang))
    if template is None:
        template = SNIPPETS.get((purpose, "python"))
    if template is None:
        template = SNIPPETS[(PURPOSE_ENCRYPTION, "python")]

    body = template.format(
        old=entry.algorithm,
        new=rec["replacement"],
        std=rec["standard"],
        hybrid=rec["hybrid"],
        spec=BC_SPEC.get(rec["replacement"], "ml_kem_768"),
    )

    header = (f"# Target: {entry.finding.file_path}:"
              f"{entry.finding.line_number}\n")
    if lang in ("java", "javascript"):
        header = header.replace("#", "//")
    return header + body, lang


def assess(entry: SBOMEntry, ctx: ScanContext) -> RiskAssessment:
    """Full Module 3 pipeline for a single CBOM entry."""
    from .risk_engine import score_entry

    score, level, breakdown = score_entry(entry, ctx)
    rec = recommend(entry, ctx)
    delta, perf_note = performance_penalty(rec["replacement"])
    effort, effort_note = EFFORT_MODEL.get(entry.purpose, ("Medium", ""))
    snippet, snippet_lang = generate_snippet(entry, rec)

    return RiskAssessment(
        sbom_entry=entry,
        risk_score=score,
        risk_level=level,
        score_breakdown=breakdown,
        replacement=rec["replacement"],
        nist_standard=rec["standard"],
        hybrid_option=rec["hybrid"],
        recommended_library=rec["library"],
        nist_level=rec["nist_level"],
        performance_note=perf_note,
        performance_delta_pct=delta,
        effort=effort,
        effort_note=effort_note,
        code_snippet=snippet,
        snippet_language=snippet_lang,
    )


def build_roadmap(entries: list[SBOMEntry], ctx: ScanContext
                  ) -> list[RiskAssessment]:
    """Assess every entry and return them ordered Critical-first."""
    assessments = [assess(e, ctx) for e in entries]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
             "Informational": 4}
    # Sort on the uncapped score so findings that saturate the 0-10 band are
    # still ordered relative to one another.
    assessments.sort(key=lambda a: (
        order.get(a.risk_level, 9),
        -a.score_breakdown.get("raw_score", a.risk_score),
        -a.risk_score,
    ))
    return assessments
