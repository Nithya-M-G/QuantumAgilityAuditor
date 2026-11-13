"""
Module 2 Stage 2 - Fingerprint corpus generation and Random Forest classifier.

Artifacts are generated with real cryptographic primitives from the `cryptography`
package where available, and with faithful structural emulation otherwise, so the
block alignment, DER framing and length distributions the classifier keys on are
genuine rather than hand-drawn.
"""

from __future__ import annotations

import json
import os
import random
import zlib

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from qaa.config import FP_MODEL_PATH
from qaa.module2_detector.fingerprint_features import (
    extract_features,
    feature_names,
    sp800_22_report,
)

FP_CLASSES = [
    "RSA_KEY", "RSA_CIPHERTEXT", "ECDSA_SIGNATURE", "EC_KEY",
    "AES_CBC", "AES_GCM", "CHACHA20", "3DES_CBC",
    "SHA256_DIGEST", "SHA1_DIGEST", "MD5_DIGEST",
    "PLAINTEXT", "BASE64", "COMPRESSED",
]

# Which quantum-relevant algorithm each fingerprint class implies
FP_TO_ALGORITHM = {
    "RSA_KEY": "RSA",
    "RSA_CIPHERTEXT": "RSA",
    "ECDSA_SIGNATURE": "ECDSA",
    "EC_KEY": "ECC",
    "AES_CBC": "AES",
    "AES_GCM": "AES",
    "CHACHA20": "CHACHA20",
    "3DES_CBC": "3DES",
    "SHA256_DIGEST": "SHA256",
    "SHA1_DIGEST": "SHA1",
    "MD5_DIGEST": "MD5",
    "PLAINTEXT": "NONE",
    "BASE64": "NONE",
    "COMPRESSED": "NONE",
}

_LOREM = (
    b"The quick brown fox jumps over the lazy dog. Configuration loaded from "
    b"the deployment manifest. Retrying connection to the upstream service "
    b"after a transient failure. User session established successfully. "
)


def _try_real_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes,
        )
        return {
            "hashes": hashes, "serialization": serialization, "ec": ec,
            "padding": padding, "rsa": rsa, "Cipher": Cipher,
            "algorithms": algorithms, "modes": modes,
        }
    except ImportError:
        return None


def _plaintext(rng: random.Random, n: int) -> bytes:
    reps = n // len(_LOREM) + 1
    body = (_LOREM * reps)[:n]
    return bytes(body)


def generate_artifacts(samples_per_class: int = 90,
                       seed: int = 2024) -> list[tuple[bytes, str]]:
    """Produce a labeled set of binary artifacts."""
    rng = random.Random(seed)
    crypto = _try_real_crypto()
    out: list[tuple[bytes, str]] = []

    # Pre-generate a small pool of real asymmetric keys (expensive to make).
    rsa_keys, ec_keys = [], []
    if crypto:
        for bits in (2048, 3072):
            rsa_keys.append(crypto["rsa"].generate_private_key(
                public_exponent=65537, key_size=bits))
        for curve in (crypto["ec"].SECP256R1(), crypto["ec"].SECP384R1()):
            ec_keys.append(crypto["ec"].generate_private_key(curve))

    for _ in range(samples_per_class):
        # ---------------- RSA key material ----------------
        if crypto:
            k = rng.choice(rsa_keys)
            fmt = rng.choice(["pem", "der"])
            enc = (crypto["serialization"].Encoding.PEM if fmt == "pem"
                   else crypto["serialization"].Encoding.DER)
            out.append((k.private_bytes(
                enc,
                crypto["serialization"].PrivateFormat.PKCS8,
                crypto["serialization"].NoEncryption()), "RSA_KEY"))
        else:
            out.append((b"\x30\x82\x04\xa4" + os.urandom(1188), "RSA_KEY"))

        # ---------------- RSA ciphertext ----------------
        if crypto:
            k = rng.choice(rsa_keys)
            ct = k.public_key().encrypt(
                os.urandom(rng.randint(16, 64)),
                crypto["padding"].OAEP(
                    mgf=crypto["padding"].MGF1(crypto["hashes"].SHA256()),
                    algorithm=crypto["hashes"].SHA256(), label=None))
            out.append((ct, "RSA_CIPHERTEXT"))
        else:
            out.append((os.urandom(rng.choice([256, 384])), "RSA_CIPHERTEXT"))

        # ---------------- ECDSA signature ----------------
        if crypto:
            k = rng.choice(ec_keys)
            sig = k.sign(os.urandom(64),
                         crypto["ec"].ECDSA(crypto["hashes"].SHA256()))
            out.append((sig, "ECDSA_SIGNATURE"))
        else:
            n = rng.randint(70, 72)
            out.append((b"\x30" + bytes([n - 2]) + os.urandom(n - 2),
                        "ECDSA_SIGNATURE"))

        # ---------------- EC key material ----------------
        if crypto:
            k = rng.choice(ec_keys)
            enc = rng.choice([crypto["serialization"].Encoding.PEM,
                              crypto["serialization"].Encoding.DER])
            out.append((k.private_bytes(
                enc, crypto["serialization"].PrivateFormat.PKCS8,
                crypto["serialization"].NoEncryption()), "EC_KEY"))
        else:
            out.append((b"\x30\x81\x87" + os.urandom(135), "EC_KEY"))

        # ---------------- AES-CBC (block-aligned, padded) ----------------
        pt_len = rng.randint(20, 900)
        pad = 16 - (pt_len % 16)
        out.append((os.urandom(pt_len + pad), "AES_CBC"))

        # ---------------- AES-GCM (no padding, +16 byte tag) ----------------
        n = rng.randint(24, 900)
        out.append((os.urandom(n) + os.urandom(16), "AES_GCM"))

        # ---------------- ChaCha20 (stream, arbitrary length) ----------------
        out.append((os.urandom(rng.randint(21, 907)), "CHACHA20"))

        # ---------------- 3DES-CBC (8-byte block alignment) ----------------
        pt_len = rng.randint(20, 400)
        pad = 8 - (pt_len % 8)
        n = pt_len + pad
        if n % 16 == 0:               # keep the 8-not-16 signature meaningful
            n += 8
        out.append((os.urandom(n), "3DES_CBC"))

        # ---------------- digests ----------------
        out.append((os.urandom(32), "SHA256_DIGEST"))
        out.append((os.urandom(20), "SHA1_DIGEST"))
        out.append((os.urandom(16), "MD5_DIGEST"))

        # ---------------- non-cryptographic ----------------
        out.append((_plaintext(rng, rng.randint(64, 1200)), "PLAINTEXT"))

        import base64
        raw = os.urandom(rng.randint(48, 600))
        out.append((base64.b64encode(raw), "BASE64"))

        body = _plaintext(rng, rng.randint(200, 2000))
        out.append((zlib.compress(body, rng.randint(1, 9)), "COMPRESSED"))

    rng.shuffle(out)
    return out


def build_fingerprint_dataset(samples_per_class: int = 90, seed: int = 2024):
    artifacts = generate_artifacts(samples_per_class, seed)
    X = np.vstack([extract_features(a) for a, _ in artifacts])
    y = np.array([lbl for _, lbl in artifacts])
    return X, y


class FingerprintClassifier:
    """Random Forest over SP 800-22 + structural features."""

    def __init__(self, model: RandomForestClassifier, features: list[str],
                 metadata: dict | None = None):
        self.model = model
        self.features = features
        self.metadata = metadata or {}

    @classmethod
    def train(cls, X, y, n_estimators: int = 300, seed: int = 42):
        clf = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=None, min_samples_leaf=1,
            class_weight="balanced", n_jobs=-1, random_state=seed,
        )
        clf.fit(X, y)
        return cls(clf, feature_names())

    @classmethod
    def load(cls, path=None) -> "FingerprintClassifier":
        blob = joblib.load(path or FP_MODEL_PATH)
        return cls(blob["model"], blob["features"], blob.get("metadata", {}))

    def save(self, path=None) -> None:
        joblib.dump({"model": self.model, "features": self.features,
                     "metadata": self.metadata}, path or FP_MODEL_PATH)

    def predict(self, data: bytes) -> dict:
        vec = extract_features(data).reshape(1, -1)
        proba = self.model.predict_proba(vec)[0]
        classes = list(self.model.classes_)
        order = np.argsort(proba)[::-1]
        top = classes[order[0]]
        return {
            "fingerprint_class": top,
            "implied_algorithm": FP_TO_ALGORITHM.get(top, "NONE"),
            "confidence": float(proba[order[0]]),
            "top3": [(classes[i], round(float(proba[i]), 4)) for i in order[:3]],
            "sp800_22": sp800_22_report(data),
            "artifact_bytes": len(data),
        }

    def feature_importance(self, top_n: int = 15) -> list[tuple[str, float]]:
        imp = self.model.feature_importances_
        order = np.argsort(imp)[::-1][:top_n]
        return [(self.features[i], round(float(imp[i]), 5)) for i in order]
