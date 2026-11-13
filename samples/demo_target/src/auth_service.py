"""Legacy authentication service - target for the Quantum-Agility Auditor."""
import hashlib
import os

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_backend
from cryptography.hazmat.primitives.asymmetric import ec


class TokenIssuer:
    """Issues and verifies session tokens for the customer portal."""

    def provision(self):
        # Aliased import: a keyword scanner looking for "rsa.generate" misses this.
        self._signing = _rsa_backend.generate_private_key(
            public_exponent=65537, key_size=1024
        )
        return self._signing

    def issue(self, claims):
        pem = self._signing.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="RS256")

    def sign_receipt(self, message):
        return self._signing.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )


def derive_session(peer_public_key):
    """Ephemeral key agreement for the mobile channel."""
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    return ephemeral.exchange(ec.ECDH(), peer_public_key)


def legacy_checksum(payload):
    # TODO(SEC-4412): replace before the 2026 audit
    return hashlib.md5(payload).hexdigest()


def password_fingerprint(password, salt):
    return hashlib.sha1(salt + password.encode()).hexdigest()


def new_request_id():
    # Hard negative: CSPRNG token, no algorithm choice to migrate.
    return os.urandom(16).hex()
