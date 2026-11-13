"""Already migrated to post-quantum primitives - should score Informational."""
import oqs


def establish_pq_session():
    with oqs.KeyEncapsulation("ML-KEM-768") as responder:
        public_key = responder.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as initiator:
            ciphertext, shared = initiator.encap_secret(public_key)
        return responder.decap_secret(ciphertext), shared
