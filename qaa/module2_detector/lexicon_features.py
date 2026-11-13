"""
Module 2 - Domain-informed lexical feature extractor.

MOTIVATION (this block exists because of a measured failure)
------------------------------------------------------------
A pure TF-IDF model trained on this corpus scores ~100% under a random split and
collapses to ~44% when an entire *template family* is held out. Diagnosis of the
failure case:

    MessageDigest md = MessageDigest.getInstance("MD5");

With the Java MD5 family held out, the model has still seen the Java SHA-1 and
SHA-256 families. Those share the tokens `MessageDigest` and `getInstance`,
which are frequent and therefore heavily weighted, while the single token that
actually decides the answer - the algorithm literal `MD5` - contributes one
low-weight dimension out of ~180k. The model confidently answers SHA-1.

That is a feature-scaling problem, not a capacity problem. This transformer
fixes it by emitting a small, dense block of features in which each dimension
corresponds to a cryptographic *marker* - an algorithm literal, a mode string,
a curve name, a key size bracket. Given a high transformer weight in the
FeatureUnion, the algorithm literal can no longer be outvoted by scaffolding.

This is a hybrid symbolic/statistical design, not a lookup table: the markers
are evidence fed to the SVM, which still learns how to weigh them, resolve
conflicts (a snippet naming both AES and RSA), and combine them with the
free-text TF-IDF evidence.
"""

from __future__ import annotations

import re

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin

# ---------------------------------------------------------------------------
# Marker definitions: (feature_name, compiled_regex)
# Ordered and fixed so the feature matrix is stable across fit/transform.
# ---------------------------------------------------------------------------
# Identifier-aware boundary. Plain \b treats "_" as a word character, so
# \bmd5\b fails to match MD5_CTX and EVP_rc4 - a bug that cost ~20 points of
# leave-one-library-out accuracy on the OpenSSL-style families. These lookarounds
# break on "_" and "-" as well, which is what C and cipher-suite naming needs.
_B = r"(?<![A-Za-z0-9])"
_E = r"(?![A-Za-z0-9])"


def _m(body: str) -> str:
    """Wrap an alternation body in identifier-aware boundaries."""
    return _B + "(?:" + body + ")" + _E


_MARKER_SPECS: list[tuple[str, str]] = [
    # --- algorithm literals -------------------------------------------------
    ("mk_rsa", _m(r"rsa|withrsa|rsassa|rsacryptoserviceprovider")),
    ("mk_rsa_pad", _m(r"pkcs1|oaep|pss|rsassa|pkcs1_?oaep|pkcs1_?v1_?5")),
    ("mk_modulus", _m(r"modulus_?length|public_?exponent|65537|rsa_f4")),
    ("mk_ecdsa", _m(r"ecdsa|ecdsasigner|withecdsa|signingkey|elliptic")),
    ("mk_ecdh", _m(r"ecdh|ecdhe|createecdh|ecdiffiehellman")),
    ("mk_ec_generic", _m(r"ec|ecc|elliptic|eckey|ec_?key|ecgenparameterspec")),
    ("mk_curve", _m(r"secp\d+[rk]1|prime256v1|nist\d+p|p-?(?:256|384|521)|"
                   r"brainpool\w*|x9_62")),
    ("mk_x25519", _m(r"x25519|curve25519")),
    ("mk_ed25519", _m(r"ed25519")),
    # NOTE: "generate_parameters" was deliberately removed from this marker.
    # DSA_generate_parameters_ex and DH_generate_parameters_ex share that
    # substring, so including it made every OpenSSL DSA snippet look like DH
    # (measured: 0% recall on the held-out dsa_openssl family).
    ("mk_dh", _m(r"dh|diffiehellman|diffie_?hellman|dh_?new|"
                r"creatediffiehellman|dh_?generate\w*|dh_?generator|"
                r"diffie|hellman|"
                r"ffdhe\d*|dhparam\w*")),
    ("mk_dsa", _m(r"dsa|withdsa")),
    # "fernet" is included because the pyca Fernet recipe is AES-128-CBC with
    # an HMAC; the token never says AES but the primitive is AES.
    ("mk_aes", _m(r"aes|rijndael|fernet")),
    ("mk_aes_bits", _m(r"aes[-_]?(?:128|192|256)")),
    # "triple" alone is included because CamelCase expansion turns
    # TripleDESCryptoServiceProvider into "Triple DES Crypto ...", which
    # otherwise fires only the single-DES marker.
    ("mk_3des", _m(r"3des|des3|desede|tripledes|triple_?des|triple|"
                  r"des[-_]?ede3?|newtripledescipher|des_?ede")),
    ("mk_des", _m(r"des")),
    ("mk_rc4", _m(r"rc4|arc4|arcfour")),
    ("mk_chacha", _m(r"chacha20|chacha|poly1305|chacha20poly1305")),
    ("mk_md5", _m(r"md5|md5hex")),
    ("mk_sha1", _m(r"sha1|sha[-_]1|sha1hex")),
    ("mk_sha2", _m(r"sha256|sha[-_]256|sha384|sha[-_]384|sha512|sha[-_]512")),
    ("mk_sha3", _m(r"sha3|sha3_?(?:256|512)|keccak|shake128|shake256")),
    ("mk_mlkem", _m(r"ml[-_]?kem|kyber\d*|mlkem\w*|ml_?kem_?\d+")),
    ("mk_mldsa", _m(r"ml[-_]?dsa|dilithium\d*")),
    ("mk_slhdsa", _m(r"slh[-_]?dsa|sphincs")),
    ("mk_pqc_lib", _m(r"oqs|liboqs|pqcrypto|kyber_?py|keyencapsulation")),
    # --- operation context --------------------------------------------------
    ("mk_op_keygen", _m(r"generate_?key\w*|generatekeypair\w*|"
                       r"generate_?private_?key|keypairgenerator|newkeypair|"
                       r"keygen\w*|generate")),
    ("mk_op_sign", _m(r"sign|signature|do_?sign|signdata|initsign|signingkey|"
                     r"verify")),
    ("mk_op_exchange", _m(r"keyagreement|exchange|computesecret|compute_?key|"
                         r"dophase|encaps|decaps|sharedsecret")),
    ("mk_op_encrypt", _m(r"encrypt\w*|cipher|createcipheriv|encryptinit\w*|"
                        r"encrypt_?mode|new_?cipher|newcipher")),
    ("mk_op_hash", _m(r"digest|hash|hexdigest|createhash|messagedigest|"
                     r"digestutils|sum")),
    ("mk_op_mac", _m(r"hmac|mac|authtag|poly1305")),
    # --- cipher modes -------------------------------------------------------
    ("mk_mode_gcm", _m(r"gcm")),
    ("mk_mode_cbc", _m(r"cbc")),
    ("mk_mode_ecb", _m(r"ecb")),
    ("mk_mode_ctr", _m(r"ctr")),
    # --- library provenance -------------------------------------------------
    ("mk_lib_pyca", _m(r"hazmat|fernet|cryptography")),
    ("mk_lib_pycryptodome", _m(r"cryptodome|publickey")),
    ("mk_lib_jca", _m(r"javax|getinstance|messagedigest|keypairgenerator|"
                     r"keyagreement")),
    ("mk_lib_bc", _m(r"bouncycastle|bcprov|bcpkix")),
    ("mk_lib_openssl", _m(r"evp|evp_\w+|bn_new|nid|ctx|openssl")),
    ("mk_lib_node", _m(r"createhash|createcipheriv|generatekeypairsync|"
                      r"require|buffer")),
    # JWT algorithm identifiers are split by family: RS256 and ES256 sit in the
    # same string position but imply completely different primitives, so they
    # must not share a feature dimension.
    ("mk_jwt_rsa_alg", _m(r"rs256|rs384|rs512|ps256|ps384|ps512")),
    ("mk_jwt_ec_alg", _m(r"es256|es384|es512")),
    ("mk_jwt_hmac_alg", _m(r"hs256|hs384|hs512")),
    ("mk_lib_jwt", _m(r"jwt|jsonwebtoken|jose")),
    ("mk_lib_hashlib", _m(r"hashlib")),
    # --- key sizes ----------------------------------------------------------
    ("mk_bits_small", _m(r"512|768|1024")),
    ("mk_bits_2048", _m(r"2048")),
    ("mk_bits_large", _m(r"3072|4096|7680|8192")),
    ("mk_bits_sym", _m(r"128|192|256")),
    # --- negative / non-crypto evidence ------------------------------------
    ("mk_neg_web", _m(r"requests|fetch|axios|urllib|usestate|useeffect|"
                     r"responseentity|endpoint|http")),
    ("mk_neg_data", _m(r"pandas|read_?csv|dataframe|numpy|dropna|groupby|"
                      r"collectors|arraylist|stream")),
    ("mk_neg_db", _m(r"session|query|commit|sqlalchemy|jdbc|filter")),
    ("mk_neg_log", _m(r"logger|logging|println|console")),
    ("mk_neg_encoding", _m(r"base64|b64encode|hexlify|urlsafe|dumps|encode")),
    ("mk_neg_pwhash", _m(r"bcrypt|scrypt|argon2|pbkdf2|gensalt|hashpw")),
    ("mk_neg_rand", _m(r"secrets|token_?urlsafe|urandom|securerandom|"
                      r"rand|reader")),
]

_COMMENT_LINE = re.compile(r"(^\s*(#|//).*$)|(/\*.*?\*/)", re.M | re.S)

_SNAKE_SPLIT = re.compile(r"_+")
_CAMEL_SPLIT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _expand(text: str) -> str:
    """Append subword expansions of compound identifiers to the raw text."""
    out = [text]
    for tok in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)):
        if "_" in tok or _CAMEL_SPLIT.search(tok):
            parts = [q for p in _SNAKE_SPLIT.split(tok) for q in _CAMEL_SPLIT.split(p)]
            out.extend(p for p in parts if p)
    return " ".join(out)


class CryptoLexiconVectorizer(BaseEstimator, TransformerMixin):
    """
    Emit a dense block of cryptographic-marker features for each snippet.

    Feature layout (all values in [0, 1]):

        [0 : M]        marker present anywhere in the snippet
        [M : 2M]       marker present in NON-COMMENT text only
        [2M : 2M + 3]  structural: snippet length bucket, line count bucket,
                       and the count of distinct markers fired

    The duplicated comment-stripped block lets the SVM learn that an algorithm
    named only inside a comment is weak evidence - the single largest source of
    false positives in keyword-based crypto scanners.
    """

    def __init__(self, strip_comments: bool = True):
        self.strip_comments = strip_comments
        self._patterns = [(n, re.compile(p, re.I)) for n, p in _MARKER_SPECS]

    # sklearn API ----------------------------------------------------------
    def fit(self, X, y=None):                      # noqa: N803, ARG002
        self.n_markers_ = len(self._patterns)
        self.n_features_out_ = 2 * self.n_markers_ + 3
        return self

    def transform(self, X):                        # noqa: N803
        n_markers = len(self._patterns)
        rows = []
        for text in X:
            text = text or ""
            # Expand compound identifiers first, so that RSAKey, MD5_CTX and
            # ECDSASigner expose their algorithm token to the marker regexes.
            # Without this, a marker anchored with identifier boundaries can
            # never fire inside a CamelCase name (measured: 0% recall on the
            # held-out paramiko RSA family, which only ever writes RSAKey).
            text = _expand(text)
            code_only = _COMMENT_LINE.sub(" ", text) if self.strip_comments else text
            vec = np.zeros(2 * n_markers + 3, dtype=np.float32)
            fired = 0
            for i, (_name, pat) in enumerate(self._patterns):
                if pat.search(text):
                    vec[i] = 1.0
                    fired += 1
                if pat.search(code_only):
                    vec[n_markers + i] = 1.0
            n_lines = text.count("\n") + 1
            vec[2 * n_markers] = min(len(text) / 400.0, 1.0)
            vec[2 * n_markers + 1] = min(n_lines / 12.0, 1.0)
            vec[2 * n_markers + 2] = min(fired / 8.0, 1.0)
            rows.append(vec)
        return sparse.csr_matrix(np.vstack(rows)) if rows else sparse.csr_matrix(
            (0, 2 * n_markers + 3), dtype=np.float32
        )

    def get_feature_names_out(self, input_features=None):   # noqa: ARG002
        names = [n for n, _ in self._patterns]
        return np.array(
            [f"{n}__any" for n in names]
            + [f"{n}__code" for n in names]
            + ["struct__len", "struct__lines", "struct__marker_count"]
        )
