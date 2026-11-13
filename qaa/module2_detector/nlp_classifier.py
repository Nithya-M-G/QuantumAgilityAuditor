"""
Module 2 Stage 1 - NLP cryptographic classifier.

Pipeline
--------
    FeatureUnion
      |- TfidfVectorizer(word,  1-2 grams)   lexical API shape
      |- TfidfVectorizer(char_wb, 3-5 grams) sub-token robustness
    -> SVM

Two SVM back-ends are supported:

    "rbf"    - SVC(kernel='rbf', probability=True). This is the configuration
               named in the project design document.
    "linear" - LinearSVC wrapped in CalibratedClassifierCV. Trains an order of
               magnitude faster on high-dimensional sparse TF-IDF and is usually
               at least as accurate on this kind of data.

Both expose predict_proba, which Module 2 needs for the confidence column and
which LIME requires for the explainability panel.

A deterministic-prior fusion step combines the classifier probability with the
Module 1 detector hint. Rationale: when a Python AST walker has *proved* that a
call resolves to `rsa.generate_private_key`, that is stronger evidence than any
text classifier, and the SBOM should say so. When Module 1 only has a weak regex
hint, the classifier dominates. The fusion weight is a function of which
detector produced the finding.
"""

from __future__ import annotations

import re

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import SVC, LinearSVC

from qaa.config import (
    ALGORITHM_DB,
    NLP_MODEL_PATH,
)
from qaa.schema import Finding, SBOMEntry

from .lexicon_features import CryptoLexiconVectorizer

# How much to trust the Module 1 deterministic hint, by detector.
DETECTOR_PRIOR_WEIGHT = {
    "ast": 0.70,          # resolved through imports - very strong evidence
    "pcap": 0.75,         # IANA registry lookup - effectively ground truth
    "dependency": 0.55,   # manifest name match - strong but coarse
    "config": 0.45,       # cipher-suite string - moderately strong
    "regex": 0.35,        # API-shaped pattern - the classifier should lead
}


_SNAKE = re.compile(r"_+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def split_identifiers(text: str) -> str:
    """
    Expand compound identifiers into their subwords, keeping the original.

        MD5_CTX          -> MD5_CTX md5 ctx
        EVP_des_ede3_cbc -> EVP_des_ede3_cbc evp des ede3 cbc
        generateKeyPair  -> generateKeyPair generate Key Pair
        RSAKey           -> RSAKey RSA Key

    Letter/digit boundaries are deliberately NOT split: "md5" must stay "md5",
    not become "md 5", or the algorithm name is destroyed by the tokeniser.

    Without this the word vectorizer tokenises MD5_CTX as the single unseen
    token "md5_ctx" and never sees "md5" at all, which is why an OpenSSL-style
    MD5 snippet was classified as NONE when its template family was held out.
    Subword splitting of identifiers is standard practice for ML on source code.
    """
    if not text:
        return ""
    pieces = [text]
    for token in set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)):
        if "_" in token or _CAMEL.search(token):
            parts = _SNAKE.split(token)
            parts = [q for p in parts for q in _CAMEL.split(p)]
            pieces.extend(p for p in parts if p)
    return " ".join(pieces).lower()


def build_pipeline(kernel: str = "linear", C: float = 4.0,
                   random_state: int = 42) -> Pipeline:
    """Construct the (untrained) Module 2 Stage-1 pipeline."""
    features = FeatureUnion([
        # Domain-informed marker block. The high transformer weight is
        # deliberate and empirically justified - see lexicon_features.py for
        # the measured failure it corrects.
        ("lexicon", CryptoLexiconVectorizer(strip_comments=True)),
        ("word", TfidfVectorizer(
            analyzer="word",
            token_pattern=r"[A-Za-z_][A-Za-z0-9_]+|\d+",
            ngram_range=(1, 2),
            lowercase=True,
            preprocessor=split_identifiers,
            sublinear_tf=True,
            min_df=1,
            max_features=60_000,
        )),
        ("char", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            lowercase=True,
            sublinear_tf=True,
            min_df=2,
            max_features=120_000,
        )),
    ], transformer_weights={"lexicon": 3.0, "word": 1.0, "char": 0.6})

    if kernel == "rbf":
        clf = SVC(kernel="rbf", C=C, gamma="scale", probability=True,
                  class_weight="balanced", random_state=random_state)
    else:
        base = LinearSVC(C=C, class_weight="balanced",
                         random_state=random_state, max_iter=20000)
        clf = CalibratedClassifierCV(base, method="sigmoid", cv=5)

    return Pipeline([("features", features), ("clf", clf)])


class CryptoNLPClassifier:
    """Trained-model wrapper used at scan time."""

    def __init__(self, pipeline: Pipeline, labels: list[str],
                 metadata: dict | None = None):
        self.pipeline = pipeline
        self.labels = list(labels)
        self.metadata = metadata or {}

    # ---------------- persistence ----------------
    @classmethod
    def load(cls, path=None) -> "CryptoNLPClassifier":
        path = path or NLP_MODEL_PATH
        blob = joblib.load(path)
        return cls(blob["pipeline"], blob["labels"], blob.get("metadata", {}))

    def save(self, path=None) -> None:
        path = path or NLP_MODEL_PATH
        joblib.dump({"pipeline": self.pipeline, "labels": self.labels,
                     "metadata": self.metadata}, path)

    # ---------------- inference ----------------
    def predict_proba(self, texts: list[str]) -> np.ndarray:
        return self.pipeline.predict_proba(texts)

    def predict_one(self, text: str) -> tuple[str, float, dict[str, float]]:
        proba = self.pipeline.predict_proba([text])[0]
        classes = list(self.pipeline.classes_)
        idx = int(np.argmax(proba))
        vector = {c: float(p) for c, p in zip(classes, proba)}
        return classes[idx], float(proba[idx]), vector

    # ---------------- fusion with Module 1 ----------------
    def classify_finding(self, finding: Finding) -> SBOMEntry:
        """
        Classify one Module-1 finding into a CBOM entry.

        Fuses the classifier posterior with the deterministic detector hint.
        """
        text = finding.snippet or finding.matched_pattern
        classes = list(self.pipeline.classes_)
        proba = self.pipeline.predict_proba([text])[0]
        vector = {c: float(p) for c, p in zip(classes, proba)}

        hint = finding.hint_algorithm
        method = "nlp_classifier"

        if hint and hint in ALGORITHM_DB:
            w = DETECTOR_PRIOR_WEIGHT.get(finding.detector, 0.4)
            # Blend: shift probability mass toward the deterministic hint.
            for c in vector:
                vector[c] *= (1.0 - w)
            vector[hint] = vector.get(hint, 0.0) + w
            total = sum(vector.values()) or 1.0
            vector = {c: p / total for c, p in vector.items()}
            method = f"{finding.detector}+nlp_fused"

        algorithm = max(vector, key=vector.get)
        confidence = vector[algorithm]

        # A concrete deterministic hint is never overridden all the way to
        # "no cryptography here". Module 1's config and manifest patterns are
        # curated and precise, whereas the classifier was trained on code
        # snippets and is out-of-distribution on an sshd_config line or a
        # Maven coordinate. Letting a low-confidence NONE win there produced a
        # measured false negative on `HostKeyAlgorithms ssh-rsa,...`.
        if algorithm == "NONE" and hint and hint != "NONE" and hint in ALGORITHM_DB:
            algorithm = hint
            confidence = max(vector.get(hint, 0.0),
                             DETECTOR_PRIOR_WEIGHT.get(finding.detector, 0.4))
            method = f"{finding.detector}_hint_retained"

        # Algorithms Module 1 can name but the classifier has no class for
        # (X25519, ED25519, ECC variants, ML-DSA, SLH-DSA) pass straight through.
        if hint and hint not in classes and hint in ALGORITHM_DB:
            algorithm = hint
            confidence = max(confidence, DETECTOR_PRIOR_WEIGHT.get(
                finding.detector, 0.4) + 0.35)
            confidence = min(confidence, 0.99)
            method = f"{finding.detector}_deterministic"

        meta = ALGORITHM_DB.get(algorithm, ALGORITHM_DB["NONE"])
        return SBOMEntry(
            finding=finding,
            algorithm=algorithm,
            confidence=confidence,
            purpose=meta["purpose"],
            threat_class=meta["threat"],
            detection_method=method,
            probability_vector=dict(sorted(vector.items(),
                                           key=lambda kv: -kv[1])[:6]),
        )

    def classify_all(self, findings: list[Finding]) -> list[SBOMEntry]:
        return [self.classify_finding(f) for f in findings]
