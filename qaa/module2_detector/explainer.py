"""
Module 2 - LIME explainability layer.

Produces a token-level attribution for any classifier decision: which parts of
the snippet pushed the model toward the predicted algorithm, and which pushed
against it. This is what the dashboard's explanation panel renders, and it is
the part of the pipeline that turns "the model says RSA, confidence 0.94" into
an auditable claim a security reviewer can check.

LIME is used rather than raw SVM coefficients because the pipeline is a
FeatureUnion of three heterogeneous blocks (marker features, word TF-IDF, char
TF-IDF). A single coefficient vector over that union is not human-readable,
whereas LIME perturbs the *original text* and reports attributions in terms the
reviewer can see in their own source file.
"""

from __future__ import annotations

from functools import lru_cache

from qaa.schema import SBOMEntry


class LimeCryptoExplainer:
    """Thin wrapper around lime.lime_text.LimeTextExplainer."""

    def __init__(self, classifier, num_features: int = 10,
                 num_samples: int = 400):
        self.classifier = classifier
        self.num_features = num_features
        self.num_samples = num_samples
        self._explainer = None

    def _ensure(self):
        if self._explainer is None:
            try:
                from lime.lime_text import LimeTextExplainer
            except ImportError as exc:
                raise RuntimeError(
                    "LIME is not installed. Run: pip install lime"
                ) from exc
            self._explainer = LimeTextExplainer(
                class_names=list(self.classifier.pipeline.classes_),
                bow=False,                 # keep token positions meaningful
                split_expression=r"\W+",
                random_state=42,
            )
        return self._explainer

    def explain(self, text: str, label: str | None = None
                ) -> list[tuple[str, float]]:
        """
        Return [(token, weight), ...] for the predicted (or requested) class.

        Positive weight  = token pushed the model TOWARD this class.
        Negative weight  = token pushed AWAY from it.
        """
        explainer = self._ensure()
        classes = list(self.classifier.pipeline.classes_)
        target = label if label in classes else None
        if target is None:
            target = self.classifier.predict_one(text)[0]
        idx = classes.index(target)

        exp = explainer.explain_instance(
            text,
            self.classifier.pipeline.predict_proba,
            labels=(idx,),
            num_features=self.num_features,
            num_samples=self.num_samples,
        )
        return [(tok, round(float(w), 5)) for tok, w in exp.as_list(label=idx)]

    def explain_entry(self, entry: SBOMEntry) -> SBOMEntry:
        """Attach a LIME explanation to a CBOM entry in place."""
        try:
            entry.lime_tokens = self.explain(
                entry.finding.snippet or entry.finding.matched_pattern,
                entry.algorithm,
            )
        except Exception as exc:                        # noqa: BLE001
            entry.lime_tokens = [(f"<explanation unavailable: {exc}>", 0.0)]
        return entry


# ---------------------------------------------------------------------------
# A cheap, always-available fallback so the dashboard never shows a blank panel
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _marker_patterns():
    from qaa.module2_detector.lexicon_features import _MARKER_SPECS
    import re
    return [(n, re.compile(p, re.I)) for n, p in _MARKER_SPECS]


def marker_evidence(text: str) -> list[tuple[str, str]]:
    """
    Which domain markers fired, and on what substring.

    This is deterministic and instant, unlike LIME which needs a few hundred
    model calls. The dashboard shows this immediately and loads the full LIME
    attribution on demand.
    """
    from qaa.module2_detector.lexicon_features import _expand
    expanded = _expand(text or "")
    out = []
    for name, pat in _marker_patterns():
        m = pat.search(expanded)
        if m:
            out.append((name.replace("mk_", ""), m.group(0)))
    return out
