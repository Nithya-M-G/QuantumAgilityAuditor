"""
Shared data structures that flow between the four modules.

    Module 1  ->  Finding        (raw, unclassified evidence)
    Module 2  ->  SBOMEntry      (algorithm identified + confidence + LIME)
    Module 3  ->  RiskAssessment (score, level, recommendation, snippet)
    Module 4  ->  consumes all three for the dashboard and the PDF
"""

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    """Raw evidence produced by Module 1 before any AI classification."""
    file_path: str
    line_number: int
    surface: str                      # source_code | config | dependency | network
    snippet: str                      # the evidence text handed to Module 2
    matched_pattern: str              # what the detector keyed on
    detector: str                     # ast | regex | config | dependency | pcap
    language: str = "unknown"
    key_size: int | None = None
    curve: str | None = None
    hint_algorithm: str | None = None  # deterministic guess, may be None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SBOMEntry:
    """One row of the Cryptographic Bill of Materials (Module 2 output)."""
    finding: Finding
    algorithm: str
    confidence: float
    purpose: str
    threat_class: str
    detection_method: str             # nlp_classifier | ast_deterministic | fingerprint
    lime_tokens: list[tuple[str, float]] = field(default_factory=list)
    probability_vector: dict[str, float] = field(default_factory=dict)

    def to_row(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "file": self.finding.file_path,
            "line": self.finding.line_number,
            "surface": self.finding.surface,
            "confidence": round(self.confidence, 4),
            "purpose": self.purpose,
            "threat_class": self.threat_class,
            "key_size": self.finding.key_size,
            "detection_method": self.detection_method,
            "evidence": self.finding.snippet.strip()[:160],
        }


@dataclass
class RiskAssessment:
    """Module 3 output: one scored, prioritised migration item."""
    sbom_entry: SBOMEntry
    risk_score: float
    risk_level: str                   # Critical | High | Medium | Low | Informational
    score_breakdown: dict[str, Any]
    replacement: str
    nist_standard: str
    hybrid_option: str
    recommended_library: str
    nist_level: str
    performance_note: str
    performance_delta_pct: float
    effort: str
    effort_note: str
    code_snippet: str
    snippet_language: str

    def to_row(self) -> dict:
        e = self.sbom_entry
        return {
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "algorithm": e.algorithm,
            "file": e.finding.file_path,
            "line": e.finding.line_number,
            "surface": e.finding.surface,
            "purpose": e.purpose,
            "replacement": self.replacement,
            "nist_standard": self.nist_standard,
            "effort": self.effort,
            "confidence": round(e.confidence, 3),
            "perf_delta_pct": self.performance_delta_pct,
        }


@dataclass
class ScanContext:
    """User-supplied context that drives the Module 3 risk multipliers."""
    data_sensitivity: str = "internal"     # public|internal|financial|medical|...
    system_lifespan_years: int = 3
    system_name: str = "Unnamed System"
    auditor: str = "Quantum-Agility Auditor"

    @property
    def hndl_exposed(self) -> bool:
        from qaa.config import HNDL_LIFESPAN_YEARS
        return self.system_lifespan_years > HNDL_LIFESPAN_YEARS
