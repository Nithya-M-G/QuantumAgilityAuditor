"""
End-to-end pipeline: Module 1 -> Module 2 -> Module 3.

This is the single entry point used by both the Streamlit dashboard and the CLI,
so the two can never drift apart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from qaa.module1_scanner.orchestrator import ScanStats, scan_target
from qaa.module2_detector.nlp_classifier import CryptoNLPClassifier
from qaa.module3_reasoner.recommender import build_roadmap
from qaa.schema import Finding, RiskAssessment, SBOMEntry, ScanContext


@dataclass
class AuditResult:
    context: ScanContext
    findings: list[Finding] = field(default_factory=list)
    sbom: list[SBOMEntry] = field(default_factory=list)
    roadmap: list[RiskAssessment] = field(default_factory=list)
    stats: ScanStats | None = None
    timings: dict[str, float] = field(default_factory=dict)

    # -- convenience views used by the dashboard ---------------------------
    @property
    def actionable(self) -> list[RiskAssessment]:
        return [a for a in self.roadmap if a.risk_level != "Informational"]

    def level_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0,
                  "Informational": 0}
        for a in self.roadmap:
            counts[a.risk_level] = counts.get(a.risk_level, 0) + 1
        return counts

    def algorithm_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.roadmap:
            k = a.sbom_entry.algorithm
            out[k] = out.get(k, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def surface_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.roadmap:
            k = a.sbom_entry.finding.surface
            out[k] = out.get(k, 0) + 1
        return out

    def sbom_rows(self) -> list[dict]:
        return [e.to_row() for e in self.sbom]

    def roadmap_rows(self) -> list[dict]:
        return [a.to_row() for a in self.roadmap]

    def summary(self) -> dict:
        c = self.level_counts()
        return {
            "system": self.context.system_name,
            "total_findings": len(self.findings),
            "cbom_entries": len(self.sbom),
            "actionable": len(self.actionable),
            "critical": c["Critical"],
            "high": c["High"],
            "medium": c["Medium"],
            "low": c["Low"],
            "already_pqc": c["Informational"],
            "hndl_exposed": self.context.hndl_exposed,
            "scan_seconds": round(sum(self.timings.values()), 3),
        }


def run_audit(
    target: str | Path,
    context: ScanContext | None = None,
    classifier: CryptoNLPClassifier | None = None,
    include_pcap: bool = True,
    progress: Callable[[str, int, int], None] | None = None,
) -> AuditResult:
    """Run the full four-module audit against a target path."""
    ctx = context or ScanContext()
    timings: dict[str, float] = {}

    # ---- Module 1 -------------------------------------------------------
    t0 = time.perf_counter()
    findings, stats = scan_target(target, include_pcap=include_pcap,
                                  progress=progress)
    timings["module1_scan"] = time.perf_counter() - t0

    # ---- Module 2 -------------------------------------------------------
    t0 = time.perf_counter()
    clf = classifier or CryptoNLPClassifier.load()
    sbom = clf.classify_all(findings)
    timings["module2_classify"] = time.perf_counter() - t0

    # ---- Module 3 -------------------------------------------------------
    t0 = time.perf_counter()
    roadmap = build_roadmap(sbom, ctx)
    timings["module3_reason"] = time.perf_counter() - t0

    return AuditResult(context=ctx, findings=findings, sbom=sbom,
                       roadmap=roadmap, stats=stats, timings=timings)


def to_cyclonedx(result: AuditResult) -> dict:
    """
    Emit the CBOM as CycloneDX 1.6 JSON.

    This is the machine-readable artifact that EU CRA / NIST-aligned compliance
    tooling consumes, and it makes the project's output interoperable with
    existing CBOM viewers rather than a bespoke format.
    """
    from qaa.config import ALGORITHM_DB, THREAT_PQC

    components = []
    for a in result.roadmap:
        e = a.sbom_entry
        meta = ALGORITHM_DB.get(e.algorithm, ALGORITHM_DB["NONE"])
        components.append({
            "type": "cryptographic-asset",
            "name": e.algorithm,
            "bom-ref": f"crypto/{e.algorithm}/{e.finding.file_path}"
                       f"#{e.finding.line_number}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": e.purpose,
                    "parameterSetIdentifier": str(e.finding.key_size or ""),
                    "curve": e.finding.curve or "",
                    "nistQuantumSecurityLevel":
                        5 if meta["threat"] == THREAT_PQC else 0,
                },
                "oid": "",
            },
            "evidence": {
                "occurrences": [{
                    "location": e.finding.file_path,
                    "line": e.finding.line_number,
                    "additionalContext": e.finding.matched_pattern,
                }]
            },
            "properties": [
                {"name": "qaa:riskScore", "value": str(a.risk_score)},
                {"name": "qaa:riskLevel", "value": a.risk_level},
                {"name": "qaa:surface", "value": e.finding.surface},
                {"name": "qaa:confidence", "value": f"{e.confidence:.4f}"},
                {"name": "qaa:replacement", "value": a.replacement},
                {"name": "qaa:nistStandard", "value": a.nist_standard},
                {"name": "qaa:detectionMethod", "value": e.detection_method},
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "DSATM CSE(AI)",
                       "name": "Quantum-Agility Auditor",
                       "version": "1.0.0"}],
            "component": {"type": "application",
                          "name": result.context.system_name},
            "properties": [
                {"name": "qaa:dataSensitivity",
                 "value": result.context.data_sensitivity},
                {"name": "qaa:systemLifespanYears",
                 "value": str(result.context.system_lifespan_years)},
                {"name": "qaa:hndlExposed",
                 "value": str(result.context.hndl_exposed)},
            ],
        },
        "components": components,
    }
