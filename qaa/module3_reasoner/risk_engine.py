"""
Module 3a - Risk Scoring Engine.

Implements the five-factor scoring algorithm from the project design:

    base   = severity_table[algorithm]
    if key_size < min_safe_key:        base += 2
    if sensitivity in {financial, medical, ...}:  base *= 1.5
    if system_lifespan > 5 years:      base *= 1.3        (HNDL multiplier)
    base  *= surface_weight            (exposure adjustment)
    base  *= confidence_adjustment     (uncertain findings are de-prioritised)

    Critical if score > 8, High if score > 5, Medium if score > 2, else Low.

The HNDL multiplier is the factor that makes this different from a conventional
vulnerability scanner. "Harvest Now, Decrypt Later" means an adversary records
ECDHE-protected traffic today and decrypts it once a cryptographically relevant
quantum computer exists. A key exchange protecting data with a 20-year
confidentiality requirement is therefore *already* compromised, even though no
quantum computer exists yet. A scanner that scores only present-day
exploitability rates that finding as low risk, which is exactly backwards.

Two extensions beyond the base specification, both documented so a reviewer can
see what is design and what is addition:

  * surface weighting - a cipher suite observed in a live PCAP is confirmed
    exposure and scores higher than the same algorithm named in a dependency
    manifest, which may never be reached at runtime.
  * confidence adjustment - a finding the classifier is only 55% sure about
    should not outrank one it is 99% sure about. Without this the roadmap
    prioritises noise.
"""

from __future__ import annotations

from qaa.config import (
    ALGORITHM_DB,
    HNDL_LIFESPAN_YEARS,
    HNDL_MULTIPLIER,
    RISK_CRITICAL_THRESHOLD,
    RISK_HIGH_THRESHOLD,
    RISK_MEDIUM_THRESHOLD,
    SENSITIVITY_MULTIPLIER,
    SURFACE_WEIGHT,
    THREAT_PQC,
    UNDERSIZED_KEY_PENALTY,
)
from qaa.schema import SBOMEntry, ScanContext


def score_entry(entry: SBOMEntry, ctx: ScanContext) -> tuple[float, str, dict]:
    """
    Score one CBOM entry.

    Returns (score, level, breakdown) where breakdown records every factor so
    the dashboard and the PDF can show the arithmetic rather than a bare number.
    """
    meta = ALGORITHM_DB.get(entry.algorithm, ALGORITHM_DB["NONE"])
    breakdown: dict = {"algorithm": entry.algorithm}

    # --- Factor 1: intrinsic algorithm severity ---------------------------
    base = float(meta["base_severity"])
    breakdown["base_severity"] = base
    breakdown["threat_class"] = meta["threat"]

    # Already post-quantum, or nothing detected: score is zero by definition.
    if meta["threat"] == THREAT_PQC or entry.algorithm == "NONE":
        breakdown["note"] = ("Post-quantum standard already in use - no "
                             "migration required.")
        return 0.0, "Informational", breakdown

    # --- Factor 2: key size --------------------------------------------------
    key_size = entry.finding.key_size
    min_safe = meta["min_safe_key"]
    if key_size is not None and min_safe and key_size < min_safe:
        base += UNDERSIZED_KEY_PENALTY
        breakdown["undersized_key"] = {
            "observed": key_size, "minimum_safe": min_safe,
            "penalty": UNDERSIZED_KEY_PENALTY,
        }
    else:
        breakdown["undersized_key"] = None
    breakdown["after_key_penalty"] = round(base, 3)

    # --- Factor 3: data sensitivity -----------------------------------------
    sens_mult = SENSITIVITY_MULTIPLIER.get(ctx.data_sensitivity, 1.0)
    base *= sens_mult
    breakdown["sensitivity"] = {"class": ctx.data_sensitivity,
                                "multiplier": sens_mult}

    # --- Factor 4: system lifespan / HNDL exposure --------------------------
    hndl_applied = False
    if ctx.system_lifespan_years > HNDL_LIFESPAN_YEARS:
        base *= HNDL_MULTIPLIER
        hndl_applied = True
    breakdown["hndl"] = {
        "lifespan_years": ctx.system_lifespan_years,
        "threshold_years": HNDL_LIFESPAN_YEARS,
        "multiplier": HNDL_MULTIPLIER if hndl_applied else 1.0,
        "applied": hndl_applied,
        "rationale": (
            "Data protected by this primitive must stay confidential beyond "
            "the expected arrival of a cryptographically relevant quantum "
            "computer. Traffic captured today is decryptable later."
            if hndl_applied else
            "System lifespan is inside the HNDL threshold."
        ),
    }

    # --- Factor 5: exposure surface -----------------------------------------
    surf_w = SURFACE_WEIGHT.get(entry.finding.surface, 1.0)
    base *= surf_w
    breakdown["surface"] = {"type": entry.finding.surface, "weight": surf_w}

    # --- Confidence adjustment ----------------------------------------------
    # Maps confidence [0,1] onto a [0.75, 1.0] multiplier: a low-confidence
    # finding is de-prioritised but never dismissed.
    conf_adj = 0.75 + 0.25 * max(0.0, min(1.0, entry.confidence))
    base *= conf_adj
    breakdown["confidence_adjustment"] = {
        "confidence": round(entry.confidence, 4),
        "multiplier": round(conf_adj, 4),
    }

    # The reported score is capped to the 0-10 band the design specifies, but
    # the uncapped value is retained. Without it the cap saturates: an RSA-1024
    # key in a financial, HNDL-exposed system reaches 11+ before clipping, so
    # every worst-case finding reports exactly 10.0 and the roadmap loses the
    # ability to rank within the Critical band. Ordering uses raw_score.
    raw = round(base, 3)
    score = round(min(base, 10.0), 2)
    breakdown["raw_score"] = raw
    breakdown["final_score"] = score
    breakdown["saturated"] = raw > 10.0
    return score, classify_level(score), breakdown


def classify_level(score: float) -> str:
    if score > RISK_CRITICAL_THRESHOLD:
        return "Critical"
    if score > RISK_HIGH_THRESHOLD:
        return "High"
    if score > RISK_MEDIUM_THRESHOLD:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def explain_score(breakdown: dict) -> str:
    """Render the arithmetic as a single readable line for the report."""
    parts = [f"base({breakdown['algorithm']})={breakdown.get('base_severity')}"]
    if breakdown.get("undersized_key"):
        u = breakdown["undersized_key"]
        parts.append(f"+{u['penalty']} (key {u['observed']} < {u['minimum_safe']})")
    s = breakdown.get("sensitivity")
    if s and s["multiplier"] != 1.0:
        parts.append(f"x{s['multiplier']} ({s['class']} data)")
    h = breakdown.get("hndl")
    if h and h["applied"]:
        parts.append(f"x{h['multiplier']} (HNDL, {h['lifespan_years']}y lifespan)")
    sf = breakdown.get("surface")
    if sf and sf["weight"] != 1.0:
        parts.append(f"x{sf['weight']} ({sf['type']} surface)")
    c = breakdown.get("confidence_adjustment")
    if c:
        parts.append(f"x{c['multiplier']} (confidence {c['confidence']})")
    return " ".join(parts) + f" = {breakdown.get('final_score', 0)}"
