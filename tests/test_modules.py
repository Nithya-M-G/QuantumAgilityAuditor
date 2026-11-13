"""
Test suite for the Quantum-Agility Auditor.

Run with:   python -m pytest tests/ -v
       or:  python tests/test_modules.py     (no pytest required)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qaa.config import ALGORITHM_DB, SAMPLES_DIR
from qaa.module1_scanner.ast_scanner import scan_python_file
from qaa.module1_scanner.config_scanner import scan_config_file
from qaa.module1_scanner.dependency_scanner import scan_dependency_file
from qaa.module1_scanner.orchestrator import scan_target
from qaa.module1_scanner.regex_scanner import scan_text_source
from qaa.module2_detector.fingerprint_features import extract_features, monobit_test
from qaa.module2_detector.lexicon_features import CryptoLexiconVectorizer
from qaa.module3_reasoner.recommender import assess, recommend
from qaa.module3_reasoner.risk_engine import classify_level, score_entry
from qaa.schema import Finding, SBOMEntry, ScanContext


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.write_text(body)
    return p


# ===========================================================================
# MODULE 1
# ===========================================================================
def test_ast_resolves_aliased_import():
    """The headline Module 1 claim: aliased crypto imports are still caught."""
    with tempfile.TemporaryDirectory() as d:
        p = _write(Path(d), "a.py",
                   "from cryptography.hazmat.primitives.asymmetric "
                   "import rsa as _backend\n"
                   "k = _backend.generate_private_key("
                   "public_exponent=65537, key_size=1024)\n")
        f = scan_python_file(p)
        assert any(x.hint_algorithm == "RSA" for x in f), \
            "aliased RSA import not resolved"
        assert any(x.key_size == 1024 for x in f), "key_size not extracted"


def test_ast_ignores_comments_and_strings():
    """A word in a comment or a plain string is not a cryptographic finding."""
    with tempfile.TemporaryDirectory() as d:
        p = _write(Path(d), "b.py",
                   "# TODO: migrate our RSA and ECDSA usage next quarter\n"
                   "TICKET = 'SEC-4412 tracks the MD5 removal'\n"
                   "x = 1 + 1\n")
        assert scan_python_file(p) == [], "false positive on comment/string"


def test_regex_strips_comments():
    with tempfile.TemporaryDirectory() as d:
        p = _write(Path(d), "c.java",
                   "// Cipher.getInstance(\"DES/ECB/PKCS5Padding\") was removed\n"
                   "int n = rows.size();\n")
        assert scan_text_source(p) == [], "matched inside a comment"


def test_regex_detects_real_java_call():
    with tempfile.TemporaryDirectory() as d:
        p = _write(Path(d), "d.java",
                   "Cipher c = Cipher.getInstance(\"DESede/CBC/PKCS5Padding\");\n")
        assert any(x.hint_algorithm == "3DES" for x in scan_text_source(p))


def test_config_scanner_flags_cipher_suites():
    with tempfile.TemporaryDirectory() as d:
        p = _write(Path(d), "nginx.conf",
                   "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA:RC4-MD5;\n")
        fams = {x.hint_algorithm for x in scan_config_file(p)}
        assert {"RSA", "3DES", "RC4"} <= fams, f"missing families: {fams}"


def test_dependency_scanner_parses_package_json():
    with tempfile.TemporaryDirectory() as d:
        p = _write(Path(d), "package.json",
                   '{"dependencies": {"node-forge": "^1.3.1", '
                   '"crypto-js": "^4.2.0", "react": "^18.2.0"}}')
        found = scan_dependency_file(p)
        libs = {f.extra["library"] for f in found}
        assert "node-forge" in libs and "crypto-js" in libs
        assert "react" not in libs, "flagged a non-crypto dependency"


def test_orchestrator_covers_every_surface():
    demo = SAMPLES_DIR / "demo_target"
    if not demo.exists():
        return
    findings, stats = scan_target(demo, include_pcap=False)
    surfaces = {f.surface for f in findings}
    assert {"source_code", "config", "dependency"} <= surfaces, surfaces
    assert stats.files_scanned >= 8


# ===========================================================================
# MODULE 2
# ===========================================================================
def test_lexicon_matches_inside_identifiers():
    """Regression test for the \\b-vs-underscore bug that cost ~20 points."""
    import numpy as np
    v = CryptoLexiconVectorizer().fit([])
    names = list(v.get_feature_names_out())
    for text, marker in [("MD5_CTX ctx; MD5_Init(&ctx);", "mk_md5__any"),
                         ("EVP_EncryptInit_ex(c, EVP_rc4(), 0,0,0);",
                          "mk_rc4__any"),
                         ("paramiko.RSAKey.generate(bits=2048)", "mk_rsa__any")]:
        row = v.transform([text]).toarray()[0]
        idx = names.index(marker)
        assert row[idx] == 1.0, f"{marker} did not fire on: {text}"


def test_lexicon_separates_jwt_algorithms():
    """RS256 and ES256 must not share a feature dimension."""
    import numpy as np
    v = CryptoLexiconVectorizer().fit([])
    names = list(v.get_feature_names_out())
    rs = v.transform(["jwt.sign(c, k, {algorithm:'RS256'})"]).toarray()[0]
    es = v.transform(["jwt.sign(c, k, {algorithm:'ES256'})"]).toarray()[0]
    assert rs[names.index("mk_jwt_rsa_alg__any")] == 1.0
    assert rs[names.index("mk_jwt_ec_alg__any")] == 0.0
    assert es[names.index("mk_jwt_ec_alg__any")] == 1.0


def test_sp800_22_monobit_separates_random_from_constant():
    import os
    import numpy as np
    from qaa.module2_detector.fingerprint_features import _bits
    assert monobit_test(_bits(os.urandom(2048))) > 0.01, "random data rejected"
    assert monobit_test(_bits(b"\x00" * 2048)) < 0.01, "constant data accepted"


def test_fingerprint_feature_vector_is_stable():
    import os
    from qaa.module2_detector.fingerprint_features import feature_names
    v = extract_features(os.urandom(256))
    assert len(v) == len(feature_names())
    assert not any(x != x for x in v), "NaN in feature vector"


def test_fingerprint_detects_block_alignment():
    import os
    from qaa.module2_detector.fingerprint_features import structural_features
    assert structural_features(os.urandom(256))["struct_mod16"] == 1.0
    assert structural_features(os.urandom(255))["struct_mod16"] == 0.0


def test_classifier_end_to_end_if_trained():
    from qaa.config import NLP_MODEL_PATH
    if not NLP_MODEL_PATH.exists():
        return
    from qaa.module2_detector.nlp_classifier import CryptoNLPClassifier
    clf = CryptoNLPClassifier.load()
    for text, expected in [
        ("from Crypto.PublicKey import RSA\nk = RSA.generate(2048)", "RSA"),
        ("Cipher.getInstance(\"DESede/CBC/PKCS5Padding\")", "3DES"),
        ("hashlib.md5(payload).hexdigest()", "MD5"),
        ("import pandas as pd\ndf = pd.read_csv(path)", "NONE"),
    ]:
        got, conf, _ = clf.predict_one(text)
        assert got == expected, f"{text!r} -> {got}, expected {expected}"


# ===========================================================================
# MODULE 3
# ===========================================================================
def _entry(alg="RSA", key_size=1024, surface="source_code", conf=0.95):
    meta = ALGORITHM_DB[alg]
    return SBOMEntry(
        finding=Finding(file_path="x.py", line_number=1, surface=surface,
                        snippet="rsa.generate_private_key(key_size=1024)",
                        matched_pattern="rsa", detector="ast",
                        language="python", key_size=key_size),
        algorithm=alg, confidence=conf, purpose=meta["purpose"],
        threat_class=meta["threat"], detection_method="ast+nlp_fused")


def test_hndl_multiplier_raises_score():
    """The defining behaviour of this project: long-lived systems score higher."""
    e = _entry()
    _, _, bs = score_entry(e, ScanContext(system_lifespan_years=3))
    _, _, b = score_entry(e, ScanContext(system_lifespan_years=20))
    # Compare raw scores: both saturate the capped 0-10 band.
    assert b["raw_score"] > bs["raw_score"], "HNDL multiplier had no effect"
    assert b["hndl"]["applied"] is True
    assert b["hndl"]["multiplier"] == 1.3


def test_undersized_key_penalty():
    weak, _, bw = score_entry(_entry(key_size=1024), ScanContext())
    strong, _, bs = score_entry(_entry(key_size=4096), ScanContext())
    assert weak > strong
    assert bw["undersized_key"] is not None
    assert bs["undersized_key"] is None


def test_sensitivity_multiplier():
    _, _, lo = score_entry(_entry(), ScanContext(data_sensitivity="internal"))
    _, _, hi = score_entry(_entry(), ScanContext(data_sensitivity="financial"))
    assert hi["raw_score"] > lo["raw_score"]


def test_score_cap_is_reported_not_hidden():
    """A saturating finding must still expose its uncapped score for ranking."""
    _, _, b = score_entry(_entry(key_size=512),
                          ScanContext(data_sensitivity="defence",
                                      system_lifespan_years=25))
    assert b["final_score"] == 10.0
    assert b["raw_score"] > 10.0 and b["saturated"] is True


def test_pqc_algorithm_scores_zero():
    score, level, _ = score_entry(_entry("ML-KEM", key_size=None), ScanContext())
    assert score == 0.0 and level == "Informational"


def test_surface_weighting():
    net, _, _ = score_entry(_entry(surface="network"), ScanContext())
    dep, _, _ = score_entry(_entry(surface="dependency"), ScanContext())
    assert net > dep, "a live wire observation should outrank a manifest entry"


def test_thresholds():
    assert classify_level(9.0) == "Critical"
    assert classify_level(6.0) == "High"
    assert classify_level(3.0) == "Medium"
    assert classify_level(1.0) == "Low"
    assert classify_level(0.0) == "Informational"


def test_recommendation_is_purpose_aware():
    """RSA for key transport -> FIPS 203; RSA for signing -> FIPS 204."""
    ctx = ScanContext()
    kex = _entry("RSA")
    sig = _entry("RSA")
    sig.purpose = "digital_signature"
    assert "203" in recommend(kex, ctx)["standard"]
    assert "204" in recommend(sig, ctx)["standard"]


def test_high_sensitivity_selects_stronger_parameter_set():
    std = recommend(_entry(), ScanContext(data_sensitivity="internal"))
    high = recommend(_entry(), ScanContext(data_sensitivity="defence"))
    assert std["replacement"] == "ML-KEM-768"
    assert high["replacement"] == "ML-KEM-1024"


def test_snippet_generation_matches_language():
    a = assess(_entry(), ScanContext())
    assert "oqs" in a.code_snippet and "ML-KEM" in a.code_snippet
    assert a.snippet_language == "python"

    e = _entry()
    e.finding.language = "java"
    aj = assess(e, ScanContext())
    assert aj.snippet_language == "java"
    assert "KeyPairGenerator" in aj.code_snippet


# ===========================================================================
# MODULE 4 / pipeline
# ===========================================================================
def test_full_pipeline_and_exports():
    from qaa.config import NLP_MODEL_PATH
    demo = SAMPLES_DIR / "demo_target"
    if not (NLP_MODEL_PATH.exists() and demo.exists()):
        return
    from qaa.module4_report.pdf_export import build_pdf
    from qaa.pipeline import run_audit, to_cyclonedx

    r = run_audit(demo, ScanContext(data_sensitivity="financial",
                                    system_lifespan_years=15),
                  include_pcap=False)
    assert len(r.sbom) > 20
    assert r.level_counts()["Critical"] > 0
    assert r.summary()["hndl_exposed"] is True

    bom = to_cyclonedx(r)
    assert bom["bomFormat"] == "CycloneDX" and bom["components"]

    pdf = build_pdf(r)
    assert pdf.startswith(b"%PDF"), "PDF export produced invalid bytes"
    assert len(pdf) > 5000


# ===========================================================================
if __name__ == "__main__":
    import traceback

    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception:                                   # noqa: BLE001
            print(f"  FAIL  {name}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
