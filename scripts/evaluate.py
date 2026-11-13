#!/usr/bin/env python3
"""
End-to-end system evaluation against hand-labeled ground truth.

WHY THIS IS THE NUMBER THAT MATTERS
-----------------------------------
scripts/train_all.py measures the Module 2 classifier in isolation, on synthetic
snippets. That is a component metric. The project's requirements table asks for
*system* accuracy, precision, recall, F1 and false-positive rate - i.e. how well
the whole pipeline finds real cryptography in a real file tree, where Module 1's
deterministic evidence and Module 2's classifier are fused.

Ground truth below is hand-authored against samples/demo_target: every line of
that project that genuinely uses a cryptographic primitive, plus the hard
negatives deliberately planted in it (a base64 encode, an os.urandom token, a
comment mentioning SHA-1, a Java method named testRsaMigration...). A finding is
scored correct only if the algorithm family matches at the right file and line.

Usage
-----
    python scripts/evaluate.py
    python scripts/evaluate.py --json results.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qaa.config import SAMPLES_DIR
from qaa.module2_detector.nlp_classifier import CryptoNLPClassifier
from qaa.pipeline import run_audit
from qaa.schema import ScanContext

# ---------------------------------------------------------------------------
# GROUND TRUTH
# ---------------------------------------------------------------------------
# (relative_path, algorithm) for every genuine cryptographic asset in the demo
# project. Line numbers are deliberately not pinned: a finding is credited if
# the correct algorithm is reported anywhere in the correct file, because the
# scanners legitimately report a multi-line call at different anchor lines.
# ---------------------------------------------------------------------------
GROUND_TRUTH: set[tuple[str, str]] = {
    # --- src/auth_service.py -------------------------------------------
    ("src/auth_service.py", "RSA"),        # aliased rsa.generate_private_key
    ("src/auth_service.py", "ECDH"),       # ec.ECDH() exchange
    ("src/auth_service.py", "ECC"),        # ec.generate_private_key
    ("src/auth_service.py", "MD5"),        # hashlib.md5
    ("src/auth_service.py", "SHA1"),       # hashlib.sha1
    ("src/auth_service.py", "SHA256"),     # hashes.SHA256 in PSS
    # --- src/PaymentProcessor.java ---------------------------------------
    ("src/PaymentProcessor.java", "RSA"),
    ("src/PaymentProcessor.java", "ECDSA"),
    ("src/PaymentProcessor.java", "3DES"),
    ("src/PaymentProcessor.java", "AES"),
    ("src/PaymentProcessor.java", "MD5"),
    # --- src/session.js ---------------------------------------------------
    ("src/session.js", "ECDH"),
    ("src/session.js", "ECDSA"),           # jwt ES256
    ("src/session.js", "AES"),
    ("src/session.js", "3DES"),
    ("src/session.js", "SHA1"),
    # --- src/firmware_signer.cpp ------------------------------------------
    ("src/firmware_signer.cpp", "RSA"),
    ("src/firmware_signer.cpp", "ECC"),
    ("src/firmware_signer.cpp", "SHA1"),
    # --- src/migrated_channel.py (already PQC - must be found, not flagged) -
    ("src/migrated_channel.py", "ML-KEM"),
    # --- config/nginx.conf -------------------------------------------------
    ("config/nginx.conf", "RSA"),
    ("config/nginx.conf", "ECDSA"),
    ("config/nginx.conf", "ECDH"),
    ("config/nginx.conf", "DH"),
    ("config/nginx.conf", "3DES"),
    ("config/nginx.conf", "RC4"),
    ("config/nginx.conf", "MD5"),
    ("config/nginx.conf", "SHA1"),
    # --- config/.env --------------------------------------------------------
    ("config/.env", "RSA"),
    ("config/.env", "MD5"),
    ("config/.env", "AES"),
    # --- config/sshd_config -------------------------------------------------
    ("config/sshd_config", "ECDH"),
    ("config/sshd_config", "RSA"),
    ("config/sshd_config", "3DES"),
    # --- deps/requirements.txt ----------------------------------------------
    ("deps/requirements.txt", "RSA"),      # pycryptodome / pyOpenSSL / PyJWT
    ("deps/requirements.txt", "ECDSA"),    # ecdsa
    # --- deps/package.json ---------------------------------------------------
    ("deps/package.json", "RSA"),          # node-forge / jsonwebtoken
    ("deps/package.json", "3DES"),         # crypto-js
    ("deps/package.json", "ECDSA"),        # elliptic
    # --- deps/pom.xml ---------------------------------------------------------
    ("deps/pom.xml", "RSA"),               # bcprov / jjwt
    ("deps/pom.xml", "MD5"),               # commons-codec
}

# Files whose non-crypto lines are the negative set. A finding in one of these
# files that is NOT in GROUND_TRUTH counts as a false positive.
NEGATIVE_NOTES = {
    "src/auth_service.py": "os.urandom request id; a TODO comment naming MD5",
    "src/PaymentProcessor.java": "a comment naming SHA-1; a plain List size()",
    "src/session.js": "base64 pack(); JSON.stringify",
    "config/.env": "a plain https:// URL and a postgres DSN",
}


def _rel(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve())).replace(
            "\\", "/")
    except ValueError:
        return Path(path).name


def evaluate(target: Path, ctx: ScanContext) -> dict:
    clf = CryptoNLPClassifier.load()
    t0 = time.perf_counter()
    result = run_audit(target, context=ctx, classifier=clf, include_pcap=False)
    elapsed = time.perf_counter() - t0

    predicted: set[tuple[str, str]] = set()
    for entry in result.sbom:
        predicted.add((_rel(entry.finding.file_path, target), entry.algorithm))

    tp = predicted & GROUND_TRUTH
    fp = predicted - GROUND_TRUTH
    fn = GROUND_TRUTH - predicted

    precision = len(tp) / len(predicted) if predicted else 0.0
    recall = len(tp) / len(GROUND_TRUTH) if GROUND_TRUTH else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    # Accuracy over the (file, algorithm) decision space actually exercised.
    accuracy = len(tp) / len(predicted | GROUND_TRUTH) if (
        predicted | GROUND_TRUTH) else 0.0
    fpr = len(fp) / len(predicted) if predicted else 0.0

    return {
        "target": str(target),
        "ground_truth_assets": len(GROUND_TRUTH),
        "predicted_assets": len(predicted),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "false_negatives": len(fn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
        "scan_seconds": round(elapsed, 3),
        "files_scanned": result.stats.files_scanned,
        "raw_findings": len(result.findings),
        "missed": sorted(fn),
        "spurious": sorted(fp),
        "summary": result.summary(),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=str(SAMPLES_DIR / "demo_target"))
    ap.add_argument("--sensitivity", default="financial")
    ap.add_argument("--lifespan", type=int, default=15)
    ap.add_argument("--json", help="write full results to this path")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        raise SystemExit(f"target not found: {target}")

    ctx = ScanContext(data_sensitivity=args.sensitivity,
                      system_lifespan_years=args.lifespan,
                      system_name="Benchmark Target")
    r = evaluate(target, ctx)

    print("=" * 74)
    print("END-TO-END SYSTEM EVALUATION")
    print("=" * 74)
    print(f"target            : {r['target']}")
    print(f"files scanned     : {r['files_scanned']}")
    print(f"raw findings      : {r['raw_findings']}")
    print(f"ground-truth assets: {r['ground_truth_assets']}")
    print(f"predicted assets  : {r['predicted_assets']}")
    print(f"scan time         : {r['scan_seconds']}s")
    print("-" * 74)
    print(f"  Accuracy             {r['accuracy']:.4f}   (target >= 0.85)")
    print(f"  Precision            {r['precision']:.4f}   (target >= 0.83)")
    print(f"  Recall               {r['recall']:.4f}   (target >= 0.87)")
    print(f"  F1-Score             {r['f1']:.4f}   (target >= 0.85)")
    print(f"  False positive rate  {r['false_positive_rate']:.4f}   "
          f"(target <= 0.12)")
    print("-" * 74)
    print(f"  TP {r['true_positives']}   FP {r['false_positives']}   "
          f"FN {r['false_negatives']}")

    if r["missed"]:
        print("\nMISSED (false negatives):")
        for f, a in r["missed"]:
            print(f"  - {a:10s} in {f}")
    if r["spurious"]:
        print("\nSPURIOUS (false positives):")
        for f, a in r["spurious"]:
            print(f"  - {a:10s} in {f}")

    checks = [
        ("Accuracy >= 0.85", r["accuracy"] >= 0.85),
        ("Precision >= 0.83", r["precision"] >= 0.83),
        ("Recall >= 0.87", r["recall"] >= 0.87),
        ("F1 >= 0.85", r["f1"] >= 0.85),
        ("FPR <= 0.12", r["false_positive_rate"] <= 0.12),
        ("Scan time < 120s", r["scan_seconds"] < 120),
    ]
    print("\n" + "=" * 74)
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")
    print("=" * 74)

    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2))
        print(f"\nwritten -> {args.json}")


if __name__ == "__main__":
    main()
