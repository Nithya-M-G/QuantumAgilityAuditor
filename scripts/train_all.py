#!/usr/bin/env python3
"""
Train both Module 2 classifiers and write honest evaluation metrics.

Usage
-----
    python scripts/train_all.py
    python scripts/train_all.py --kernel rbf --samples-per-template 30
    python scripts/train_all.py --quick          # skip the slow LOFO sweep

Outputs
-------
    models/nlp_classifier.joblib
    models/fingerprint_classifier.joblib
    models/nlp_metrics.json
    models/fingerprint_metrics.json
    data/nlp_corpus.csv

EVALUATION PROTOCOLS
--------------------
Three numbers are reported for the NLP classifier, because a single accuracy
figure on this kind of corpus is misleading:

  random_split    Stratified 75/25 shuffle. Optimistic: near-identical template
                  instances land on both sides of the split, so this measures
                  memorisation as much as learning. Reported for comparability
                  with published work, NOT as the headline number.

  lofo            Leave-one-template-family-out. An entire library's API shape
                  is removed from training, then tested. This answers the
                  question that matters: does the model handle a library it has
                  never seen? THIS IS THE NUMBER TO QUOTE.

  group_kfold     4-fold grouped by template family. Harsher than LOFO because
                  it removes a quarter of all API shapes at once, which can
                  strip a class of most of its training evidence. Reported as a
                  lower bound.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from qaa.config import (
    DATA_DIR,
    FP_METRICS_PATH,
    FP_MODEL_PATH,
    NLP_METRICS_PATH,
    NLP_MODEL_PATH,
)
from qaa.module2_detector.corpus import build_corpus, corpus_summary
from qaa.module2_detector.fingerprint import (
    FingerprintClassifier,
    build_fingerprint_dataset,
)
from qaa.module2_detector.nlp_classifier import CryptoNLPClassifier, build_pipeline


def _metrics(y_true, y_pred) -> dict:
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_macro": round(float(precision_score(
            y_true, y_pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(
            y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(
            y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(
            y_true, y_pred, average="weighted", zero_division=0)), 4),
    }


def false_positive_rate(y_true, y_pred) -> float:
    """
    Fraction of genuinely non-cryptographic snippets flagged as crypto.

    This is the metric the project's requirements table caps at 12%, and it is
    the one that decides whether a scanner is usable: a tool that cries wolf on
    ordinary code gets switched off.
    """
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    negatives = y_true == "NONE"
    if not negatives.any():
        return 0.0
    return round(float(np.mean(y_pred[negatives] != "NONE")), 4)


def train_nlp(args) -> dict:
    print("=" * 74)
    print("MODULE 2 STAGE 1 - NLP cryptographic classifier")
    print("=" * 74)

    rows = build_corpus(samples_per_template=args.samples_per_template,
                        seed=args.seed)
    summary = corpus_summary(rows)
    print(f"corpus: {summary['total']} snippets | {summary['classes']} classes "
          f"| {summary['template_families']} template families "
          f"| {len(summary['by_language'])} languages")

    # Persist the corpus so it is inspectable and the run is reproducible.
    csv_path = DATA_DIR / "nlp_corpus.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["sample_id", "label",
                                           "template_family", "language",
                                           "obfuscation", "text"])
        w.writeheader()
        w.writerows(rows)
    print(f"corpus written -> {csv_path}")

    X = np.array([r["text"] for r in rows])
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["template_family"] for r in rows])

    results: dict = {"corpus": summary, "kernel": args.kernel,
                     "protocols": {}}

    # ---------------- Protocol 1: random split ----------------
    t0 = time.perf_counter()
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=args.seed)
    pipe = build_pipeline(kernel=args.kernel)
    pipe.fit(Xtr, ytr)
    pred = pipe.predict(Xte)
    m = _metrics(yte, pred)
    m["false_positive_rate"] = false_positive_rate(yte, pred)
    m["n_test"] = int(len(yte))
    m["note"] = ("Optimistic. Near-identical template instances appear on both "
                 "sides of the split, so this measures memorisation as much as "
                 "generalisation. Do not quote this as the headline figure.")
    results["protocols"]["random_split"] = m
    print(f"\n[1/3] random split      acc={m['accuracy']:.4f}  "
          f"F1={m['f1_macro']:.4f}  FPR={m['false_positive_rate']:.4f}  "
          f"({time.perf_counter() - t0:.1f}s)")

    # ---------------- Protocol 2: grouped k-fold ----------------
    t0 = time.perf_counter()
    sgkf = StratifiedGroupKFold(n_splits=4, shuffle=True,
                                random_state=args.seed)
    fold_acc, all_true, all_pred = [], [], []
    for tr, te in sgkf.split(X, y, groups=groups):
        p = build_pipeline(kernel=args.kernel)
        p.fit(X[tr], y[tr])
        pr = p.predict(X[te])
        fold_acc.append(accuracy_score(y[te], pr))
        all_true.extend(y[te]); all_pred.extend(pr)
    m = _metrics(all_true, all_pred)
    m["false_positive_rate"] = false_positive_rate(all_true, all_pred)
    m["fold_accuracies"] = [round(float(a), 4) for a in fold_acc]
    m["note"] = ("Harsh lower bound: removes a quarter of all API shapes at "
                 "once, which can strip a class of most of its evidence.")
    results["protocols"]["group_kfold"] = m
    print(f"[2/3] grouped 4-fold    acc={m['accuracy']:.4f}  "
          f"F1={m['f1_macro']:.4f}  FPR={m['false_positive_rate']:.4f}  "
          f"({time.perf_counter() - t0:.1f}s)")

    # ---------------- Protocol 3: leave-one-family-out ----------------
    if args.quick:
        print("[3/3] LOFO             skipped (--quick)")
        results["protocols"]["lofo"] = {"skipped": True}
    else:
        t0 = time.perf_counter()
        families = sorted(set(groups))
        if args.lofo_sample and args.lofo_sample < len(families):
            rng = random.Random(args.seed)
            families = rng.sample(families, args.lofo_sample)
        lt, lp, per_family = [], [], {}
        for i, fam in enumerate(families, start=1):
            mask = groups != fam
            p = build_pipeline(kernel=args.kernel)
            p.fit(X[mask], y[mask])
            pr = p.predict(X[~mask])
            gold = y[~mask]
            per_family[fam] = round(float(accuracy_score(gold, pr)), 3)
            lt.extend(gold); lp.extend(pr)
            if i % 20 == 0:
                print(f"       ... {i}/{len(families)} families")
        m = _metrics(lt, lp)
        m["false_positive_rate"] = false_positive_rate(lt, lp)
        m["families_evaluated"] = len(families)
        m["weakest_families"] = dict(sorted(
            per_family.items(), key=lambda kv: kv[1])[:8])
        m["note"] = ("Headline generalisation figure. An entire library's API "
                     "shape is held out, so the model is tested on code "
                     "patterns it has never seen.")
        results["protocols"]["lofo"] = m
        print(f"[3/3] leave-one-out     acc={m['accuracy']:.4f}  "
              f"F1={m['f1_macro']:.4f}  FPR={m['false_positive_rate']:.4f}  "
              f"({time.perf_counter() - t0:.1f}s)")

    # ---------------- Final model on the full corpus ----------------
    print("\ntraining final model on the full corpus ...")
    final = build_pipeline(kernel=args.kernel)
    final.fit(X, y)
    labels = sorted(set(y))
    headline = results["protocols"].get("lofo", {}).get(
        "accuracy", results["protocols"]["random_split"]["accuracy"])
    clf = CryptoNLPClassifier(final, labels, metadata={
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "corpus_size": summary["total"],
        "kernel": args.kernel,
        "headline_accuracy_lofo": headline,
        "random_split_accuracy": results["protocols"]["random_split"]["accuracy"],
    })
    clf.save()
    print(f"saved -> {NLP_MODEL_PATH}")

    results["classification_report_random_split"] = classification_report(
        yte, pred, zero_division=0, output_dict=True)
    results["labels"] = labels
    results["confusion_matrix_random_split"] = confusion_matrix(
        yte, pred, labels=labels).tolist()
    NLP_METRICS_PATH.write_text(json.dumps(results, indent=2))
    print(f"metrics -> {NLP_METRICS_PATH}")
    return results


def train_fingerprint(args) -> dict:
    print("\n" + "=" * 74)
    print("MODULE 2 STAGE 2 - ciphertext fingerprint classifier")
    print("=" * 74)

    t0 = time.perf_counter()
    X, y = build_fingerprint_dataset(
        samples_per_class=args.fp_samples, seed=args.seed)
    print(f"artifacts: {X.shape[0]} samples x {X.shape[1]} features "
          f"({time.perf_counter() - t0:.1f}s)")

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=args.seed)
    fp = FingerprintClassifier.train(Xtr, ytr)
    pred = fp.model.predict(Xte)
    m = _metrics(yte, pred)
    m["n_test"] = int(len(yte))
    print(f"accuracy={m['accuracy']:.4f}  macro-F1={m['f1_macro']:.4f}")

    report = classification_report(yte, pred, zero_division=0, output_dict=True)

    # Re-train on everything for the shipped model.
    fp_full = FingerprintClassifier.train(X, y)
    fp_full.metadata = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "accuracy": m["accuracy"],
        "n_samples": int(X.shape[0]),
    }
    fp_full.save()
    print(f"saved -> {FP_MODEL_PATH}")

    out = {
        "holdout": m,
        "classification_report": report,
        "feature_importance_top15": fp_full.feature_importance(15),
        "labels": sorted(set(y)),
        "confusion_matrix": confusion_matrix(
            yte, pred, labels=sorted(set(y))).tolist(),
        "interpretation": (
            "Classes separated by structure - RSA keys and ECDSA signatures "
            "(ASN.1 DER framing), digests (fixed length), 3DES (8-byte block "
            "alignment), plaintext, base64 and compressed data - are "
            "classified near-perfectly. AES-GCM and ChaCha20 are confused with "
            "each other at close to chance, and this is the expected and "
            "correct result: both produce unpadded output that is "
            "indistinguishable from random by design. A randomness test that "
            "could separate them would constitute a distinguishing attack on "
            "the cipher. The SP 800-22 battery therefore answers 'is this "
            "cryptographic output', while the structural features answer "
            "'which primitive produced it'."
        ),
    }
    FP_METRICS_PATH.write_text(json.dumps(out, indent=2))
    print(f"metrics -> {FP_METRICS_PATH}")
    return out


def main():
    ap = argparse.ArgumentParser(description="Train Quantum-Agility Auditor models")
    ap.add_argument("--kernel", choices=["linear", "rbf"], default="linear",
                    help="SVM back-end (default: linear, much faster)")
    ap.add_argument("--samples-per-template", type=int, default=26)
    ap.add_argument("--fp-samples", type=int, default=90)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--lofo-sample", type=int, default=40,
                    help="evaluate this many held-out families (0 = all)")
    ap.add_argument("--quick", action="store_true", help="skip the LOFO sweep")
    ap.add_argument("--skip-fingerprint", action="store_true")
    args = ap.parse_args()

    started = time.perf_counter()
    train_nlp(args)
    if not args.skip_fingerprint:
        train_fingerprint(args)

    print("\n" + "=" * 74)
    print(f"DONE in {time.perf_counter() - started:.1f}s. "
          f"Run:  streamlit run app.py")
    print("=" * 74)


if __name__ == "__main__":
    main()
