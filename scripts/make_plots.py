"""
Regenerate the evaluation charts used in the IEEE paper, straight from the
metrics your own training run already produced.

Run this from the project root (the folder containing qaa/, models/, data/):

    python scripts/make_plots.py

Requires: matplotlib, numpy  (pip install matplotlib numpy)

Reads
-----
    models/nlp_metrics.json          -> 3-protocol comparison chart
    models/fingerprint_metrics.json  -> confusion matrix + feature importance

Writes
------
    figs/protocol_comparison.png
    figs/fingerprint_confusion.png
    figs/feature_importance.png

Note: the "detection accuracy vs. keyword scanner / manual audit" bar chart
in the paper is NOT reproducible from this repo's JSON output -- those
comparison numbers (60% keyword scanner, ~95% manual audit) came from the
project's own comparison table (see the PPT), not from a script in this
codebase. There is nothing to train or benchmark for that one; it's a
literature/estimate-based comparison, not a measured result.
"""

import json
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent if (pathlib.Path(__file__).resolve().parent.name == "scripts") \
       else pathlib.Path.cwd()
MODELS = ROOT / "models"
OUT = ROOT / "figs"
OUT.mkdir(exist_ok=True)

plt.rcParams.update({"font.size": 9})


def load(name):
    path = MODELS / name
    if not path.exists():
        raise SystemExit(
            f"Could not find {path}.\n"
            f"Run `python scripts/train_all.py` first to generate it, "
            f"or check that you're running this script from the project root."
        )
    return json.loads(path.read_text())


# ---------------------------------------------------------------------
# 1) NLP classifier: 3-protocol comparison
# ---------------------------------------------------------------------
def plot_protocol_comparison():
    d = load("nlp_metrics.json")
    p = d["protocols"]

    protocols = ["random_split", "group_kfold", "lofo"]
    labels = ["Random Split", "Grouped 4-Fold", "Leave-One-Library-Out"]
    accuracy = [p[k]["accuracy"] * 100 for k in protocols]
    f1 = [p[k]["f1_macro"] * 100 for k in protocols]
    fpr = [p[k]["false_positive_rate"] * 100 for k in protocols]

    x = np.arange(len(protocols))
    width = 0.26
    fig, ax = plt.subplots(figsize=(7, 3.2))
    b1 = ax.bar(x - width, accuracy, width, label="Accuracy (%)")
    b2 = ax.bar(x, f1, width, label="Macro F1 (%)")
    b3 = ax.bar(x + width, fpr, width, label="False Positive Rate (%)")

    for bars in (b1, b2, b3):
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f"{h:.1f}", (bar.get_x() + bar.get_width() / 2, h),
                        textcoords="offset points", xytext=(0, 2),
                        ha="center", fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Score (%)")
    ax.set_ylim(0, 110)
    ax.set_title("NLP Classifier Under Three Evaluation Protocols")
    ax.legend(loc="upper center", ncol=3, bbox_to_anchor=(0.5, -0.18), frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "protocol_comparison.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {OUT / 'protocol_comparison.png'}")


# ---------------------------------------------------------------------
# 2) Fingerprinting confusion matrix
# ---------------------------------------------------------------------
def plot_confusion_matrix():
    d = load("fingerprint_metrics.json")
    labels = d["labels"]
    cm = np.array(d["confusion_matrix"])

    fig, ax = plt.subplots(figsize=(7, 6.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=90, fontsize=7)
    ax.set_yticklabels(labels, fontsize=7)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    acc = d["holdout"]["accuracy"] * 100
    ax.set_title(f"Ciphertext-Fingerprinting Confusion Matrix "
                 f"({len(labels)} classes, {acc:.1f}% accuracy)")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            v = cm[i, j]
            if v > 0:
                ax.text(j, i, str(v), ha="center", va="center",
                        color="white" if v > cm.max() / 2 else "black", fontsize=7)
    fig.colorbar(im, ax=ax, fraction=0.045, pad=0.02, label="Count")
    fig.tight_layout()
    fig.savefig(OUT / "fingerprint_confusion.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {OUT / 'fingerprint_confusion.png'}")


# ---------------------------------------------------------------------
# 3) Fingerprinting feature importance (top 10)
# ---------------------------------------------------------------------
def plot_feature_importance():
    d = load("fingerprint_metrics.json")
    top = d["feature_importance_top15"][:10]
    feats = [t[0] for t in top]
    importance = [t[1] for t in top]

    fig, ax = plt.subplots(figsize=(7, 3.4))
    y = np.arange(len(feats))
    ax.barh(y, importance[::-1])
    ax.set_yticks(y)
    ax.set_yticklabels(feats[::-1], fontsize=8)
    ax.set_xlabel("Random-Forest feature importance")
    ax.set_title("Top-10 Fingerprinting Features")
    fig.tight_layout()
    fig.savefig(OUT / "feature_importance.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {OUT / 'feature_importance.png'}")


if __name__ == "__main__":
    plot_protocol_comparison()
    plot_confusion_matrix()
    plot_feature_importance()
    print(f"\nAll charts written to {OUT}/")
