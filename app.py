"""
Quantum-Agility Auditor - Module 4: Dashboard and Output Layer.

Run with:   streamlit run app.py

Tabs
----
    Scan            target selection, context, live progress
    CBOM            the Cryptographic Bill of Materials, colour-coded
    Risk Analysis   distribution charts and the score derivation
    Roadmap         prioritised migration plan with replacement code
    Explainability  LIME token attribution + marker evidence
    Fingerprint     upload a binary artifact, run the SP 800-22 battery
    Model Metrics   the three evaluation protocols, stated honestly
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from qaa.config import (
    ALGORITHM_DB,
    FP_METRICS_PATH,
    FP_MODEL_PATH,
    NLP_METRICS_PATH,
    NLP_MODEL_PATH,
    SAMPLES_DIR,
    SENSITIVITY_MULTIPLIER,
)
from qaa.module2_detector.explainer import LimeCryptoExplainer, marker_evidence
from qaa.module2_detector.nlp_classifier import CryptoNLPClassifier
from qaa.module3_reasoner.risk_engine import explain_score
from qaa.module4_report.pdf_export import build_pdf
from qaa.pipeline import run_audit, to_cyclonedx
from qaa.schema import ScanContext

st.set_page_config(page_title="Quantum-Agility Auditor", page_icon="🔐",
                   layout="wide", initial_sidebar_state="expanded")

LEVEL_STYLE = {
    "Critical": ("#B3261E", "#FDECEA"),
    "High": ("#E8710A", "#FEF3E6"),
    "Medium": ("#B58900", "#FDF8E4"),
    "Low": ("#3D7A3D", "#EDF7ED"),
    "Informational": ("#5A6672", "#F1F3F5"),
}
def arrow_safe(df: pd.DataFrame) -> pd.DataFrame:
    """Make mixed int/'—' columns display as text so pyarrow doesn't warn."""
    df = df.copy()
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].map(lambda v: "" if v is None else str(v))
    return df
st.markdown("""
<style>
  .block-container {padding-top: 2rem; max-width: 1400px;}
  .qaa-metric {border-radius:10px; padding:14px 16px; border:1px solid #E3E8EE;}
  .qaa-metric h2 {margin:0; font-size:1.9rem; line-height:1.1;}
  .qaa-metric p {margin:2px 0 0; font-size:.78rem; color:#5A6672;
                 text-transform:uppercase; letter-spacing:.04em;}
  .qaa-banner {border-left:4px solid #B3261E; background:#FDECEA;
               padding:12px 16px; border-radius:6px; margin:8px 0 16px;}
  code {font-size:.82rem;}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner=False)
def load_classifier():
    return CryptoNLPClassifier.load()


@st.cache_resource(show_spinner=False)
def load_fingerprinter():
    from qaa.module2_detector.fingerprint import FingerprintClassifier
    return FingerprintClassifier.load()


@st.cache_data(show_spinner=False)
def load_metrics(path_str: str):
    p = Path(path_str)
    return json.loads(p.read_text()) if p.exists() else None


def models_ready() -> bool:
    return NLP_MODEL_PATH.exists()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.title("🔐 Quantum-Agility Auditor")
st.sidebar.caption("AI-powered post-quantum cryptographic vulnerability "
                   "detection and migration system")

if not models_ready():
    st.sidebar.error("Models not trained yet.")
    st.error(
        "**No trained model found.** Run this once before using the dashboard:\n\n"
        "```bash\npython scripts/train_all.py\n```\n\n"
        "It takes 2-4 minutes and writes `models/nlp_classifier.joblib` and "
        "`models/fingerprint_classifier.joblib`."
    )
    st.stop()

st.sidebar.subheader("Scan target")
demo_path = SAMPLES_DIR / "demo_target"
mode = st.sidebar.radio(
    "Source", ["Bundled demo project", "Path on this machine", "Upload files"],
    label_visibility="collapsed")

target_path: Path | None = None
if mode == "Bundled demo project":
    target_path = demo_path
    st.sidebar.caption(f"`{demo_path}`")
elif mode == "Path on this machine":
    raw = st.sidebar.text_input("Absolute path to scan", value=str(demo_path))
    target_path = Path(raw) if raw else None
else:
    uploads = st.sidebar.file_uploader(
        "Source, config, manifest or .pcap files", accept_multiple_files=True)
    if uploads:
        tmp = Path(tempfile.mkdtemp(prefix="qaa_upload_"))
        for u in uploads:
            (tmp / u.name).write_bytes(u.getbuffer())
        target_path = tmp
        st.sidebar.success(f"{len(uploads)} file(s) staged")

st.sidebar.subheader("Risk context")
st.sidebar.caption("These drive the Module 3 multipliers.")
system_name = st.sidebar.text_input("System name", "Customer Payment Portal")
sensitivity = st.sidebar.selectbox(
    "Data sensitivity", list(SENSITIVITY_MULTIPLIER.keys()), index=2)
lifespan = st.sidebar.slider("Expected system lifespan (years)", 1, 30, 15)

if lifespan > 5:
    st.sidebar.warning(
        f"**HNDL exposure.** Lifespan {lifespan}y exceeds the 5-year threshold, "
        f"so a ×1.3 Harvest-Now-Decrypt-Later multiplier applies.")

include_pcap = st.sidebar.checkbox("Scan .pcap network captures", value=True)
run_lime = st.sidebar.checkbox(
    "Compute LIME attributions", value=False,
    help="LIME perturbs each snippet a few hundred times, so it adds a few "
         "seconds per finding. Marker evidence is always available instantly.")

scan_clicked = st.sidebar.button("Run audit", type="primary",
                                 width="stretch")

# ---------------------------------------------------------------------------
# Run the audit
# ---------------------------------------------------------------------------
if scan_clicked:
    if not target_path or not Path(target_path).exists():
        st.sidebar.error("Target path does not exist.")
    else:
        ctx = ScanContext(data_sensitivity=sensitivity,
                          system_lifespan_years=lifespan,
                          system_name=system_name)
        bar = st.progress(0.0, text="Starting scan …")

        def _progress(path, i, total):
            bar.progress(min(i / max(total, 1), 1.0),
                         text=f"Module 1 · scanning {Path(path).name}")

        t0 = time.perf_counter()
        result = run_audit(target_path, context=ctx,
                           classifier=load_classifier(),
                           include_pcap=include_pcap, progress=_progress)
        bar.progress(1.0, text=f"Done in {time.perf_counter() - t0:.2f}s")
        time.sleep(0.25)
        bar.empty()

        if run_lime and result.sbom:
            with st.spinner("Computing LIME attributions …"):
                ex = LimeCryptoExplainer(load_classifier())
                for e in result.sbom[:25]:
                    ex.explain_entry(e)

        st.session_state["result"] = result

result = st.session_state.get("result")

if result is None:
    st.title("Quantum-Agility Auditor")
    st.markdown(
        "Detects quantum-vulnerable cryptography across **source code, "
        "configuration, dependency manifests and network captures**, scores "
        "each finding on a five-factor HNDL-aware model, and produces a "
        "NIST FIPS 203/204/205-aligned migration roadmap.\n\n"
        "Pick a target in the sidebar and press **Run audit**. The bundled "
        "demo project contains deliberately planted vulnerable cryptography "
        "across every supported surface."
    )
    c1, c2, c3, c4 = st.columns(4)
    for col, (title, body) in zip([c1, c2, c3, c4], [
        ("Module 1 · Scanner",
         "Python AST with import-alias resolution, API-shaped regex for "
         "Java/JS/C++/Go/C#, config and manifest parsers, and a TLS handshake "
         "parser for PCAP."),
        ("Module 2 · AI Detection",
         "TF-IDF + domain-marker features into an SVM, fused with the "
         "deterministic scanner hint. Ciphertext fingerprinting via the "
         "NIST SP 800-22 battery plus structural features."),
        ("Module 3 · Migration Reasoner",
         "Five-factor risk score with a ×1.3 HNDL multiplier, context-aware "
         "NIST replacement keyed on cryptographic purpose, and generated "
         "replacement code."),
        ("Module 4 · Dashboard",
         "Colour-coded CBOM, risk heatmap, LIME explanation panel, "
         "prioritised roadmap, and one-click PDF and CycloneDX export."),
    ]):
        col.markdown(f"**{title}**")
        col.caption(body)
    st.stop()


# ---------------------------------------------------------------------------
# Header metrics
# ---------------------------------------------------------------------------
s = result.summary()
st.title(f"Audit · {result.context.system_name}")

cols = st.columns(6)
for col, (val, label, color) in zip(cols, [
    (s["total_findings"], "Findings", "#1B3A5C"),
    (s["cbom_entries"], "CBOM entries", "#1B3A5C"),
    (s["critical"], "Critical", "#B3261E"),
    (s["high"], "High", "#E8710A"),
    (s["medium"], "Medium", "#B58900"),
    (s["already_pqc"], "Already PQC", "#3D7A3D"),
]):
    col.markdown(
        f"<div class='qaa-metric'><h2 style='color:{color}'>{val}</h2>"
        f"<p>{label}</p></div>", unsafe_allow_html=True)

if result.context.hndl_exposed:
    st.markdown(
        f"<div class='qaa-banner'><b>Harvest-Now-Decrypt-Later exposure.</b> "
        f"This system has a {result.context.system_lifespan_years}-year "
        f"lifespan, so data protected today must stay confidential past the "
        f"expected arrival of a cryptographically relevant quantum computer. "
        f"Traffic an adversary records now is decryptable later — key-exchange "
        f"findings below are already compromised, not merely at risk. "
        f"A ×1.3 multiplier has been applied.</div>",
        unsafe_allow_html=True)

st.caption(
    f"Module 1 {result.timings['module1_scan']:.2f}s · "
    f"Module 2 {result.timings['module2_classify']:.2f}s · "
    f"Module 3 {result.timings['module3_reason']:.3f}s · "
    f"{result.stats.files_scanned} files scanned, "
    f"{result.stats.files_skipped} skipped")

tabs = st.tabs(["CBOM", "Risk Analysis", "Migration Roadmap",
                "Explainability", "Fingerprinting", "Model Metrics", "Export"])

# ---------------------------------------------------------------------------
# Tab 1 - CBOM
# ---------------------------------------------------------------------------
with tabs[0]:
    st.subheader("Cryptographic Bill of Materials")
    st.caption("Every cryptographic asset found, with the surface it was found "
               "on and the classifier's confidence.")

    rows = []
    for a in result.roadmap:
        e = a.sbom_entry
        rows.append({
            "Level": a.risk_level, "Score": a.risk_score,
            "Algorithm": e.algorithm, "Purpose": e.purpose,
            "File": Path(e.finding.file_path).name, "Line": e.finding.line_number,
            "Surface": e.finding.surface,
"Key size": str(e.finding.key_size) if e.finding.key_size else "—",
            "Confidence": round(e.confidence, 3),
            "Detected by": e.detection_method,
            "Evidence": e.finding.snippet.strip().replace("\n", " ⏎ ")[:110],
        })
    df = pd.DataFrame(rows)

    c1, c2, c3 = st.columns(3)
    lv = c1.multiselect("Risk level", sorted(df["Level"].unique()),
                        default=sorted(df["Level"].unique()))
    sf = c2.multiselect("Surface", sorted(df["Surface"].unique()),
                        default=sorted(df["Surface"].unique()))
    al = c3.multiselect("Algorithm", sorted(df["Algorithm"].unique()),
                        default=sorted(df["Algorithm"].unique()))
    view = df[df["Level"].isin(lv) & df["Surface"].isin(sf)
              & df["Algorithm"].isin(al)]
    def _row_style(r):
        fg, bg = LEVEL_STYLE.get(r["Level"], ("#000", "#FFF"))
        return [f"background-color:{bg}"] * len(r)

    st.dataframe(arrow_safe(view).style.apply(_row_style, axis=1),
                 width="stretch", height=520, hide_index=True)
    st.caption(f"{len(view)} of {len(df)} entries shown.")

# ---------------------------------------------------------------------------
# Tab 2 - Risk analysis
# ---------------------------------------------------------------------------
with tabs[1]:
    st.subheader("Risk distribution")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**By severity**")
        lc = result.level_counts()
        st.bar_chart(pd.DataFrame({"findings": lc}), height=260)
        st.markdown("**By surface**")
        st.bar_chart(pd.DataFrame({"findings": result.surface_counts()}),
                     height=240)
    with c2:
        st.markdown("**By algorithm**")
        st.bar_chart(pd.DataFrame({"findings": result.algorithm_counts()}),
                     height=260)
        st.markdown("**Risk score distribution**")
        scores = pd.DataFrame({"score": [a.risk_score
                                         for a in result.actionable]})
        if len(scores):
            st.bar_chart(scores["score"].value_counts().sort_index(),
                         height=240)

    st.divider()
    st.subheader("Score derivation")
    st.caption("Every multiplier that produced each score, so the number is "
               "auditable rather than opaque.")
    for a in result.actionable[:12]:
        e = a.sbom_entry
        fg, _ = LEVEL_STYLE.get(a.risk_level, ("#000", "#FFF"))
        with st.expander(
            f"{a.risk_score:.2f}  ·  {a.risk_level}  ·  {e.algorithm}  —  "
            f"{Path(e.finding.file_path).name}:{e.finding.line_number}"
        ):
            st.code(explain_score(a.score_breakdown), language="text")
            b = a.score_breakdown
            cc1, cc2 = st.columns(2)
            cc1.markdown(
                f"- **Threat class:** {b.get('threat_class')}\n"
                f"- **Base severity:** {b.get('base_severity')}\n"
                f"- **Undersized key:** "
                f"{b.get('undersized_key') or 'no penalty'}\n"
                f"- **Sensitivity:** {b.get('sensitivity')}")
            cc2.markdown(
                f"- **HNDL applied:** {b.get('hndl', {}).get('applied')}\n"
                f"- **Surface weight:** {b.get('surface')}\n"
                f"- **Confidence adj.:** {b.get('confidence_adjustment')}\n"
                f"- **Final:** **{b.get('final_score')}**")
            if b.get("hndl", {}).get("applied"):
                st.info(b["hndl"]["rationale"])
            st.caption(ALGORITHM_DB.get(e.algorithm, {}).get("description", ""))

# ---------------------------------------------------------------------------
# Tab 3 - Roadmap
# ---------------------------------------------------------------------------

with tabs[2]:
    st.subheader("Prioritised migration roadmap")
    st.caption("Critical first. The replacement is keyed on cryptographic "
               "purpose, so RSA for key transport maps to ML-KEM while RSA for "
               "signing maps to ML-DSA.")

    road = arrow_safe(pd.DataFrame(result.roadmap_rows()))
if len(road):
    st.dataframe(road, width="stretch", height=300, hide_index=True)

    st.divider()
    for i, a in enumerate(result.actionable[:15], start=1):
        e = a.sbom_entry
        fg, bg = LEVEL_STYLE.get(a.risk_level, ("#000", "#FFF"))
        with st.expander(
            f"{i}. {e.algorithm} → {a.replacement}  ·  {a.risk_level} "
            f"({a.risk_score:.2f})  ·  {Path(e.finding.file_path).name}:"
            f"{e.finding.line_number}",
            expanded=(i == 1),
        ):
            c1, c2, c3 = st.columns(3)
            c1.metric("NIST standard", a.nist_standard.replace("NIST ", ""))
            c2.metric("Security level", a.nist_level.split("(")[0].strip())
            c3.metric("Migration effort", a.effort)

            st.markdown(f"**Transitional option:** {a.hybrid_option}")
            st.markdown(f"**Library:** `{a.recommended_library}`")
            st.markdown(f"**Performance:** {a.performance_note}")
            st.markdown(f"**Effort note:** {a.effort_note}")
            st.markdown("**Replacement code**")
            st.code(a.code_snippet, language=a.snippet_language)

# ---------------------------------------------------------------------------
# Tab 4 - Explainability
# ---------------------------------------------------------------------------
with tabs[3]:
    st.subheader("Why the model made each call")
    st.caption("Marker evidence is deterministic and instant. LIME perturbs "
               "the snippet a few hundred times to attribute the decision to "
               "individual tokens.")

    if not result.sbom:
        st.info("No findings to explain.")
    else:
        labels = [
            f"{i+1}. {a.sbom_entry.algorithm} — "
            f"{Path(a.sbom_entry.finding.file_path).name}:"
            f"{a.sbom_entry.finding.line_number}"
            for i, a in enumerate(result.roadmap)
        ]
        pick = st.selectbox("Finding", range(len(labels)),
                            format_func=lambda i: labels[i])
        entry = result.roadmap[pick].sbom_entry

        c1, c2 = st.columns([1.15, 1])
        with c1:
            st.markdown("**Evidence**")
            st.code(entry.finding.snippet, language=entry.finding.language)
            st.markdown(
                f"- **Predicted:** `{entry.algorithm}` "
                f"(confidence {entry.confidence:.3f})\n"
                f"- **Method:** `{entry.detection_method}`\n"
                f"- **Matched pattern:** `{entry.finding.matched_pattern}`")
            if entry.probability_vector:
                st.markdown("**Posterior over classes**")
                st.bar_chart(pd.DataFrame(
                    {"probability": entry.probability_vector}), height=220)

        with c2:
            st.markdown("**Marker evidence** (deterministic)")
            ev = marker_evidence(entry.finding.snippet)
            if ev:
                st.dataframe(
                    pd.DataFrame(ev, columns=["Marker", "Matched text"]),
                    width="stretch", hide_index=True, height=260)
            else:
                st.caption("No domain markers fired on this snippet.")

            st.markdown("**LIME token attribution**")
            if entry.lime_tokens:
                lime_df = pd.DataFrame(entry.lime_tokens,
                                       columns=["token", "weight"])
                st.bar_chart(lime_df.set_index("token"), height=260)
                st.caption("Positive weight pushed the model toward this "
                           "class; negative pushed away.")
            elif st.button("Compute LIME for this finding"):
                with st.spinner("Perturbing …"):
                    LimeCryptoExplainer(load_classifier()).explain_entry(entry)
                st.rerun()
            else:
                st.caption("Not computed yet. Enable it in the sidebar before "
                           "scanning, or press the button above.")

# ---------------------------------------------------------------------------
# Tab 5 - Fingerprinting
# ---------------------------------------------------------------------------
with tabs[4]:
    st.subheader("Ciphertext / binary artifact fingerprinting")
    st.caption("Identifies a cryptographic primitive from a binary artifact "
               "with no source code available.")

    st.info(
        "**A note on what this can and cannot do.** The NIST SP 800-22 battery "
        "is implemented in full and separates cryptographic output from "
        "plaintext, base64 and compressed data reliably. It cannot separate one "
        "modern cipher from another, and no randomness-based feature can: "
        "indistinguishability from random is the design goal of AES and "
        "ChaCha20, so a test that told them apart would be a distinguishing "
        "attack. The algorithm-identifying signal comes from *structure* — "
        "block alignment, ASN.1 DER framing, PEM armour, artifact length — "
        "which survives encryption because it lives in the framing.")

    if not FP_MODEL_PATH.exists():
        st.warning("Fingerprint model not trained. Run `python scripts/"
                   "train_all.py`.")
    else:
        up = st.file_uploader("Binary artifact (key, ciphertext, signature, "
                              "digest…)", type=None, key="fp_upload")
        if up is not None:
            data = up.getvalue()
            res = load_fingerprinter().predict(data)
            c1, c2, c3 = st.columns(3)
            c1.metric("Fingerprint class", res["fingerprint_class"])
            c2.metric("Implied algorithm", res["implied_algorithm"])
            c3.metric("Confidence", f"{res['confidence']:.3f}")
            st.caption(f"Artifact size: {res['artifact_bytes']} bytes")

            cc1, cc2 = st.columns(2)
            with cc1:
                st.markdown("**Top candidates**")
                st.dataframe(pd.DataFrame(res["top3"],
                                          columns=["class", "probability"]),
                             hide_index=True, width="stretch")
            with cc2:
                st.markdown("**NIST SP 800-22 p-values**")
                sp = pd.DataFrame(
                    sorted(res["sp800_22"].items()),
                    columns=["test", "p-value"])
                st.dataframe(sp, hide_index=True, width="stretch")
                st.caption("p < 0.01 rejects the randomness hypothesis. "
                           "Cryptographic output should pass every test.")

        st.divider()
        st.markdown("**Feature importance**")
        st.caption("Note how strongly the structural features dominate the "
                   "statistical ones — that is the point being made above.")
        st.dataframe(
            pd.DataFrame(load_fingerprinter().feature_importance(12),
                         columns=["feature", "importance"]),
            hide_index=True, width="stretch")

# ---------------------------------------------------------------------------
# Tab 6 - Model metrics
# ---------------------------------------------------------------------------
with tabs[5]:
    st.subheader("Model evaluation")
    nlp_m = load_metrics(str(NLP_METRICS_PATH))
    fp_m = load_metrics(str(FP_METRICS_PATH))

    if nlp_m:
        c = nlp_m["corpus"]
        st.markdown(
            f"**Corpus:** {c['total']} snippets · {c['classes']} classes · "
            f"{c['template_families']} template families · "
            f"{len(c['by_language'])} languages")

        st.warning(
            "**Read the protocol, not just the number.** A random split on "
            "this corpus reports near-100% accuracy, and that figure is "
            "close to meaningless: near-identical template instances land on "
            "both sides of the split, so it measures memorisation. The "
            "leave-one-library-out figure is the one to quote — an entire "
            "library's API shape is removed from training before testing.")

        rows = []
        for key, nice in [("random_split", "Random split (optimistic)"),
                          ("lofo", "Leave-one-library-out (headline)"),
                          ("group_kfold", "Grouped 4-fold (lower bound)")]:
            p = nlp_m["protocols"].get(key, {})
            if p.get("skipped"):
                continue
            rows.append({
                "Protocol": nice,
                "Accuracy": p.get("accuracy"),
                "Precision (macro)": p.get("precision_macro"),
                "Recall (macro)": p.get("recall_macro"),
                "F1 (macro)": p.get("f1_macro"),
                "False positive rate": p.get("false_positive_rate"),
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True,
                     width="stretch")

        for key, nice in [("lofo", "Leave-one-library-out"),
                          ("group_kfold", "Grouped 4-fold")]:
            p = nlp_m["protocols"].get(key, {})
            if p.get("note"):
                st.caption(f"**{nice}:** {p['note']}")

        weak = nlp_m["protocols"].get("lofo", {}).get("weakest_families")
        if weak:
            with st.expander("Which held-out libraries the model handles worst"):
                st.dataframe(
                    pd.DataFrame(sorted(weak.items()),
                                 columns=["template family", "accuracy"]),
                    hide_index=True, width="stretch")
                st.caption(
                    "These are the genuinely hard cases: libraries whose API "
                    "never names the algorithm (pyca Fernet is AES; the "
                    "`elliptic` npm package is ECDSA), or where one library is "
                    "the only example of a given spelling in the corpus.")

    st.divider()
    if fp_m:
        st.markdown("**Fingerprint classifier (Module 2 Stage 2)**")
        h = fp_m["holdout"]
        c1, c2, c3 = st.columns(3)
        c1.metric("Accuracy", f"{h['accuracy']:.3f}")
        c2.metric("Macro F1", f"{h['f1_macro']:.3f}")
        c3.metric("Test artifacts", h["n_test"])
        st.info(fp_m["interpretation"])
        with st.expander("Per-class results"):
            rep = fp_m["classification_report"]
            st.dataframe(pd.DataFrame({
                k: v for k, v in rep.items() if isinstance(v, dict)
            }).T.round(3), width="stretch")

# ---------------------------------------------------------------------------
# Tab 7 - Export
# ---------------------------------------------------------------------------
with tabs[6]:
    st.subheader("Export")
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("**Executive PDF report**")
        st.caption("Summary, distribution, roadmap, detailed findings with "
                   "replacement code, methodology and NIST references.")
        if st.button("Generate PDF", type="primary"):
            with st.spinner("Rendering …"):
                st.session_state["pdf"] = build_pdf(result)
        if st.session_state.get("pdf"):
            st.download_button(
                "Download PDF", st.session_state["pdf"],
                file_name=f"quantum_agility_audit_"
                          f"{time.strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf", width="stretch")

    with c2:
        st.markdown("**CycloneDX 1.6 CBOM**")
        st.caption("Machine-readable inventory in the standard format that "
                   "compliance tooling and CBOM viewers consume.")
        st.download_button(
            "Download CBOM (JSON)",
            json.dumps(to_cyclonedx(result), indent=2),
            file_name="cbom.json", mime="application/json",
            width="stretch")

    with c3:
        st.markdown("**Raw findings**")
        st.caption("Full roadmap as CSV for spreadsheet analysis.")
        st.download_button(
            "Download roadmap (CSV)",
            pd.DataFrame(result.roadmap_rows()).to_csv(index=False),
            file_name="roadmap.csv", mime="text/csv",
            width="stretch")

    if result.stats and result.stats.errors:
        st.divider()
        with st.expander(f"Scanner warnings ({len(result.stats.errors)})"):
            for e in result.stats.errors:
                st.text(e)
