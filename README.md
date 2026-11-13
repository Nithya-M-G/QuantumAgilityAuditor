# Quantum-Agility Auditor

**AI-Powered Post-Quantum Cryptographic Vulnerability Detection and Migration System**

Major Project Phase II (BCA 786) · Department of CSE (Artificial Intelligence)
Dayananda Sagar Academy of Technology & Management, Bangalore

**Live demo:** https://quantumagilityauditor.streamlit.app
Choose *Bundled demo project* in the sidebar and press **Run audit**. (Free apps sleep when idle; click "Wake up" if shown.)

---

## What it does

Finds quantum-vulnerable cryptography in **source code, config files, dependency manifests and network captures**, scores each finding (including Harvest-Now-Decrypt-Later risk), and produces a migration roadmap aligned to NIST FIPS 203 / 204 / 205, with replacement code.

| Module | Role |
|---|---|
| 1. Scanner | Python AST, regex for other languages, config and manifest parsers, PCAP TLS parser |
| 2. AI Detection | TF-IDF + domain markers into an SVM; ciphertext fingerprinting with Random Forest; LIME explanations |
| 3. Migration Reasoner | Five-factor risk score, NIST replacement by cryptographic purpose, generated code |
| 4. Dashboard | Streamlit UI, PDF report, CycloneDX CBOM export |

---

## Run it locally

Requires **Python 3.12 or newer**.

```bash
git clone https://github.com/Nithya-M-G/QuantumAgilityAuditor.git
cd QuantumAgilityAuditor

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt

python -m streamlit run app.py
```

The app opens at `http://localhost:8501`. Trained models are included in `models/`.

Optional:

```bash
python scripts/train_all.py        # retrain models (2-4 min)
python scripts/evaluate.py         # benchmark on the demo project
python tests/test_modules.py       # run tests
```

---

## Using the dashboard

1. Pick a target in the sidebar: bundled demo, a path, or uploaded files.
2. Set the risk context: system name, data sensitivity, lifespan.
3. Press **Run audit**.

Tabs: **CBOM**, **Risk Analysis**, **Migration Roadmap**, **Explainability**, **Fingerprinting**, **Model Metrics**, **Export** (PDF, CycloneDX JSON, CSV).

---

## Project layout

```
app.py                  Streamlit dashboard
requirements.txt
qaa/
  config.py, schema.py, pipeline.py
  module1_scanner/      AST, regex, config, dependency, network scanners
  module2_detector/     NLP classifier, fingerprinting, LIME explainer
  module3_reasoner/     risk engine, recommender
  module4_report/       PDF export
scripts/                train_all.py, evaluate.py
samples/demo_target/    demo project with planted vulnerable crypto
models/                 trained .joblib files
tests/                  test suite
```

---

## Troubleshooting

- **`ModuleNotFoundError: qaa`**: run commands from the project root.
- **`streamlit.exe` blocked by Windows policy**: use `python -m streamlit run app.py`.
- **scikit-learn `InconsistentVersionWarning`**: install the version pinned in `requirements.txt`, or retrain with `python scripts/train_all.py`.
- **Scapy error on Windows**: install Npcap, or untick "Scan .pcap network captures".
- **LIME is slow**: leave it off while scanning and use "Compute LIME for this finding".

---

## Team

Adithi Kumble (1DT23CA001) · Allenki Sai Harini (1DT23CA002) ·
Mathamsetty Satya Pravinya (1DT23CA023) · Nithya M G (1DT23CA027)

Under the guidance of **Prof. Priyanka R**, Assistant Professor, Dept. of CSE(AI).
