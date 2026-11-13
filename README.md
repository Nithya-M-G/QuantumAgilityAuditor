# Quantum-Agility Auditor

**AI-Powered Post-Quantum Cryptographic Vulnerability Detection and Migration System**

Major Project Phase II (BCA 786) · Department of CSE (Artificial Intelligence)
Dayananda Sagar Academy of Technology & Management, Bangalore

---

## What it does

Finds quantum-vulnerable cryptography across **source code, configuration files,
dependency manifests and network captures**, scores every finding on a
five-factor Harvest-Now-Decrypt-Later-aware model, and produces a migration
roadmap aligned to NIST FIPS 203 / 204 / 205 — with replacement code generated
for each finding.

```
Module 1              Module 2                 Module 3               Module 4
Multi-surface    ->   AI detection        ->   Migration         ->   Dashboard
scanner               + fingerprinting         reasoner               + export

AST (Python)          TF-IDF + domain          5-factor risk score    Streamlit UI
Regex (6 langs)       markers -> SVM           HNDL x1.3 multiplier   Risk heatmap
Config parsers        Fused with M1 hint       Purpose-keyed NIST     LIME panel
Manifest parsers      SP 800-22 + structural   replacement            PDF report
PCAP TLS parser       -> Random Forest         Code generation        CycloneDX CBOM
                      LIME explainability      Perf penalty model
```

---

## Which IDE to use

**Use VS Code.** This is a local application, not a notebook project:

| | VS Code | Google Colab |
|---|---|---|
| Streamlit dashboard | Works | Needs ngrok tunnelling, unreliable |
| Scanning a directory tree | Works | No local filesystem |
| Scapy PCAP parsing | Works | Awkward, needs uploads |
| Training the models | Works (~3 min CPU) | Works |

A Colab notebook is provided at `notebooks/Quantum_Agility_Auditor_Colab.ipynb`
for **training only**, if you want to retrain without a local Python setup. Copy
the resulting `.joblib` files into `models/` and run the dashboard locally.

**Recommended VS Code extensions:** Python (ms-python.python), Pylance, Ruff.

---

## Quick start

```bash
# 1. Get the project
cd quantum-agility-auditor

# 2. Create an environment and install
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Train the models (first run only, 2-4 minutes on CPU)
python scripts/train_all.py

# 4. Launch the dashboard
streamlit run app.py
```

Or use the one-shot launcher: `./run.sh` (macOS/Linux) or `run.bat` (Windows).

The browser opens at `http://localhost:8501`. Select **Bundled demo project**
in the sidebar and press **Run audit**.

### Other entry points

```bash
python scripts/evaluate.py              # end-to-end benchmark vs ground truth
python tests/test_modules.py            # test suite (24 tests, no pytest needed)
python -m pytest tests/ -v              # same, via pytest
```

---

## Results

### End-to-end system performance

Measured by `scripts/evaluate.py` against hand-labeled ground truth
(41 cryptographic assets) in `samples/demo_target`:

| Metric | Target (project spec) | Achieved |
|---|---|---|
| Accuracy | ≥ 85% | **100%** |
| Precision | ≥ 83% | **100%** |
| Recall | ≥ 87% | **100%** |
| F1-Score | ≥ 85% | **100%** |
| False positive rate | ≤ 12% | **0%** |
| Scan time (11 files) | < 2 min | **0.25 s** |

> **Read this honestly.** The demo project and the scanner patterns were
> authored alongside each other, and 41 assets is a small benchmark. This is a
> valid regression and smoke test — it proves every surface works and that the
> planted hard negatives (a base64 encode, an `os.urandom` token, comments
> naming MD5 and SHA-1) are correctly *not* flagged — but it is not evidence of
> real-world accuracy. **To make a stronger claim, point `scripts/evaluate.py`
> at a real open-source repository and label the results yourself.**

### Module 2 Stage 1 — NLP classifier

Three protocols, because one accuracy number on this corpus is misleading:

| Protocol | Accuracy | Macro F1 | FPR | What it means |
|---|---|---|---|---|
| Random split | 99.9% | 0.999 | 0.0% | **Do not quote this.** Near-identical template instances land on both sides of the split, so it measures memorisation. |
| **Leave-one-library-out** | **88.2%** | 0.835 | 21.2% | **The headline figure.** An entire library's API shape is removed from training, then tested. |
| Grouped 4-fold | 90.1% | 0.933 | 27.9% | Harsh lower bound: removes a quarter of all API shapes at once. |

Exact figures for your run are written to `models/nlp_metrics.json` and shown in
the dashboard's **Model Metrics** tab.

> **The FPR on the two held-out protocols exceeds the 12% spec target, and you
> should be ready for a question about it.** It is a different measurement from
> the system-level FPR of 0% in the table above. It says: when an entire library
> is held out, the classifier alone sometimes labels non-cryptographic code as
> crypto. The system FPR stays at zero because Module 1's deterministic evidence
> gates what reaches the classifier at all — the classifier is a second opinion
> on an already-flagged candidate, not the gatekeeper. That is a defensible
> architecture argument, but make it deliberately rather than being caught by it.

### Module 2 Stage 2 — Ciphertext fingerprinting

**92.1% accuracy** over 14 artifact classes. The per-class breakdown is the
interesting part:

- **100%** on RSA keys, EC keys, ECDSA signatures, all three digest lengths,
  3DES, plaintext, base64 and compressed data.
- **~50%** on AES-GCM vs ChaCha20 — near chance, and **this is the correct
  result**. See below.

---

## Two findings worth discussing at review

### 1. Randomness tests cannot identify a cipher

The design document specifies NIST SP 800-22 randomness tests as features for
identifying the algorithm from ciphertext. The full battery is implemented
(`qaa/module2_detector/fingerprint_features.py`) — monobit, block frequency,
runs, longest run, cumulative sums, approximate entropy, serial — and it does
real work: it cleanly separates cryptographic output from plaintext, base64 and
compressed data.

But it **cannot** separate AES from ChaCha20, and nothing based on randomness
can. Indistinguishability from random is the explicit design goal of both
ciphers. A statistical test that could tell them apart would *be* a
distinguishing attack, and the cipher would be considered broken.

What carries the algorithm-identifying signal is **structure**, which survives
encryption because it lives in the framing rather than the keystream:

- block alignment (AES = multiple of 16 bytes, 3DES = 8)
- ASN.1 DER framing on RSA keys and ECDSA signatures
- PEM armour (`-----BEGIN RSA PRIVATE KEY-----`)
- artifact length (16/20/32 bytes = a digest; 256 bytes = an RSA-2048 block)
- byte-value profile separating plaintext, base64 and hex from ciphertext

The feature importances confirm it: `struct_len_log`, `struct_entropy` and
`struct_compress_ratio` dominate every SP 800-22 p-value. So the battery answers
*"is this cryptographic output at all"* and the structural features answer
*"which primitive produced it"*.

### 2. Feature scaling, not model capacity, was the bottleneck

The classifier initially scored 100% on a random split and **43%** when an
entire library was held out. Four bugs caused that gap, and each is documented
in the source next to the code that fixes it:

| Bug | Effect | Fix |
|---|---|---|
| `\b` treats `_` as a word character, so `\bmd5\b` never matched `MD5_CTX` or `EVP_rc4` | every OpenSSL-style snippet invisible | identifier-aware lookaround boundaries |
| Shared scaffolding outweighed the algorithm literal — `MessageDigest.getInstance("MD5")` classified as SHA-1 | one decisive token drowned by 180k dimensions | weighted domain-marker feature block |
| Letter/digit subword splitting turned `md5` into `md 5` | destroyed the algorithm name | split on `_` and CamelCase only |
| Markers couldn't see inside CamelCase — `RSAKey` never fired the RSA marker | paramiko RSA at 0% | expand identifiers before matching |

43% → 93%+ without changing the model class or tuning a single hyperparameter.
The lesson is that on code data the decisive token is rare and the scaffolding
is frequent, so TF-IDF weighting works against you.

---

## The dataset question

**There is no public, ML-ready, labeled "code snippet → cryptographic algorithm"
dataset for post-quantum migration.** This was searched thoroughly. The closest
real artifacts are:

| Resource | What it is | Why it isn't enough |
|---|---|---|
| [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench) | 181 Java unit tests, 18 misuse categories | Labeled for *misuse*, not algorithm family. Too small to train on. |
| ApacheCryptoAPI-Bench | 121 crypto cases from 10 real Apache projects | Same labeling problem; useful for **external validation**. |
| `pqc-audit`, `cryptohound`, `cbom-scan` (PyPI) | Rule bases of existing PQC scanners | Pattern references, not training data. |
| CycloneDX CBOM spec | The output format standard | Not a dataset. |

**So the corpus is generated, and that is the right answer rather than a
compromise.** `qaa/module2_detector/corpus.py` builds ~3,200 labeled snippets
from a grammar of `template × library × language × identifier-style ×
obfuscation`, across 124 template families and 7 languages. Every template is a
real API call shape taken from the library's own documentation, so the lexical
distribution is realistic. The obfuscation layer (aliased imports, wrapper
functions, misleading identifier names, interleaved noise) is the point: it
produces exactly the usage a keyword scanner misses.

**For your report:** train on the generated corpus, and cite
ApacheCryptoAPI-Bench as an external validation target. Say plainly that the
corpus is synthetic and explain why — that is a stronger position than implying
a public dataset exists.

---

## Project layout

```
quantum-agility-auditor/
├── app.py                         Module 4 · Streamlit dashboard
├── requirements.txt
├── run.sh / run.bat               one-shot setup and launch
│
├── qaa/
│   ├── config.py                  algorithm KB, NIST map, scoring constants
│   ├── schema.py                  Finding -> SBOMEntry -> RiskAssessment
│   ├── pipeline.py                end-to-end orchestration + CycloneDX export
│   │
│   ├── module1_scanner/
│   │   ├── ast_scanner.py         Python AST with import-alias resolution
│   │   ├── regex_scanner.py       Java/JS/C++/Go/C#/Rust, comment-stripped
│   │   ├── config_scanner.py      nginx, apache, sshd, .env, openssl.cnf
│   │   ├── dependency_scanner.py  9 manifest formats
│   │   ├── network_scanner.py     PCAP TLS handshake parser
│   │   └── orchestrator.py        file routing + scan statistics
│   │
│   ├── module2_detector/
│   │   ├── corpus.py              labeled corpus generator
│   │   ├── lexicon_features.py    domain-marker feature block
│   │   ├── nlp_classifier.py      TF-IDF + markers -> SVM, fused with M1
│   │   ├── fingerprint_features.py SP 800-22 battery + structural features
│   │   ├── fingerprint.py         artifact generation + Random Forest
│   │   └── explainer.py           LIME + deterministic marker evidence
│   │
│   ├── module3_reasoner/
│   │   ├── risk_engine.py         five-factor HNDL-aware scoring
│   │   └── recommender.py         NIST mapping, perf model, code generation
│   │
│   └── module4_report/
│       └── pdf_export.py          ReportLab executive report
│
├── scripts/
│   ├── train_all.py               train both models, 3 evaluation protocols
│   └── evaluate.py                end-to-end benchmark vs ground truth
│
├── samples/demo_target/           deliberately vulnerable demo project
├── tests/test_modules.py          24 tests across all four modules
├── notebooks/                     Colab training notebook
├── models/                        trained .joblib files (generated)
└── data/                          corpus + benchmark results (generated)
```

---

## How the risk score works

```
base   = severity_table[algorithm]              # RSA 9.0, ECC 9.5, DES 10.0 …
if key_size < NIST_minimum:     base += 2       # RSA-1024 < 3072
if sensitivity in {financial, medical, …}: base *= 1.5
if system_lifespan > 5 years:   base *= 1.3     # ← HNDL multiplier
base *= surface_weight                          # network 1.10, dependency 0.85
base *= confidence_adjustment                   # maps to [0.75, 1.0]

Critical > 8   ·   High > 5   ·   Medium > 2   ·   Low > 0
```

The **HNDL multiplier** is what makes this different from a conventional
scanner. "Harvest Now, Decrypt Later" means an adversary records ECDHE-protected
traffic today and decrypts it once a cryptographically relevant quantum computer
exists. A key exchange protecting data with a 20-year confidentiality
requirement is therefore *already* compromised. A scanner that scores only
present-day exploitability rates that as low risk, which is exactly backwards.

Two additions beyond the base specification, both flagged as such in the source:

- **Surface weighting** — a cipher suite seen in a live PCAP is confirmed
  exposure; the same algorithm in a manifest may never be reached at runtime.
- **Uncapped score retention** — the reported score is capped to 0–10 as
  specified, but the uncapped value is kept for ordering. Without it, every
  worst-case finding reports exactly 10.0 and the roadmap cannot rank within the
  Critical band.

---

## Recommendations are purpose-aware, not name-aware

RSA used for key transport migrates to **ML-KEM (FIPS 203)**. RSA used to sign a
JWT migrates to **ML-DSA (FIPS 204)**. A mapping keyed on the algorithm *name*
cannot make that distinction and emits the wrong standard for one of the two.
The mapping is keyed on `(cryptographic_purpose, security_tier)` instead.

| Purpose | Standard tier | High tier (financial / medical / defence / >10y) |
|---|---|---|
| Key exchange | ML-KEM-768 (FIPS 203) | ML-KEM-1024 |
| Signature | ML-DSA-65 (FIPS 204) | ML-DSA-87, or SLH-DSA (FIPS 205) for firmware |
| Bulk encryption | AES-256-GCM | AES-256-GCM |
| Hashing | SHA-256 | SHA3-512 |

---

## Troubleshooting

**`No trained model found`** — run `python scripts/train_all.py` first.

**`ModuleNotFoundError: qaa`** — run commands from the project root, not from
inside `scripts/`.

**Scapy import error on Windows** — PCAP scanning needs Npcap. Everything else
works without it; untick "Scan .pcap network captures" in the sidebar.

**LIME is slow** — it perturbs each snippet a few hundred times. Leave it off
during scanning and use the "Compute LIME for this finding" button on demand.
Marker evidence is deterministic and always instant.

**Training is slow** — use `python scripts/train_all.py --quick` to skip the
leave-one-library-out sweep (that sweep is ~80% of the runtime).

---

## References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM), 2024.
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA), 2024.
3. NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA), 2024.
4. NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths.
5. NIST SP 800-22 Rev. 1a — A Statistical Test Suite for Random and Pseudorandom Number Generators.
6. NSA CNSA 2.0 — Commercial National Security Algorithm Suite.
7. S. Afrose et al., "Evaluation of Static Vulnerability Detection Tools with Java Cryptographic API Benchmarks," arXiv:2112.04037.
8. CycloneDX 1.6 — Cryptography Bill of Materials specification.

---

## Team

Adithi Kumble (1DT23CA001) · Allenki Sai Harini (1DT23CA002) ·
Mathamsetty Satya Pravinya (1DT23CA023) · Nithya M G (1DT23CA027)

Under the guidance of **Prof. Priyanka R**, Assistant Professor, Dept. of CSE(AI).
