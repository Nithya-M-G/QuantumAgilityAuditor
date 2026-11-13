#!/usr/bin/env bash
# One-shot setup and launch for macOS / Linux.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "==> creating virtual environment"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> installing dependencies"
pip install -q --upgrade pip
pip install -q -r requirements.txt

if [ ! -f "models/nlp_classifier.joblib" ]; then
  echo "==> training models (first run only, 2-4 minutes)"
  python scripts/train_all.py
fi

echo "==> launching dashboard at http://localhost:8501"
streamlit run app.py
