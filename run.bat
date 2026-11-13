@echo off
REM One-shot setup and launch for Windows.
cd /d "%~dp0"

if not exist ".venv\" (
  echo ==^> creating virtual environment
  python -m venv .venv
)
call .venv\Scripts\activate.bat

echo ==^> installing dependencies
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt

if not exist "models\nlp_classifier.joblib" (
  echo ==^> training models ^(first run only, 2-4 minutes^)
  python scripts\train_all.py
)

echo ==^> launching dashboard at http://localhost:8501
streamlit run app.py
