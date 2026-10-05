# DROID-SHIELD

Explainable Android APK Malware Risk Assessment System.

## Features
- APK upload and validation
- SHA-256 hashing
- Android manifest parsing with Androguard
- Permission risk analysis
- Activities/services/receivers/providers
- Suspicious API indicators
- Network URL/IP extraction
- Persistence and sensitive-permission combinations
- Obfuscation heuristics
- Explainable risk factors
- 0–100 risk score
- Safe / Suspicious / Malicious classification
- Interactive security dashboard

## Quick Start — Windows

1. Install Python 3.10+.
2. Open Command Prompt in this folder.
3. Create virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Run:

```bash
python app.py
```

6. Open:
http://127.0.0.1:5000

## If Python command is not recognized

Try:

```bash
py -m venv venv
venv\Scripts\activate
py -m pip install -r requirements.txt
py app.py
```

## Demo

Upload any APK you are authorized to analyze. The system performs static analysis only. It does not install or execute the APK.

## Architecture

Upload -> APK parser -> Feature extraction -> Rule-based risk engine -> Explainable result -> Dashboard

## Important limitation

This MVP is a static risk-assessment tool, not a guarantee that an APK is malware-free. Dynamic sandboxing and a validated malware dataset can be added for production/research use.

## Suggested hackathon extension

Train XGBoost on a labeled APK feature dataset and use SHAP to explain model predictions. The current rule engine provides a working fallback so the demo remains functional even without a trained ML model.
