# CyberAware

CyberAware is a small Flask prototype for interactive cybersecurity-awareness training. Users classify simulated messages, identify suspicious indicators, receive immediate explanations, and see session progress.

## Current features

- Three original phishing/legitimate training scenarios
- Suspicious-indicator selection
- Immediate explainable feedback
- Session scoring and progress
- Results and restart flow
- Automated Flask tests with pytest

The URL risk checker from the development plan is intentionally left for the next implementation stage.

## Run locally

Create and activate a virtual environment, then install the requirements:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Git Bash:

```bash
source .venv/Scripts/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open `http://127.0.0.1:5000` in a browser.

## Run tests

```bash
pytest -q
```

## Suggested first commits

1. `Set up Flask application and scenario data`
2. `Add phishing classification workflow`
3. `Add indicator feedback and scoring`
4. `Add automated tests for training flow`

Do not create artificial/backdated commits; use these only as examples for genuine development stages.
