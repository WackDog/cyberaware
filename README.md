# CyberAware

CyberAware is a Flask web application for practising cybersecurity awareness.

## Features

- Phishing/legitimate message scenarios
- Suspicious indicator selection
- Explainable feedback
- Score and progress tracking
- Educational URL risk checker
- 21 automated tests

## Run

```bash
python -m pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Test

```bash
python -m pytest -q
```

## Technology

Python, Flask, HTML, CSS, JavaScript and pytest.

The URL checker analyses URL text only and does not visit submitted websites.