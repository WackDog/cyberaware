# CyberAware

CyberAware is a small Flask-based cybersecurity awareness prototype. It lets users practise identifying phishing messages, select suspicious indicators, receive explainable feedback, track a session score, and inspect unfamiliar URLs using transparent educational heuristics.

## Features

- Phishing/legitimate message scenarios
- Suspicious-indicator selection
- Immediate feedback and explanations
- Session scoring and progress
- Educational URL risk checker
- Automated tests with pytest

## URL checker

The URL checker performs local string/structure analysis only. It does **not** visit the submitted website or send the URL to an external service. Current checks include:

- IP-address hostnames
- `@` symbols in the authority section
- explicit HTTP links
- excessive subdomains
- Punycode hostnames
- unusually high numbers of hyphens
- unusually long URLs
- account/security-related wording

The result is guidance rather than a malware verdict. A low result does not prove that a website is safe, and a warning does not prove that it is malicious.

## Run locally

Create and activate a virtual environment, then install dependencies:

```bash
python -m venv .venv
```

Git Bash on Windows:

```bash
source .venv/Scripts/activate
python -m pip install -r requirements.txt
```

Run the tests:

```bash
pytest -q
```

Run the app:

```bash
python app.py
```

Then open `http://127.0.0.1:5000`.

## Project structure

```text
app.py                 Flask routes and session logic
scenarios.py           Original training scenarios
url_checker.py         URL-analysis rules
static/style.css       Styling
templates/             Jinja templates
tests/                 pytest tests
```
