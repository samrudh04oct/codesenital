# 🛡️ CodeSentinel AI

CodeSentinel AI is a local, security-focused code review application that helps developers analyze uploaded project ZIP files for risky code patterns, insecure logic, and maintainability issues. The system combines deterministic static analysis with Gemini-based AI review to produce a clean, explainable project report.

## Project overview

This project was designed to solve a common problem in code review: developers often need a fast, structured way to review a project before deployment without exposing secrets or running code from an untrusted source.

CodeSentinel AI does this by:

- accepting a ZIP upload from a user
- validating and extracting the project safely
- identifying secret files and redacting secret-like strings
- running local static analysis using Ruff and Bandit
- asking Gemini to review the cleaned source for deeper logic and security issues
- merging findings into a single result
- scoring the project on a deterministic 0-100 scale
- displaying the results via a Streamlit dashboard

## Key features and capabilities

- Secure ZIP upload validation and extraction
- Path traversal prevention and zip-slip protection
- Secret file blocking for .env, .pem, .key, credentials files, and similar patterns
- Secret redaction for API keys, tokens, passwords, and private key material
- Local execution of linting and security checks without running user code
- AI-assisted deeper review using Gemini structured output
- Merge of static and AI findings into one unified report
- Deterministic 0-100 rating system
- Web-based dashboard built with Streamlit
- Results grouped by file and severity for easier developer review
- Support for Python, JavaScript, and TypeScript source code review

## Architecture overview

CodeSentinel AI follows a pipeline architecture:

1. Ingestion: the user uploads a ZIP file
2. Validation: archive size, file count, file sizes, and traversal paths are checked
3. Extraction: files are unpacked into a temporary safe workspace
4. Discovery: supported source files are found and classified
5. Protection: secret files and secret values are filtered out or redacted
6. Analysis: Ruff and Bandit scan the extracted code
7. Review: Gemini reviews the cleaned source with a strict JSON schema
8. Merge: all findings are combined into a single result set
9. Scoring: a fixed scoring model converts findings to a project rating
10. Presentation: Streamlit renders the dashboard and detailed findings

---

## Tech stack

### Core application stack
- Python 3.12+
- Streamlit for the frontend dashboard and upload workflow
- Google GenAI SDK for Gemini-powered code evaluation
- python-dotenv for environment configuration

### Security and static analysis tools
- Ruff for Python linting and code quality checks
- Bandit for Python security checks
- Custom validation logic for ZIP safety and secret detection

### Supporting libraries
- pathlib and zipfile for secure file handling
- dataclasses for typed findings model
- json for structured AI response handling
- subprocess for invoking local analysis tools

### Input and review model
- ZIP-based upload workflow
- Supported source file types: .py, .js, .ts, .tsx, .jsx
- Structured JSON response schema from Gemini
- Deterministic score computation from a fixed penalty table

---

## Challenges faced during development

### 1. Safe handling of uploaded project files
A major challenge was to review untrusted code without executing it. The app reads source files, but never executes uploaded code. This required secure ZIP validation, path traversal checks, and strict limits on file count and file sizes.

### 2. Secret protection
The project needed to prevent API keys, tokens, passwords, private keys, and credentials from ever reaching Gemini. This was solved by:

- skipping known secret file names such as .env, .pem, .key, credentials.json
- redacting secret-like strings inside source files before sending code to AI
- removing private-key material and API-key-like patterns from the prompt

### 3. Untrusted archive security
ZIP archives can contain malicious path traversal entries such as ../ or absolute paths. The solution implemented ZIP-slip protection and refused any archive entry that attempted to escape the extraction directory.

### 4. Model reliability and API compatibility
Gemini model names evolve frequently, and older model names can become unavailable. The app needed a fallback mechanism so it could keep working when a specific model is retired or blocked. This was addressed by trying a supported list of models instead of a single hardcoded one.

### 5. Deterministic scoring
AI systems can be unpredictable, so score generation was designed to be deterministic and explainable. The final score is not invented by Gemini; instead, it is calculated from a fixed severity-to-penalty mapping.

### 6. Balancing AI insight with static analysis
Static tools catch many known patterns quickly, but they miss some logic issues and architecture concerns. The project combines both approaches so that AI adds context and reasoning without replacing the reliable local checks.

### 7. Large-project constraints
Projects can be big, and sending the entire codebase to an AI model is not always practical. The app caps the size of the code blob and reads only a limited number of supported files, ensuring the review remains manageable and safe.

---

## How the project works

The workflow is:

1. User uploads a ZIP archive
2. The app validates the ZIP size and content
3. Files are safely extracted into a temporary workspace
4. The app discovers supported source files
5. Secret files are skipped
6. Ruff and Bandit run locally on the extracted project
7. Secrets inside source files are redacted before AI review
8. Gemini reviews the cleaned project for logic, security, and maintainability issues
9. Static findings and AI findings are merged
10. A deterministic score is computed based on severity and category
11. The results are shown on the dashboard

### High-level pipeline

Upload ZIP → Validate → Safe extract → Source discovery → Secret filtering → Ruff + Bandit → Gemini review → Merge findings → Score project → Display dashboard

---

## Folder structure

```text
CodeSentinelAI/
├── app.py                     # Streamlit UI and orchestration logic
├── gemini_review.py           # Gemini API integration and structured JSON prompt
├── scoring.py                 # Severity-based deterministic scoring logic
├── static_analysis.py         # Ruff + Bandit result normalization
├── utils.py                   # ZIP safety, secret detection, source discovery
├── requirements.txt           # Python dependencies
├── .env.example               # Example environment configuration file
├── .env                       # Actual runtime environment variables (not committed)
├── README.md                  # Project documentation
├── test_project/
│   ├── app.py                 # Sample project file
│   └── login.py               # Intentionally vulnerable sample file
├── sample_test_project.zip    # ZIP archive used for testing the workflow
└── .gitignore                 # Excludes secrets and local environment files
```

---

## Output produced by the project

The app generates a dashboard with the following outputs:

- overall project score out of 100
- security score
- code quality score
- maintainability score
- reliability score
- counts of findings by severity: Critical, High, Medium, Low, Info
- summary text from Gemini review
- list of all issues found by static analysis and AI review
- grouped findings by file
- warnings when secrets were skipped or when Gemini could not complete the review

### Example result interpretation
- A score close to 100 means the project is clean and low-risk
- Lower scores indicate higher risk from vulnerability or maintainability problems
- The app shows both the issue count and the severity distribution so the reviewer can prioritize fixes quickly

---

## Rating parameters and review parameters

### Severity levels used
- CRITICAL
- HIGH
- MEDIUM
- LOW
- INFO

### Category labels used
- SECURITY
- BUG
- CODE_QUALITY
- PERFORMANCE
- MAINTAINABILITY
- RELIABILITY

### Scoring model
The project calculates score penalties based on severity and category. The exact scoring behavior is defined in scoring.py.

Example penalty logic used by the app:

- CRITICAL findings have the strongest penalty
- HIGH findings are heavily penalized
- MEDIUM, LOW, and INFO contribute progressively smaller penalties
- Security issues affect the security rating most strongly
- Maintainability and reliability categories also have dedicated penalty tables

### Overall rating formula
The app begins at 100 and subtracts penalty points for every finding. The final values are clamped to a range between 0 and 100.

### Review parameters used in analysis
These are the main guardrails and checks in the app:

- ZIP maximum size: 100 MB
- Maximum files per archive: 500
- Maximum file size inside ZIP: 2 MB
- Maximum source characters sent to Gemini: 60,000
- Supported source extensions: .py, .js, .ts, .tsx, .jsx
- Secret files skipped entirely
- Path traversal blocked
- Absolute ZIP paths rejected
- Project scan limited to safe and supported files

### Finding review rules
Gemini is only asked to review a cleaned and redacted code blob. The model is instructed to:

- review for bugs and security issues
- assess maintainability and reliability problems
- avoid inventing non-existent files or code
- give a realistic line number only when it can be justified
- return machine-readable structured JSON

## Review and rating parameters summary

| Parameter | Value / Rule |
|---|---|
| Max ZIP size | 100 MB |
| Max files per archive | 500 |
| Max file size | 2 MB |
| Supported source extensions | .py, .js, .ts, .tsx, .jsx |
| Max AI prompt size | 60,000 characters |
| Secret files blocked | .env, .pem, .key, credentials.json, private key types |
| Security checks | Ruff + Bandit |
| AI review model | Gemini with JSON schema |
| Severity labels | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| Rating output | 0-100 score across overall, security, quality, maintainability, reliability |

## Project goals and value

The project is designed to help users:

- review code quickly before deployment
- reduce the risk of insecure or unsafe code reaching production
- analyze unknown or third-party projects safely
- get a consistent and explainable risk score
- combine local static analysis with AI reasoning in a single workflow

---

## How to run the project

### 1. Install dependencies

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Add Gemini key
Create a .env file in the project root with:

```env
GEMINI_API_KEY=your_api_key_here
```

### 3. Launch the app

```powershell
streamlit run app.py
```

Then open the local URL shown in the terminal, usually http://localhost:8501

---

## What this project gives you

CodeSentinel AI gives a developer or reviewer a practical, fast, and explainable security review of an untrusted or unfamiliar project. It is especially useful for:

- checking for obvious vulnerabilities before deployment
- reviewing a new codebase quickly
- validating uploaded project submissions
- identifying issues that static analysis alone may miss
- generating a consistent risk score for prioritization

---

## Summary

CodeSentinel AI combines three important ideas:

- secure analysis of untrusted code
- local static checks for speed and consistency
- AI-assisted review for deeper insight

This makes it a useful project for learning how to build a secure, structured code review tool with automation, scoring, and safety controls built in.
