# Website Security Auditor
**Abstract:** A Flask tool that performs non-invasive HTTP/HTTPS configuration checks on authorized websites and produces an educational security-configuration score with evidence and remediation.
**Problem:** Many sites ship without basic security headers, safe cookies or proper HTTPS redirects, and manual checking is slow.
**Objectives:** automate configuration checks; block SSRF; score transparently; keep history; export reports.

## Architecture
Browser -> Flask (`app.py`) -> `url_validator` (DNS/IP checks) -> `security_auditor` (pinned-IP requests, redirect validation, findings) -> `scoring` -> `database` (SQLite) -> `report_generator` (JSON/CSV/HTML/PDF).
**Stack:** Python 3.11+, Flask, requests/ssl/socket, SQLite, Bootstrap 5, Chart.js, ReportLab, pytest.

## Modules
`url_validator.py` safe targets | `security_auditor.py` checks and findings | `scoring.py` score | `database.py` history | `report_generator.py` exports | `app.py` routes | `tests/` pytest suite.

## Scoring
Start 100; High -20, Medium -10, Low -3, Informational 0; each finding ID counts once. 85+ low risk, 60-84 moderate, below 60 high. Not-assessed audits show N/A. This is an educational score, not an industry rating.

## Database
Table `audits(id, url, hostname, started, completed, status, score, report JSON)` with an index on hostname. All queries are parameterized. Cookie values are never stored.

## Install and run (cmd)
```
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python app.py
python -m pytest
```
Open http://127.0.0.1:5000. Port conflict: change the port at the bottom of `app.py`.

## Cybersecurity concepts covered
Network security (SSRF defence), HTTPS and TLS/PKI (certificate chain, hostname match), security protocols (HSTS), vulnerability assessment, risk management (severity and scoring), security controls (headers, cookie flags).

## Limitations
Single GET request per audit; no code, injection or authentication testing; CDN/WAF behaviour can cause false positives; the TLS check covers certificate verification and expiry text only (no cipher or protocol audit); history comparison is by finding ID.

## Future enhancements
TLS protocol/cipher audit, multi-page crawl, scheduled audits, user accounts, dark/light themes.
See `DOCS.md` for the report outline, slides, demo script and viva questions.
