# Log Analysis Mini SIEM

A beginner-friendly Python project that analyzes sanitized sample logs and generates terminal alerts for suspicious activity.

This project was built to practice blue-team detection, Python scripting, log analysis, and security reporting for entry-level Security Engineer, DevSecOps, Cloud Security, and SOC roles.

## Overview

Log Analysis Mini SIEM reads sample authentication and web access logs, parses important fields, applies simple detection rules, and prints clean alerts with severity levels.

The workflow is similar to a small SIEM pipeline:

```text
Sample logs -> Parse events -> Apply detection rules -> Generate alerts -> Summarize findings
```

This project uses sample logs only. It does not collect, transmit, or analyze private real-world logs.

## Features

- Python-based command-line tool
- Uses only the Python standard library
- Parses sample SSH authentication logs
- Parses sample web access logs
- Supports optional report export with `--output`
- Detects repeated failed login attempts
- Detects possible brute-force behavior
- Detects suspicious IP addresses from a local watchlist
- Detects repeated HTTP 404 errors
- Detects requests to sensitive paths:
  - `/admin`
  - `/.env`
  - `/wp-login.php`
  - `/config`
  - `/login`
- Generates clean terminal alerts with `INFO`, `WARN`, and `HIGH` severity levels
- Prints evidence and recommendations for each alert
- Includes sanitized sample logs and sample output

## Folder Structure

```text
python-log-analysis-mini-siem/
├── README.md
├── LICENSE
├── .gitattributes
├── .gitignore
├── requirements.txt
├── mini_siem.py
├── sample_logs/
│   ├── auth.log
│   └── web_access.log
├── reports/
│   ├── .gitkeep
│   └── sample-alert-output.txt
├── tests/
│   └── test_mini_siem.py
└── docs/
    └── detection-rules.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/ThiagoMicki1/python-log-analysis-mini-siem.git
cd python-log-analysis-mini-siem
```

Check your Python version:

```bash
python --version
```

Python 3.10 or newer is recommended.

This project does not require external packages. The `requirements.txt` file is included for standard project structure.

## Usage

Run the tool with the included sample logs:

```bash
python mini_siem.py
```

On some systems, use:

```bash
python3 mini_siem.py
```

Run the tool with custom sample log paths:

```bash
python mini_siem.py --auth-log sample_logs/auth.log --web-log sample_logs/web_access.log
```

Save a copy of the terminal report:

```bash
python mini_siem.py --output reports/local-alert-report.txt
```

View command-line help:

```bash
python mini_siem.py --help
```

Run the tests:

```bash
python -m unittest discover -s tests
```

## Sample Output

See the full sanitized sample output in [`reports/sample-alert-output.txt`](reports/sample-alert-output.txt).

Example:

```text
================================================================
 Log Analysis Mini SIEM
 Beginner Python Detection Report
================================================================
Auth log: sample_logs/auth.log
Web log:  sample_logs/web_access.log

== Alerts ==
[HIGH] Possible brute-force activity from 203.0.113.50
       Evidence: 10 failed login attempt(s)
       Recommendation: Review authentication logs, block the IP if malicious, and consider disabling password-based SSH login.

[HIGH] Sensitive path requested: /.env
       Evidence: 203.0.113.50 used GET and received HTTP 404
       Recommendation: Confirm whether this endpoint should be public. Restrict, monitor, or remove exposed sensitive paths.

[WARN] Repeated 404 errors from 198.51.100.23
       Evidence: 10 HTTP 404 response(s)
       Recommendation: Review requested paths for scanning, directory brute forcing, or vulnerability probing.

== Summary ==
Log lines analyzed: 35
Alerts generated:   12
INFO alerts:        0
WARN alerts:        9
HIGH alerts:        3
```

## Detection Rules

Detailed rule explanations are available in [`docs/detection-rules.md`](docs/detection-rules.md).

Summary:

| Rule | Severity | Purpose |
| --- | --- | --- |
| Repeated failed logins | `WARN` | Detects multiple failed SSH login attempts from one IP |
| Possible brute force | `HIGH` | Detects many failed SSH login attempts from one IP |
| Suspicious IP observed | `WARN` | Flags IPs from a local suspicious IP watchlist |
| Repeated 404 errors | `WARN` | Detects possible directory brute forcing or scanning |
| Sensitive path access | `WARN` or `HIGH` | Detects requests to commonly targeted paths |

## Security Concepts Learned

### Log Parsing

The project extracts useful fields from raw log lines, including IP addresses, usernames, HTTP methods, requested paths, and status codes.

Why it matters: security teams need to transform raw logs into structured events before they can detect suspicious behavior.

### Brute-Force Detection

The project counts failed login attempts by source IP.

Why it matters: repeated failed logins may indicate password guessing, credential stuffing, or automated brute-force attacks.

### Web Reconnaissance Detection

The project detects repeated `404` responses and requests to sensitive paths.

Why it matters: attackers often search for hidden files, admin panels, login pages, old applications, and exposed configuration files.

### Threat Intelligence Basics

The project compares log IPs against a small local suspicious IP list.

Why it matters: real security teams often enrich logs with known-bad indicators from threat intelligence feeds or internal blocklists.

### Alert Severity

The project uses `INFO`, `WARN`, and `HIGH` labels.

Why it matters: severity helps analysts prioritize what to review first.

### Security Reporting

Each alert includes a title, evidence, and recommendation.

Why it matters: security findings are more useful when they explain what happened, why it matters, and what to do next.

## Project Scope

This is an educational portfolio project, not a production SIEM.

It is intended for:

- Python practice
- Blue-team detection practice
- Safe sample log analysis
- Beginner cybersecurity portfolios
- SOC and Security Engineer interview discussion

It is not intended for:

- Real-time monitoring
- Production incident response
- Processing private logs
- Malware detection
- Full SIEM replacement

## Future Improvements

- Add JSON alert output
- Add CSV report export
- Add timestamp parsing and time-window based detections
- Add command-line threshold options
- Add more unit tests and edge-case log samples
- Add support for cloud logs such as AWS CloudTrail samples
- Add basic MITRE ATT&CK mapping
- Add allowlist support for trusted IP addresses
- Add severity scoring
- Add a simple HTML report

## Disclaimer

This project uses sanitized sample logs for educational purposes. Always get permission before analyzing logs from systems you do not own or administer.
