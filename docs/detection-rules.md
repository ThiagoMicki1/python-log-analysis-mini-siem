# Detection Rules

This document explains the beginner detection rules used by Log Analysis Mini SIEM.

## Rule 1: Repeated Failed Login Attempts

Detection logic:

```text
If one IP has 5 or more failed SSH login attempts, generate a WARN alert.
```

Security meaning:

Repeated failed logins may indicate password guessing, credential stuffing, or a user repeatedly entering the wrong password.

Example alert:

```text
[WARN] Repeated failed login attempts from 203.0.113.50
```

Recommendation:

Review the source IP, targeted usernames, and login pattern. If the activity is unauthorized, consider blocking the IP or strengthening authentication controls.

## Rule 2: Possible Brute Force

Detection logic:

```text
If one IP has 10 or more failed SSH login attempts, generate a HIGH alert.
```

Security meaning:

A high number of failed logins from one IP can indicate automated brute-force activity.

Example alert:

```text
[HIGH] Possible brute-force activity from 203.0.113.50
```

Recommendation:

Review authentication logs, block malicious sources, disable password-based SSH login when possible, and use key-based authentication or multi-factor authentication.

## Rule 3: Suspicious IP Address

Detection logic:

```text
If a log event contains an IP from the suspicious IP list, generate a WARN alert.
```

Security meaning:

Security teams often compare logs against known-bad IPs, threat intelligence feeds, or internal blocklists. This project uses a small local list for beginner practice.

Example suspicious IPs:

```text
203.0.113.50
198.51.100.23
192.0.2.44
```

Recommendation:

Do not block an IP based only on one simple match. Compare it with business context, other logs, and trusted threat intelligence.

## Rule 4: Repeated 404 Errors

Detection logic:

```text
If one IP generates 8 or more HTTP 404 responses, generate a WARN alert.
```

Security meaning:

Many 404 responses from one IP can indicate directory brute forcing, vulnerability scanning, or discovery attempts.

Example alert:

```text
[WARN] Repeated 404 errors from 198.51.100.23
```

Recommendation:

Review the requested paths. Look for patterns such as old admin pages, backup files, debug paths, or application-specific probes.

## Rule 5: Sensitive Path Access

Detection logic:

```text
If a request targets a sensitive path, generate a WARN or HIGH alert.
```

Sensitive paths:

| Path | Severity | Why It Matters |
| --- | --- | --- |
| `/admin` | `WARN` | Common admin panel target |
| `/.env` | `HIGH` | Environment files may expose secrets |
| `/wp-login.php` | `WARN` | Common WordPress login target |
| `/config` | `HIGH` | Config paths may expose sensitive settings |
| `/login` | `WARN` | Login endpoints are common attack targets |

Recommendation:

Confirm whether the endpoint should be public. Restrict access, monitor attempts, and remove exposed sensitive files or routes.

## Rule Tuning Notes

The thresholds in this project are intentionally simple:

```text
FAILED_LOGIN_WARN_THRESHOLD = 5
FAILED_LOGIN_HIGH_THRESHOLD = 10
HTTP_404_WARN_THRESHOLD = 8
```

In a real environment, detection thresholds should be tuned based on normal traffic, user behavior, system purpose, and risk tolerance.
