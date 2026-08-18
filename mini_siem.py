#!/usr/bin/env python3

"""
Log Analysis Mini SIEM

A beginner-friendly Python tool that reads sanitized sample logs,
applies simple blue-team detection rules, and prints terminal alerts.
"""

from __future__ import annotations

import argparse
import io
import re
from contextlib import redirect_stdout
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


FAILED_LOGIN_WARN_THRESHOLD = 5
FAILED_LOGIN_HIGH_THRESHOLD = 10
HTTP_404_WARN_THRESHOLD = 8

SUSPICIOUS_IPS = {
    "203.0.113.50",
    "198.51.100.23",
    "192.0.2.44",
}

SENSITIVE_PATHS = {
    "/admin": "WARN",
    "/.env": "HIGH",
    "/wp-login.php": "WARN",
    "/config": "HIGH",
    "/login": "WARN",
}

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:(?:invalid user )?)(?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

WEB_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) .* "(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[^"]+" (?P<status>\d{3})'
)


@dataclass
class Alert:
    severity: str
    title: str
    evidence: str
    recommendation: str


def read_log_lines(log_path: Path) -> list[str]:
    """Read a log file and return non-empty lines."""
    if not log_path.exists():
        print(f"[INFO] Log file not found: {log_path}")
        return []

    with log_path.open("r", encoding="utf-8") as log_file:
        return [line.strip() for line in log_file if line.strip()]


def parse_failed_logins(auth_lines: list[str]) -> list[dict[str, str]]:
    """Extract failed SSH login events from auth log lines."""
    failed_logins = []

    for line in auth_lines:
        match = FAILED_LOGIN_PATTERN.search(line)
        if match:
            failed_logins.append(
                {
                    "ip": match.group("ip"),
                    "username": match.group("username"),
                    "raw": line,
                }
            )

    return failed_logins


def parse_web_requests(web_lines: list[str]) -> list[dict[str, str]]:
    """Extract IP, method, path, and status code from web access logs."""
    web_requests = []

    for line in web_lines:
        match = WEB_LOG_PATTERN.search(line)
        if match:
            web_requests.append(
                {
                    "ip": match.group("ip"),
                    "method": match.group("method"),
                    "path": match.group("path"),
                    "status": match.group("status"),
                    "raw": line,
                }
            )

    return web_requests


def detect_repeated_failed_logins(failed_logins: list[dict[str, str]]) -> list[Alert]:
    """Alert when one IP has repeated failed login attempts."""
    alerts = []
    failed_login_counts = Counter(event["ip"] for event in failed_logins)

    for ip, count in failed_login_counts.items():
        if count >= FAILED_LOGIN_HIGH_THRESHOLD:
            severity = "HIGH"
            title = f"Possible brute-force activity from {ip}"
            recommendation = "Review authentication logs, block the IP if malicious, and consider disabling password-based SSH login."
        elif count >= FAILED_LOGIN_WARN_THRESHOLD:
            severity = "WARN"
            title = f"Repeated failed login attempts from {ip}"
            recommendation = "Review the source IP and confirm whether the activity is expected."
        else:
            continue

        alerts.append(
            Alert(
                severity=severity,
                title=title,
                evidence=f"{count} failed login attempt(s)",
                recommendation=recommendation,
            )
        )

    return alerts


def detect_suspicious_ips(
    failed_logins: list[dict[str, str]], web_requests: list[dict[str, str]]
) -> list[Alert]:
    """Alert when logs contain an IP from the local suspicious IP list."""
    alerts = []
    seen_ips = Counter()

    for event in failed_logins:
        seen_ips[event["ip"]] += 1

    for request in web_requests:
        seen_ips[request["ip"]] += 1

    for ip in sorted(SUSPICIOUS_IPS):
        if seen_ips[ip] > 0:
            alerts.append(
                Alert(
                    severity="WARN",
                    title=f"Suspicious IP observed: {ip}",
                    evidence=f"{seen_ips[ip]} matching log event(s)",
                    recommendation="Compare this IP against threat intelligence, firewall logs, and business context before taking action.",
                )
            )

    return alerts


def detect_repeated_404s(web_requests: list[dict[str, str]]) -> list[Alert]:
    """Alert when one IP generates many HTTP 404 responses."""
    alerts = []
    not_found_counts = Counter(
        request["ip"] for request in web_requests if request["status"] == "404"
    )

    for ip, count in not_found_counts.items():
        if count >= HTTP_404_WARN_THRESHOLD:
            alerts.append(
                Alert(
                    severity="WARN",
                    title=f"Repeated 404 errors from {ip}",
                    evidence=f"{count} HTTP 404 response(s)",
                    recommendation="Review requested paths for scanning, directory brute forcing, or vulnerability probing.",
                )
            )

    return alerts


def detect_sensitive_paths(web_requests: list[dict[str, str]]) -> list[Alert]:
    """Alert when requests target sensitive or commonly attacked paths."""
    alerts = []

    for request in web_requests:
        path = request["path"]
        if path in SENSITIVE_PATHS:
            severity = SENSITIVE_PATHS[path]
            alerts.append(
                Alert(
                    severity=severity,
                    title=f"Sensitive path requested: {path}",
                    evidence=f'{request["ip"]} used {request["method"]} and received HTTP {request["status"]}',
                    recommendation="Confirm whether this endpoint should be public. Restrict, monitor, or remove exposed sensitive paths.",
                )
            )

    return alerts


def print_banner() -> None:
    print("=" * 64)
    print(" Log Analysis Mini SIEM")
    print(" Beginner Python Detection Report")
    print("=" * 64)


def print_alert(alert: Alert) -> None:
    print(f"[{alert.severity}] {alert.title}")
    print(f"       Evidence: {alert.evidence}")
    print(f"       Recommendation: {alert.recommendation}")
    print()


def print_summary(total_lines: int, alerts: list[Alert]) -> None:
    severity_counts = Counter(alert.severity for alert in alerts)

    print("== Summary ==")
    print(f"Log lines analyzed: {total_lines}")
    print(f"Alerts generated:   {len(alerts)}")
    print(f"INFO alerts:        {severity_counts['INFO']}")
    print(f"WARN alerts:        {severity_counts['WARN']}")
    print(f"HIGH alerts:        {severity_counts['HIGH']}")


def run_analysis(auth_log: Path, web_log: Path) -> None:
    auth_lines = read_log_lines(auth_log)
    web_lines = read_log_lines(web_log)

    failed_logins = parse_failed_logins(auth_lines)
    web_requests = parse_web_requests(web_lines)

    alerts: list[Alert] = []
    alerts.extend(detect_repeated_failed_logins(failed_logins))
    alerts.extend(detect_suspicious_ips(failed_logins, web_requests))
    alerts.extend(detect_repeated_404s(web_requests))
    alerts.extend(detect_sensitive_paths(web_requests))

    severity_order = {"HIGH": 0, "WARN": 1, "INFO": 2}
    alerts.sort(key=lambda alert: severity_order.get(alert.severity, 99))

    print_banner()
    print(f"Auth log: {auth_log}")
    print(f"Web log:  {web_log}")
    print()

    print("== Alerts ==")
    if alerts:
        for alert in alerts:
            print_alert(alert)
    else:
        print("[INFO] No alerts generated from the provided sample logs.")
        print()

    print_summary(len(auth_lines) + len(web_lines), alerts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze sample auth and web logs for beginner blue-team detections."
    )
    parser.add_argument(
        "--auth-log",
        default="sample_logs/auth.log",
        type=Path,
        help="Path to the sample authentication log file.",
    )
    parser.add_argument(
        "--web-log",
        default="sample_logs/web_access.log",
        type=Path,
        help="Path to the sample web access log file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to save a copy of the alert report.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.output:
        report_buffer = io.StringIO()
        with redirect_stdout(report_buffer):
            run_analysis(args.auth_log, args.web_log)

        report_text = report_buffer.getvalue()
        print(report_text, end="")

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report_text, encoding="utf-8")
        print(f"\n[INFO] Report saved to: {args.output}")
    else:
        run_analysis(args.auth_log, args.web_log)


if __name__ == "__main__":
    main()
