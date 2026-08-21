import unittest

from mini_siem import (
    detect_repeated_404s,
    detect_repeated_failed_logins,
    detect_sensitive_paths,
    parse_failed_logins,
    parse_web_requests,
)


class MiniSiemTests(unittest.TestCase):
    def test_parse_failed_login_line(self):
        auth_lines = [
            "Aug 18 09:01:14 ubuntu-lab sshd[1207]: Failed password for invalid user admin from 203.0.113.50 port 41001 ssh2"
        ]

        failed_logins = parse_failed_logins(auth_lines)

        self.assertEqual(len(failed_logins), 1)
        self.assertEqual(failed_logins[0]["ip"], "203.0.113.50")
        self.assertEqual(failed_logins[0]["username"], "admin")

    def test_parse_web_request_line(self):
        web_lines = [
            '198.51.100.23 - - [18/Aug/2026:09:02:01 -0400] "GET /wp-login.php HTTP/1.1" 404 128'
        ]

        web_requests = parse_web_requests(web_lines)

        self.assertEqual(len(web_requests), 1)
        self.assertEqual(web_requests[0]["ip"], "198.51.100.23")
        self.assertEqual(web_requests[0]["method"], "GET")
        self.assertEqual(web_requests[0]["path"], "/wp-login.php")
        self.assertEqual(web_requests[0]["status"], "404")

    def test_detect_possible_brute_force(self):
        failed_logins = [{"ip": "203.0.113.50", "username": "admin", "raw": ""}] * 10

        alerts = detect_repeated_failed_logins(failed_logins)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertIn("brute-force", alerts[0].title)

    def test_detect_repeated_404s(self):
        web_requests = [
            {"ip": "198.51.100.23", "method": "GET", "path": f"/missing-{number}", "status": "404", "raw": ""}
            for number in range(8)
        ]

        alerts = detect_repeated_404s(web_requests)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "WARN")

    def test_repeated_404s_stays_quiet_below_threshold(self):
        web_requests = [
            {"ip": "198.51.100.23", "method": "GET", "path": f"/missing-{number}", "status": "404", "raw": ""}
            for number in range(7)
        ]

        alerts = detect_repeated_404s(web_requests)

        self.assertEqual(alerts, [])

    def test_detect_sensitive_high_path(self):
        web_requests = [
            {"ip": "203.0.113.50", "method": "GET", "path": "/.env", "status": "404", "raw": ""}
        ]

        alerts = detect_sensitive_paths(web_requests)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
