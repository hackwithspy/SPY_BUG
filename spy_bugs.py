#!/usr/bin/env python3
"""
                         SPY BUG
              Authorized Web Security Scanner
                         Version 1.0

Single-file Kali Linux security assessment tool.

Capabilities:
- DNS reconnaissance and same-host crawling
- Security headers and cookie configuration checks
- Common-path discovery
- Reflected-input analysis and optional harmless browser XSS proof
- Passive SQL error detection and optional read-only boolean differential checks
- Two-account IDOR access comparisons
- Business-logic review of discovered forms
- Authenticated GET checks
- TLS inspection
- HTML and JSON reports

Use only on systems you own or are explicitly authorized to test.
Active confirmation is opt-in. No data extraction, destructive writes,
authentication bypass, or transaction manipulation is performed.
"""

import argparse
import difflib
import hashlib
import html
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
from bs4 import BeautifulSoup


BANNER = r"""
   ____  ____  __   __   ____  _   _  ____
 / ___||  _ \ \ \ / /  | __ )| | | |/ ___|
 \___ \| |_) | \ V /   |  _ \| | | | |  _
  ___) |  __/  | |     | |_) | |_| | |_| |
 |____/|_|     |_|     |____/ \___/ \____|


                         SPY BUG
"""

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SQL_SIGNATURES = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite_error",
    "sqlstate[",
    "postgresql query failed",
    "ora-00933",
    "mysql_fetch",
    "odbc sql",
]

COMMON_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "admin/",
    "api/",
    "swagger/",
    "openapi.json",
    "server-status",
    ".env",
    ".git/config",
]

SENSITIVE_FIELDS = {
    "price", "amount", "total", "discount", "role", "admin",
    "user_id", "userid", "account_id", "quantity", "is_admin",
    "balance", "payment", "status",
}

REFLECTION_MARKER = "SPYBUG_REFLECTION_"
XSS_PROOF_MARKER = "SPY_BUG_XSS_PROOF"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(text):
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("Invalid target URL")
    return url.rstrip("/")


def load_cookie_header(filename):
    if not filename:
        return None
    path = Path(filename)
    if not path.is_file():
        raise ValueError(f"Cookie file not found: {filename}")
    value = path.read_text(encoding="utf-8").strip()
    if "\n" in value or "\r" in value:
        raise ValueError("Cookie file must contain one raw Cookie header line")
    return value or None


class SpyBugs:
    def __init__(
        self,
        target,
        delay=1.0,
        max_pages=40,
        timeout=10,
        cookie_a=None,
        cookie_b=None,
        active_confirm=False,
        browser_confirm=False,
    ):
        self.target = normalize_url(target)
        self.host = urlparse(self.target).hostname
        self.delay = max(0.5, delay)
        self.max_pages = max_pages
        self.timeout = timeout
        self.active_confirm = active_confirm
        self.browser_confirm = browser_confirm

        self.visited = set()
        self.urls = set()
        self.forms = []
        self.findings = []
        self.errors = []
        self.started = utc_now()
        self._last_request = 0.0

        self.cookie_a = load_cookie_header(cookie_a)
        self.cookie_b = load_cookie_header(cookie_b)

        self.session = self.make_session(self.cookie_a)
        self.account_a = self.make_session(self.cookie_a)
        self.account_b = self.make_session(self.cookie_b)

    @staticmethod
    def make_session(cookie=None):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "SPY-BUG/3.0 Authorized-Security-Assessment"
        })
        if cookie:
            session.headers["Cookie"] = cookie
        return session

    def in_scope(self, url):
        parsed = urlparse(url)
        return (
            parsed.scheme in ("http", "https")
            and parsed.hostname == self.host
            and parsed.port in (None, 80, 443)
        )

    def request(self, url, session=None, params=None):
        if not self.in_scope(url):
            self.errors.append({
                "url": url,
                "error": "Out-of-scope URL blocked",
            })
            return None

        wait = self.delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)

        try:
            response = (session or self.session).get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
            self._last_request = time.monotonic()

            # Redirects to another host are not followed for further analysis.
            if not self.in_scope(response.url):
                self.errors.append({
                    "url": url,
                    "error": "Redirect left authorized host; response ignored",
                })
                return None
            return response
        except requests.RequestException as exc:
            self._last_request = time.monotonic()
            self.errors.append({"url": url, "error": str(exc)})
            return None

    def add_finding(
        self, category, severity, status, url, detail, evidence=""
    ):
        item = {
            "category": category,
            "severity": severity,
            "status": status,
            "url": url,
            "detail": detail,
            "evidence": str(evidence)[:500],
            "time": utc_now(),
        }
        key = (
            item["category"], item["status"], item["url"],
            item["detail"], item["evidence"],
        )
        if not any(
            (x["category"], x["status"], x["url"], x["detail"], x["evidence"]) == key
            for x in self.findings
        ):
            self.findings.append(item)
            print(f"[{severity}] [{status}] {category}: {url}")

    # 1. Reconnaissance
    def reconnaissance(self):
        print("\n[1] RECONNAISSANCE")
        try:
            addresses = sorted({
                result[4][0]
                for result in socket.getaddrinfo(
                    self.host, None, type=socket.SOCK_STREAM
                )
            })
            print("[+] DNS addresses:", ", ".join(addresses))
        except socket.gaierror as exc:
            addresses = []
            self.errors.append({"url": self.target, "error": f"DNS: {exc}"})
            print("[!] DNS lookup failed:", exc)
        return addresses

    # 2. Same-host crawler and form inventory
    def crawl(self):
        print("\n[2] WEB CRAWLING")
        queue = deque([self.target])

        while queue and len(self.visited) < self.max_pages:
            url = queue.popleft()
            if url in self.visited or not self.in_scope(url):
                continue

            self.visited.add(url)
            self.urls.add(url)
            print("[CRAWL]", url)

            response = self.request(url)
            if response is None:
                continue
            if "text/html" not in response.headers.get("Content-Type", "").lower():
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                new_url = urljoin(url, tag["href"])
                parsed = urlparse(new_url)
                clean_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    "", parsed.query, ""
                ))
                if self.in_scope(clean_url):
                    self.urls.add(clean_url)
                    if clean_url not in self.visited:
                        queue.append(clean_url)

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                if not self.in_scope(action):
                    continue
                fields = []
                for field in form.find_all(["input", "select", "textarea", "button"]):
                    name = field.get("name", "")
                    if name:
                        fields.append({
                            "name": name,
                            "type": field.get("type", "text"),
                        })
                self.forms.append({
                    "page": url,
                    "action": action,
                    "method": form.get("method", "get").upper(),
                    "fields": fields,
                })

    # 3. Headers and cookie flags
    def security_headers(self):
        print("\n[3] SECURITY HEADERS AND COOKIES")
        response = self.request(self.target)
        if response is None:
            return

        for header in SECURITY_HEADERS:
            if header not in response.headers:
                self.add_finding(
                    "Missing Security Header", "LOW", "POTENTIAL",
                    self.target, f"Response does not include {header}.",
                )

        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            lower_cookie = set_cookie.lower()
            if "secure" not in lower_cookie and urlparse(self.target).scheme == "https":
                self.add_finding(
                    "Cookie Configuration", "LOW", "POTENTIAL",
                    self.target, "A Set-Cookie response may lack Secure.",
                )
            if "httponly" not in lower_cookie:
                self.add_finding(
                    "Cookie Configuration", "LOW", "POTENTIAL",
                    self.target, "A Set-Cookie response may lack HttpOnly.",
                )
            if "samesite" not in lower_cookie:
                self.add_finding(
                    "Cookie Configuration", "INFO", "POTENTIAL",
                    self.target, "A Set-Cookie response may lack SameSite.",
                )

    # 4. Directory/path discovery: status only; never print file contents
    def directory_scan(self):
        print("\n[4] COMMON PATH DISCOVERY")
        for path in COMMON_PATHS:
            url = urljoin(self.target + "/", path)
            response = self.request(url)
            if response is None:
                continue
            if response.status_code == 200:
                self.add_finding(
                    "Public Path Discovery", "INFO", "REVIEW_REQUIRED",
                    url, "Path returned HTTP 200. Review access policy and content safely.",
                )
            elif response.status_code in (401, 403):
                print(f"[INFO] Restricted path: {path} ({response.status_code})")

    # 5. Reflected input analysis
    def xss_analysis(self):
        print("\n[5] REFLECTED INPUT / XSS ANALYSIS")
        for original_url in list(self.visited):
            parsed = urlparse(original_url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            base = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, "", "", ""
            ))
            for parameter in params:
                marker = REFLECTION_MARKER + parameter + "_END"
                test_params = {
                    key: (values[0] if values else "")
                    for key, values in params.items()
                }
                test_params[parameter] = marker
                response = self.request(base, params=test_params)
                if response is None or marker not in response.text:
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                context = "Unclassified response context"
                for node in soup.find_all(string=lambda value: value and marker in value):
                    if node.parent:
                        context = f"HTML text node inside <{node.parent.name}>"
                        break

                self.add_finding(
                    "Reflected Input", "INFO", "REFLECTION_CONFIRMED",
                    original_url,
                    f"Marker reflected for parameter '{parameter}'. "
                    f"{context}. Reflection alone is not proof of XSS.",
                    marker,
                )

                if self.browser_confirm:
                    self.confirm_xss_in_browser(base, test_params, original_url)

    def confirm_xss_in_browser(self, base_url, params, original_url):
        """Optional benign proof: set document.title only; no data access."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.add_finding(
                "XSS Browser Confirmation", "INFO", "NOT_RUN",
                original_url,
                "Install Playwright and Chromium to enable browser confirmation.",
            )
            return

        proof_payload = (
            f"<script>document.title='{XSS_PROOF_MARKER}'</script>"
        )
        candidate_params = dict(params)
        first_key = next(iter(candidate_params))
        candidate_params[first_key] = proof_payload
        test_url = base_url + "?" + urlencode(candidate_params, doseq=True)

        if len(test_url) > 6000:
            return

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
                title = page.title()
                browser.close()

            if title == XSS_PROOF_MARKER:
                self.add_finding(
                    "Cross-Site Scripting", "HIGH", "CONFIRMED",
                    original_url,
                    "A harmless proof script executed and changed the document title.",
                    "document.title proof marker observed; no data was accessed.",
                )
        except Exception as exc:
            self.errors.append({
                "url": original_url,
                "error": f"Browser XSS confirmation: {exc}",
            })

    # 6. Passive SQL error signatures
    def sqli_passive(self):
        print("\n[6] PASSIVE SQL ERROR ANALYSIS")
        for url in list(self.visited):
            response = self.request(url)
            if response is None:
                continue
            body = response.text.lower()
            for signature in SQL_SIGNATURES:
                if signature in body:
                    self.add_finding(
                        "Database Error Disclosure", "MEDIUM", "INDICATOR",
                        url, "A known database error signature appeared in the response.",
                        signature,
                    )
                    break

    # 7. Optional read-only boolean differential confirmation
    @staticmethod
    def similarity(a, b):
        return difflib.SequenceMatcher(
            None, a[:50000], b[:50000]
        ).ratio()

    def sqli_active_confirmation(self):
        if not self.active_confirm:
            print("\n[7] SQLi ACTIVE CONFIRMATION: disabled (use --active-confirm)")
            return

        print("\n[7] SQLi READ-ONLY BOOLEAN DIFFERENTIAL CHECK")
        print("[!] This sends limited GET requests with boolean conditions.")
        for original_url in list(self.visited):
            parsed = urlparse(original_url)
            original_params = parse_qs(parsed.query)
            if not original_params:
                continue

            base = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, "", "", ""
            ))
            baseline_params = {
                key: (values[0] if values else "")
                for key, values in original_params.items()
            }
            baseline = self.request(base, params=baseline_params)
            if baseline is None:
                continue

            for parameter, values in original_params.items():
                original_value = values[0] if values else ""
                # Two low-impact boolean probes; no UNION, time delay,
                # stacked query, file access, or data extraction.
                if re.fullmatch(r"-?\d+", original_value):
                    true_suffix, false_suffix = " AND 1=1", " AND 1=2"
                else:
                    true_suffix, false_suffix = "' AND '1'='1", "' AND '1'='2"

                true_params = dict(baseline_params)
                false_params = dict(baseline_params)
                true_params[parameter] = original_value + true_suffix
                false_params[parameter] = original_value + false_suffix

                true_response = self.request(base, params=true_params)
                false_response = self.request(base, params=false_params)
                if not true_response or not false_response:
                    continue

                true_sim = self.similarity(baseline.text, true_response.text)
                false_sim = self.similarity(baseline.text, false_response.text)
                true_error = any(s in true_response.text.lower() for s in SQL_SIGNATURES)
                false_error = any(s in false_response.text.lower() for s in SQL_SIGNATURES)

                # Conservative classification: differential evidence is
                # still an indicator, not universal proof of SQL injection.
                if (
                    true_response.status_code == baseline.status_code
                    and false_response.status_code == baseline.status_code
                    and true_sim > 0.95
                    and false_sim < 0.80
                    and not true_error
                    and not false_error
                ):
                    self.add_finding(
                        "Possible Boolean-Based SQL Injection", "HIGH",
                        "STRONG_DIFFERENTIAL_EVIDENCE", original_url,
                        f"Parameter '{parameter}' produced a repeatable-looking "
                        "true/false response difference. Confirm manually in an "
                        "authorized test environment; dynamic pages can cause false positives.",
                        f"true_similarity={true_sim:.3f}; false_similarity={false_sim:.3f}",
                    )

    # 8. Two-account IDOR comparison (metadata only)
    def idor_analysis(self, pairs):
        print("\n[8] TWO-ACCOUNT IDOR COMPARISON")
        if not pairs:
            print("[INFO] Supply --idor-pair for authorized account comparisons.")
            return
        if not self.cookie_a or not self.cookie_b:
            print("[!] IDOR comparison requires both --cookie-a and --cookie-b.")
            return

        for pair in pairs:
            if "|" not in pair:
                print("[!] Invalid IDOR pair; expected URL_A|URL_B")
                continue
            url_a, url_b = pair.split("|", 1)
            if not self.in_scope(url_a) or not self.in_scope(url_b):
                print("[!] Out-of-scope IDOR URL blocked.")
                continue

            # Each account requests both objects. Bodies are fingerprinted
            # locally and are never copied into the report.
            a_own = self.request(url_a, self.account_a)
            a_other = self.request(url_b, self.account_a)
            b_own = self.request(url_b, self.account_b)
            b_other = self.request(url_a, self.account_b)
            if not all((a_own, a_other, b_own, b_other)):
                continue

            cross_account_success = (
                200 <= a_other.status_code < 300
                or 200 <= b_other.status_code < 300
            )
            if cross_account_success:
                self.add_finding(
                    "Possible IDOR", "HIGH", "AUTHORIZATION_REVIEW_REQUIRED",
                    url_a,
                    "At least one cross-account GET returned a successful status. "
                    "A successful response alone does not prove unauthorized object "
                    "access; verify ownership using non-sensitive test records.",
                    (
                        f"A->A:{a_own.status_code}; A->B:{a_other.status_code}; "
                        f"B->B:{b_own.status_code}; B->A:{b_other.status_code}; "
                        f"body_fingerprints={digest(a_other.text)[:12]},"
                        f"{digest(b_other.text)[:12]}"
                    ),
                )
            else:
                print("[INFO] No successful cross-account response in supplied pair.")

    # 9. Business logic: inventory and review signals, no writes
    def business_logic_analysis(self):
        print("\n[9] BUSINESS LOGIC REVIEW")
        for form in self.forms:
            names = {
                field["name"].lower()
                for field in form["fields"]
                if field["name"]
            }
            sensitive = sorted(names.intersection(SENSITIVE_FIELDS))
            if sensitive:
                self.add_finding(
                    "Business Logic Review", "INFO", "REVIEW_REQUIRED",
                    form["action"],
                    "Form includes sensitive workflow fields: "
                    + ", ".join(sensitive)
                    + ". Verify server-side authorization, pricing, quantity, "
                    "role, and state-transition rules.",
                )
            if form["method"] == "GET" and sensitive:
                self.add_finding(
                    "Potential State-Changing GET", "LOW", "REVIEW_REQUIRED",
                    form["action"],
                    "GET form includes sensitive-looking fields. Verify that "
                    "GET does not perform state-changing operations.",
                )
        print(f"[+] Forms reviewed: {len(self.forms)}")

    # 10. Authenticated GET checks
    def authenticated_scan(self):
        print("\n[10] AUTHENTICATED GET CHECKS")
        if not self.cookie_a:
            print("[INFO] No --cookie-a supplied; authenticated checks skipped.")
            return
        for url in sorted(self.visited):
            response = self.request(url, session=self.session)
            if response is None:
                continue
            if response.status_code in (401, 403):
                self.add_finding(
                    "Authenticated Access Review", "INFO", "ACCESS_DENIED",
                    url, f"Account A received HTTP {response.status_code}.",
                )

    # 11. TLS
    def tls_analysis(self):
        print("\n[11] TLS INSPECTION")
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            self.add_finding(
                "Transport Security", "MEDIUM", "POTENTIAL",
                self.target, "Target URL uses HTTP rather than HTTPS.",
            )
            return
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as tls:
                    print("[+] Negotiated TLS:", tls.version())
        except (OSError, ssl.SSLError) as exc:
            self.add_finding(
                "TLS Inspection", "INFO", "REVIEW_REQUIRED",
                self.target, str(exc),
            )

    # 12. Reports
    def report_data(self):
        return {
            "tool": "SPY BUG",
            "version": "3.0",
            "target": self.target,
            "started": self.started,
            "finished": utc_now(),
            "statistics": {
                "pages_crawled": len(self.visited),
                "urls_discovered": len(self.urls),
                "forms_discovered": len(self.forms),
                "findings": len(self.findings),
                "errors": len(self.errors),
            },
            "findings": self.findings,
            "errors": self.errors,
            "limitations": [
                "Automated results require human review.",
                "Business-logic validation depends on application-specific expected behavior.",
                "IDOR results require test accounts and object ownership verification.",
                "SQL differential evidence can be affected by dynamic responses.",
            ],
        }

    def json_report(self):
        Path("spy_bugs_report.json").write_text(
            json.dumps(self.report_data(), indent=2),
            encoding="utf-8",
        )
        print("[+] JSON report saved: spy_bugs_report.json")

    def html_report(self):
        rows = []
        for item in self.findings:
            rows.append(
                "<tr>"
                f"<td>{html.escape(item['severity'])}</td>"
                f"<td>{html.escape(item['status'])}</td>"
                f"<td>{html.escape(item['category'])}</td>"
                f"<td>{html.escape(item['url'])}</td>"
                f"<td>{html.escape(item['detail'])}</td>"
                f"<td>{html.escape(item['evidence'])}</td>"
                "</tr>"
            )

        report = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SPY BUG Security Report</title>
<style>
body{{background:#101820;color:#f4f4f4;font-family:Arial,sans-serif;padding:24px}}
h1{{color:#00e5a8}} .meta{{background:#1c2935;padding:14px;border-radius:8px}}
table{{border-collapse:collapse;width:100%;background:#1c2935;margin-top:18px}}
th,td{{border:1px solid #405060;padding:9px;text-align:left;overflow-wrap:anywhere}}
th{{background:#263746}} .note{{color:#c8d3dc}}
</style>
</head>
<body>
<h1>SPY BUG</h1>
<h2>Web Security Assessment Report</h2>
<div class="meta">
<p><b>Target:</b> {html.escape(self.target)}</p>
<p><b>Started:</b> {html.escape(self.started)}</p>
<p><b>Pages:</b> {len(self.visited)} |
<b>URLs:</b> {len(self.urls)} |
<b>Forms:</b> {len(self.forms)} |
<b>Findings:</b> {len(self.findings)}</p>
</div>
<table>
<thead><tr><th>Severity</th><th>Status</th><th>Category</th>
<th>URL</th><th>Details</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<p class="note">Automated findings are evidence-based indicators, not a guarantee.
Review and reproduce findings manually within the authorized scope.</p>
</body></html>"""

        Path("spy_bugs_report.html").write_text(
            report, encoding="utf-8"
        )
        print("[+] HTML report saved: spy_bugs_report.html")

    def run(self, idor_pairs=None):
        print(BANNER)
        print("[+] Starting SPY BUG")
        print("[+] Target:", self.target)
        print("[+] Active SQL differential checks:", self.active_confirm)
        print("[+] Browser XSS proof:", self.browser_confirm)

        self.reconnaissance()
        self.crawl()
        self.security_headers()
        self.directory_scan()
        self.xss_analysis()
        self.sqli_passive()
        self.sqli_active_confirmation()
        self.idor_analysis(idor_pairs or [])
        self.business_logic_analysis()
        self.authenticated_scan()
        self.tls_analysis()
        self.json_report()
        self.html_report()

        print("\n================================")
        print("          SPY BUG DONE")
        print("================================")
        print("[+] Pages:", len(self.visited))
        print("[+] URLs:", len(self.urls))
        print("[+] Forms:", len(self.forms))
        print("[+] Findings:", len(self.findings))
        print("[+] Reports: spy_bugs_report.html, spy_bugs_report.json")


def main():
    parser = argparse.ArgumentParser(
        description="SPY BUG - authorized web security scanner"
    )
    parser.add_argument("--target", required=True, help="Authorized target URL")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm permission to test this target")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Minimum delay between requests (minimum 0.5)")
    parser.add_argument("--max-pages", type=int, default=40,
                        help="Maximum pages to crawl (1-200)")
    parser.add_argument("--cookie-a", help="File containing Account A Cookie header")
    parser.add_argument("--cookie-b", help="File containing Account B Cookie header")
    parser.add_argument("--idor-pair", action="append", default=[],
                        help="Authorized object URL pair: URL_A|URL_B")
    parser.add_argument("--active-confirm", action="store_true",
                        help="Enable limited read-only SQL boolean differential checks")
    parser.add_argument("--browser-confirm-xss", action="store_true",
                        help="Enable harmless browser title-marker XSS proof (requires Playwright)")
    args = parser.parse_args()

    if not args.authorized:
        parser.error("Permission confirmation required: add --authorized")
    if args.delay < 0.5:
        parser.error("--delay must be at least 0.5 seconds")
    if not 1 <= args.max_pages <= 200:
        parser.error("--max-pages must be between 1 and 200")
    if bool(args.cookie_a) != bool(args.cookie_b):
        parser.error("For IDOR checks, provide both --cookie-a and --cookie-b")

    try:
        scanner = SpyBugs(
            target=args.target,
            delay=args.delay,
            max_pages=args.max_pages,
            cookie_a=args.cookie_a,
            cookie_b=args.cookie_b,
            active_confirm=args.active_confirm,
            browser_confirm=args.browser_confirm_xss,
        )
        scanner.run(idor_pairs=args.idor_pair)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)
    except (ValueError, OSError) as exc:
        print("[!] Error:", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()

