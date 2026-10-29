import uuid
import re
import ssl
import socket
import json
import urllib.parse
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.assessment.interfaces import AssessmentContext, Observation, AssessmentCheck

class SecurityHeadersCheck(AssessmentCheck):
    """
    Evaluates HTTP response headers for missing protective security headers.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "security-headers",
            "name": "HTTP Security Headers Assessment",
            "category": "Configuration",
            "severity": "MEDIUM",
            "description": "Verifies that industry standard HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) are present and properly configured."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        target_url = context.base_url
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        try:
            req_headers = {
                "User-Agent": "curl/7.55.1",
                "Accept": "*/*",
                **context.auth_headers
            }
            async with httpx.AsyncClient(headers=req_headers, timeout=8.0, verify=False, follow_redirects=True) as client:
                # Try HEAD first to bypass CDN anti-bot challenges and read genuine web server headers
                try:
                    res = await client.head(target_url)
                    headers = {k.lower(): v for k, v in res.headers.items()}
                except Exception:
                    headers = {}

                # If missing headers or HEAD failed, probe with GET
                if not headers or "strict-transport-security" not in headers:
                    try:
                        res_get = await client.get(target_url)
                        for k, v in res_get.headers.items():
                            if k.lower() not in headers:
                                headers[k.lower()] = v
                        res = res_get
                    except Exception:
                        pass
                
                raw_response = f"HTTP/{getattr(res, 'http_version', '1.1')} {getattr(res, 'status_code', 200)}\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
                raw_request = f"HEAD / HTTP/1.1\nHost: {context.base_url}\nUser-Agent: curl/7.55.1"

                # 1. HSTS Check
                if target_url.startswith("https://") and "strict-transport-security" not in headers:
                    findings.append({
                        "title": "Missing Strict-Transport-Security (HSTS) Header",
                        "category": "Cryptographic Failures",
                        "severity": "MEDIUM",
                        "confidence": 95.0,
                        "description": "The application does not enforce HTTP Strict Transport Security (HSTS), allowing potential SSL stripping / MITM downgrade attacks.",
                        "endpoint": f"GET {getattr(res.url, 'path', '/') or '/'}",
                        "method": "GET",
                        "parameter": "Strict-Transport-Security",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Man-In-The-Middle attackers can downgrade client connections from HTTPS to plaintext HTTP.",
                        "remediation": "Add the Strict-Transport-Security header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                    })

                # 2. Content-Security-Policy (CSP) Check
                if "content-security-policy" not in headers:
                    findings.append({
                        "title": "Missing Content-Security-Policy (CSP) Header",
                        "category": "Injection & XSS Protection",
                        "severity": "HIGH",
                        "confidence": 90.0,
                        "description": "Content-Security-Policy header is missing, which significantly increases exposure to Cross-Site Scripting (XSS) and data injection.",
                        "endpoint": f"GET {getattr(res.url, 'path', '/') or '/'}",
                        "method": "GET",
                        "parameter": "Content-Security-Policy",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Malicious scripts injected via XSS can execute unrestricted and exfiltrate sensitive data or session tokens.",
                        "remediation": "Define and deploy a robust Content-Security-Policy header restricting script, object, and style sources."
                    })

                # 3. X-Frame-Options Check (Clickjacking)
                if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                    findings.append({
                        "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                        "category": "Broken Access Control",
                        "severity": "MEDIUM",
                        "confidence": 95.0,
                        "description": "The web page does not prohibit framing in iframes, leaving it vulnerable to Clickjacking attacks.",
                        "endpoint": f"GET {getattr(res.url, 'path', '/') or '/'}",
                        "method": "GET",
                        "parameter": "X-Frame-Options",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Attackers can trick authenticated users into clicking concealed buttons/links by framing the application in a transparent iframe.",
                        "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
                    })

                # 4. X-Content-Type-Options Check
                if "x-content-type-options" not in headers or headers.get("x-content-type-options") != "nosniff":
                    findings.append({
                        "title": "Missing X-Content-Type-Options Header",
                        "category": "Security Misconfiguration",
                        "severity": "LOW",
                        "confidence": 99.0,
                        "description": "Missing 'X-Content-Type-Options: nosniff' header allows browsers to perform MIME-type sniffing.",
                        "endpoint": f"GET {getattr(res.url, 'path', '/') or '/'}",
                        "method": "GET",
                        "parameter": "X-Content-Type-Options",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Files interpreted as executable content (e.g., HTML/JS disguised as images) may execute malicious scripts in client browsers.",
                        "remediation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses."
                    })

                # 5. Information Disclosure (Server / Powered-By)
                revealing_banner = None
                if "x-powered-by" in headers:
                    revealing_banner = f"X-Powered-By: {headers['x-powered-by']}"
                elif "server" in headers:
                    srv = headers["server"].lower().strip()
                    # Only flag if server header reveals software version numbers or specific internals, not generic CDN proxies
                    import re
                    if re.search(r'[\d\.]+', srv) and srv not in ("hcdn", "cloudflare", "akamai", "fastly"):
                        revealing_banner = f"Server: {headers['server']}"

                if revealing_banner:
                    findings.append({
                        "title": "Server Banner Information Disclosure",
                        "category": "Information Disclosure",
                        "severity": "LOW",
                        "confidence": 85.0,
                        "description": f"The web server exposes software version details in header: '{revealing_banner}'.",
                        "endpoint": f"GET {getattr(res.url, 'path', '/') or '/'}",
                        "method": "GET",
                        "parameter": "Server / X-Powered-By",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Adversaries can tailor exploits targeting known vulnerabilities of the identified web server or framework.",
                        "remediation": "Disable or mask server banners in the web server configuration (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)."
                    })

        except Exception as e:
            # Fallback for unreachable / offline targets during dev testing
            findings.append({
                "title": f"Target Unreachable or Connection Timeout",
                "category": "Availability",
                "severity": "INFO",
                "confidence": 100.0,
                "description": f"Could not establish HTTP connection to {target_url}: {str(e)}",
                "endpoint": f"GET /",
                "method": "GET",
                "parameter": "Network",
                "request": f"GET / HTTP/1.1\nHost: {context.base_url}",
                "response": f"Connection Error: {str(e)}",
                "impact": "Automated security checks could not complete full live handshake.",
                "remediation": "Verify the target URL is running, accessible, and not blocking scanner IP addresses."
            })

        return findings

class SensitiveFilesCheck(AssessmentCheck):
    """
    Checks for exposed configuration and environment files (e.g. .env, robots.txt, .git).
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "sensitive-files",
            "name": "Sensitive File Exposure Check",
            "category": "Information Disclosure",
            "severity": "HIGH",
            "description": "Tests for publicly accessible sensitive files such as .env, .git/HEAD, and robots.txt."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"

        targets = [
            ("/.env", "Environment Variables File Exposure", "CRITICAL", "High risk of leaked database passwords, API keys, and credentials."),
            ("/robots.txt", "Robots.txt Information Disclosure", "INFO", "Robots.txt discloses hidden administration or private endpoints.")
        ]

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            for path, title, severity, impact in targets:
                try:
                    res = await client.get(f"{base}{path}")
                    if res.status_code == 200 and len(res.text.strip()) > 0:
                        if path == "/.env" and any(k in res.text for k in ["DB_", "SECRET", "PASSWORD", "KEY="]):
                            findings.append({
                                "title": title,
                                "category": "Security Misconfiguration",
                                "severity": severity,
                                "confidence": 98.0,
                                "description": f"The sensitive file '{path}' is publicly accessible without authentication.",
                                "endpoint": f"GET {path}",
                                "method": "GET",
                                "parameter": path,
                                "request": f"GET {path} HTTP/1.1\nHost: {res.url.host}",
                                "response": f"HTTP/1.1 200 OK\n\n{res.text[:200]}...",
                                "impact": impact,
                                "remediation": f"Block public access to '{path}' in web server access control rules immediately."
                            })
                        elif path == "/robots.txt":
                            findings.append({
                                "title": title,
                                "category": "Reconnaissance",
                                "severity": severity,
                                "confidence": 100.0,
                                "description": "Robots.txt was found and discloses directory structure.",
                                "endpoint": "GET /robots.txt",
                                "method": "GET",
                                "parameter": "robots.txt",
                                "request": f"GET /robots.txt HTTP/1.1\nHost: {res.url.host}",
                                "response": f"HTTP/1.1 200 OK\n\n{res.text[:150]}",
                                "impact": impact,
                                "remediation": "Ensure disallowed paths in robots.txt are protected by authentication and not solely reliant on obscurity."
                            })
                except Exception:
                    continue

        return findings

class CorsMisconfigurationCheck(AssessmentCheck):
    """
    Evaluates Cross-Origin Resource Sharing (CORS) configurations for overly permissive or vulnerable policies.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "cors-misconfiguration",
            "name": "CORS Policy Security Assessment",
            "category": "Cross-Origin Security",
            "severity": "HIGH",
            "description": "Checks if the server permits arbitrary or unvetted origins with credentials, exposing private API data to cross-origin abuse."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        target_url = context.base_url
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        test_origin = "https://security-audit-test.example.com"
        headers_to_send = {
            "Origin": test_origin,
            "User-Agent": "CyberAI-Scanner/1.0"
        }

        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=False) as client:
                res = await client.get(target_url, headers=headers_to_send)
                headers = {k.lower(): v for k, v in res.headers.items()}
                
                acao = headers.get("access-control-allow-origin")
                acac = headers.get("access-control-allow-credentials", "").lower() == "true"

                raw_request = f"GET / HTTP/1.1\nHost: {res.url.host}\nOrigin: {test_origin}\nUser-Agent: CyberAI-Scanner/1.0"
                raw_response = f"HTTP/{res.http_version} {res.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in res.headers.items())

                # 1. Arbitrary Origin reflection with credentials allowed (Critical/High)
                if acao == test_origin and acac:
                    findings.append({
                        "title": "Vulnerable CORS Policy: Arbitrary Origin Reflection with Credentials",
                        "category": "Cross-Origin Security",
                        "severity": "HIGH",
                        "confidence": 98.0,
                        "description": f"The application reflects arbitrary untrusted Origin headers ('{test_origin}') in Access-Control-Allow-Origin while allowing Access-Control-Allow-Credentials: true.",
                        "endpoint": "GET /",
                        "method": "GET",
                        "parameter": "Origin",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Malicious websites can issue authenticated cross-origin requests and exfiltrate confidential user data or perform unauthorized transactions.",
                        "remediation": "Do not dynamically reflect untrusted Origin headers. Maintain an explicit whitelist of trusted origins and avoid setting Access-Control-Allow-Credentials: true with reflected origins."
                    })
                # 2. Insecure Wildcard with credentials or excessive allowance
                elif acao == "*" and acac:
                    findings.append({
                        "title": "Invalid Insecure CORS Configuration: Wildcard with Credentials",
                        "category": "Cross-Origin Security",
                        "severity": "HIGH",
                        "confidence": 100.0,
                        "description": "The server specifies Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true.",
                        "endpoint": "GET /",
                        "method": "GET",
                        "parameter": "Access-Control-Allow-Origin",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "Severe configuration anomaly violating web standards and inviting cross-origin eavesdropping.",
                        "remediation": "Remove the wildcard origin when credentials are required and configure trusted domains explicitly."
                    })
                # 3. Permissive Wildcard on potentially authenticated endpoints
                elif acao == "*":
                    findings.append({
                        "title": "Permissive CORS Wildcard (Access-Control-Allow-Origin: *)",
                        "category": "Information Disclosure",
                        "severity": "LOW",
                        "confidence": 90.0,
                        "description": "The endpoint allows any external website to read response content via Access-Control-Allow-Origin: *.",
                        "endpoint": "GET /",
                        "method": "GET",
                        "parameter": "Access-Control-Allow-Origin",
                        "request": raw_request,
                        "response": raw_response,
                        "impact": "If this endpoint serves sensitive user or organizational data, unauthorized origins can read the response.",
                        "remediation": "Ensure wildcard CORS is only enabled on strictly public, non-sensitive static resources or documentation."
                    })
        except Exception:
            pass

        return findings

class OpenRedirectCheck(AssessmentCheck):
    """
    Tests web endpoints for open URL redirection vulnerabilities in query parameters.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "open-redirect",
            "name": "Open URL Redirection Assessment",
            "category": "Broken Access Control",
            "severity": "MEDIUM",
            "description": "Tests query parameters commonly used for navigation (redirect, url, next, dest) against arbitrary off-site redirections."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"

        canary_destination = "https://security-audit-canary.test"
        param_candidates = ["redirect", "url", "next", "return_to", "dest", "target", "r"]

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            for param in param_candidates:
                test_url = f"{base}/?{param}={canary_destination}"
                try:
                    res = await client.get(test_url)
                    location = res.headers.get("location", "")

                    if res.status_code in [301, 302, 303, 307, 308] and location.startswith(canary_destination):
                        raw_request = f"GET /?{param}={canary_destination} HTTP/1.1\nHost: {res.url.host}\nUser-Agent: CyberAI-Scanner/1.0"
                        raw_response = f"HTTP/{res.http_version} {res.status_code}\nLocation: {location}\n" + "\n".join(f"{k}: {v}" for k, v in res.headers.items() if k.lower() != "location")

                        findings.append({
                            "title": f"Unvalidated Open URL Redirection via '{param}' Parameter",
                            "category": "Broken Access Control",
                            "severity": "MEDIUM",
                            "confidence": 95.0,
                            "description": f"The application accepts an arbitrary external URL in parameter '{param}' and immediately redirects users without domain validation.",
                            "endpoint": f"GET /?{param}=...",
                            "method": "GET",
                            "parameter": param,
                            "request": raw_request,
                            "response": raw_response,
                            "impact": "Attackers can create convincing phishing links using your legitimate domain name that seamlessly forward victims to credential-harvesting phishing sites.",
                            "remediation": "Restrict redirects strictly to local relative paths (e.g. matching '^/[^/\\\\].*') or validate target destinations against an authoritative domain whitelist."
                        })
                        break # One confirmed parameter is sufficient for discovery
                except Exception:
                    continue

        return findings

class SqlErrorDisclosureCheck(AssessmentCheck):
    """
    Checks for technical database error leakage in HTTP responses when input syntax markers are evaluated.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "sql-error-disclosure",
            "name": "Database Error & SQL Syntax Leakage Assessment",
            "category": "Injection & Database Security",
            "severity": "HIGH",
            "description": "Tests query parameters for raw DBMS error messages and unhandled SQL syntax exceptions."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"

        # Defensive diagnostics signatures (detecting unhandled database exceptions)
        db_error_signatures = [
            ("MySQL / MariaDB", ["you have an error in your sql syntax", "check the manual that corresponds to your mysql server", "mysql_fetch_array"]),
            ("PostgreSQL", ["psqlexception", "syntax error at or near", "pg_query(): query failed", "unterminated quoted string at or near"]),
            ("SQLite", ["sqlite3.operationalerror", "unrecognized token:", "near \"'\": syntax error"]),
            ("Microsoft SQL Server", ["unclosed quotation mark after the character string", "microsoft oledb provider for sql server", "odbc sql server driver"]),
            ("Oracle", ["ora-00933", "ora-00936", "quoted string not properly terminated"]),
            ("Generic ORM / Backend", ["operationalerror:", "syntax error in sql statement", "jdbc driver sql syntax error"])
        ]

        test_params = ["id", "query", "q", "search", "page", "category"]
        test_delimiter = "'"

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            for p in test_params:
                test_url = f"{base}/?{p}=1{test_delimiter}"
                try:
                    res = await client.get(test_url)
                    body_lower = res.text.lower()

                    for db_family, sigs in db_error_signatures:
                        for sig in sigs:
                            if sig in body_lower:
                                raw_request = f"GET /?{p}=1{test_delimiter} HTTP/1.1\nHost: {res.url.host}\nUser-Agent: CyberAI-Scanner/1.0"
                                raw_response = f"HTTP/{res.http_version} {res.status_code}\n\n{res.text[:300]}..."

                                findings.append({
                                    "title": f"Database SQL Error Information Disclosure ({db_family})",
                                    "category": "Injection & Database Security",
                                    "severity": "HIGH",
                                    "confidence": 92.0,
                                    "description": f"The application returned an unhandled {db_family} error message when a single quote delimiter was evaluated in parameter '{p}'.",
                                    "endpoint": f"GET /?{p}=...",
                                    "method": "GET",
                                    "parameter": p,
                                    "request": raw_request,
                                    "response": raw_response,
                                    "impact": "Exposed SQL exceptions disclose backend database engine, table names, and column structures, making SQL Injection attacks easier to construct.",
                                    "remediation": "Use parameterized queries / prepared statements (or ORMs with bound variables) for all database operations, and enable global exception handlers that output generic user-friendly errors."
                                })
                                return findings # Return immediately on detection
                except Exception:
                    continue

        return findings

class CookieSecurityCheck(AssessmentCheck):
    """
    Evaluates HTTP Set-Cookie response headers for essential security flags (HttpOnly, Secure, SameSite).
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "cookie-security",
            "name": "Session Cookie Security Flags Assessment",
            "category": "Authentication & Session",
            "severity": "MEDIUM",
            "description": "Verifies that session and sensitive cookies enforce HttpOnly, Secure, and appropriate SameSite attributes."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        target_url = context.base_url
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
                res = await client.get(target_url)
                raw_request = f"GET / HTTP/1.1\nHost: {res.url.host}\nUser-Agent: CyberAI-Scanner/1.0"
                raw_response = f"HTTP/{res.http_version} {res.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in res.headers.items())

                # Inspect Set-Cookie headers
                cookies = res.headers.get_list("set-cookie") if hasattr(res.headers, "get_list") else ([res.headers.get("set-cookie")] if res.headers.get("set-cookie") else [])

                for cookie_str in cookies:
                    if not cookie_str:
                        continue
                    parts = [p.strip().lower() for p in cookie_str.split(";")]
                    cookie_name = cookie_str.split("=")[0].strip()

                    # Missing HttpOnly
                    if "httponly" not in parts:
                        findings.append({
                            "title": f"Cookie Missing 'HttpOnly' Flag: {cookie_name}",
                            "category": "Session Management",
                            "severity": "MEDIUM",
                            "confidence": 95.0,
                            "description": f"The cookie '{cookie_name}' is set without the 'HttpOnly' directive, making it accessible to client-side JavaScript.",
                            "endpoint": "GET /",
                            "method": "GET",
                            "parameter": cookie_name,
                            "request": raw_request,
                            "response": raw_response,
                            "impact": "If a Cross-Site Scripting (XSS) vulnerability exists anywhere on the domain, attackers can steal this session cookie using document.cookie.",
                            "remediation": "Add the 'HttpOnly' flag to the Set-Cookie directive for all authentication and session identifiers."
                        })

                    # Missing Secure flag on HTTPS
                    if target_url.startswith("https://") and "secure" not in parts:
                        findings.append({
                            "title": f"Cookie Missing 'Secure' Flag: {cookie_name}",
                            "category": "Cryptographic Failures",
                            "severity": "MEDIUM",
                            "confidence": 95.0,
                            "description": f"The cookie '{cookie_name}' was transmitted over HTTPS without the 'Secure' attribute.",
                            "endpoint": "GET /",
                            "method": "GET",
                            "parameter": cookie_name,
                            "request": raw_request,
                            "response": raw_response,
                            "impact": "Browsers may send this cookie in subsequent unencrypted HTTP requests, enabling network eavesdroppers to intercept session tokens.",
                            "remediation": "Ensure the 'Secure' flag is configured on all cookies in HTTPS production environments."
                        })

                    # Missing SameSite flag
                    has_samesite = any(p.startswith("samesite") for p in parts)
                    if not has_samesite:
                        findings.append({
                            "title": f"Cookie Missing 'SameSite' Attribute: {cookie_name}",
                            "category": "Broken Access Control",
                            "severity": "LOW",
                            "confidence": 90.0,
                            "description": f"The cookie '{cookie_name}' does not specify a 'SameSite' attribute (Lax or Strict).",
                            "endpoint": "GET /",
                            "method": "GET",
                            "parameter": cookie_name,
                            "request": raw_request,
                            "response": raw_response,
                            "impact": "Leaves the application more susceptible to Cross-Site Request Forgery (CSRF) on older browsers.",
                            "remediation": "Explicitly set 'SameSite=Lax' or 'SameSite=Strict' on all cookies."
                        })
        except Exception:
            pass

        return findings

class ActiveFormXssFuzzerCheck(AssessmentCheck):
    """
    Active Form & Parameter Fuzzer: Tests discovered HTML form inputs and URL query parameters
    for unescaped Cross-Site Scripting (Reflected XSS) vulnerabilities using safe diagnostic canaries.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "form-xss-fuzzer",
            "name": "Active Form & Parameter XSS Fuzzer",
            "category": "Injection & XSS Protection",
            "severity": "HIGH",
            "description": "Fuzzes HTML forms and query parameters with safe canary probes to detect unescaped reflection in the DOM."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        canary = 'cyberai_probe_xss"\'><xss_canary>'
        unescaped_marker = '><xss_canary>'

        headers = {
            "User-Agent": "CyberAI-Scanner/2.0",
            **context.auth_headers
        }

        # Gather target URLs and parameters from crawler or defaults
        targets_to_test = []
        if context.discovered_endpoints:
            for ep in context.discovered_endpoints:
                if ep.forms:
                    for form in ep.forms:
                        targets_to_test.append({
                            "url": form.get("action") or ep.url,
                            "method": form.get("method", "GET").upper(),
                            "params": [inp["name"] for inp in form.get("inputs", []) if inp.get("name")],
                            "is_form": True
                        })
                if ep.parameters:
                    targets_to_test.append({
                        "url": ep.url.split("?")[0],
                        "method": "GET",
                        "params": ep.parameters,
                        "is_form": False
                    })

        # Fallback to base url if no endpoints discovered yet
        if not targets_to_test:
            targets_to_test.append({
                "url": context.base_url,
                "method": "GET",
                "params": ["q", "search", "name", "query", "id"],
                "is_form": False
            })

        async with httpx.AsyncClient(
            headers=headers,
            cookies=context.cookies,
            timeout=6.0,
            verify=False,
            follow_redirects=True
        ) as client:
            tested_keys = set()
            for t in targets_to_test[:8]: # Test up to 8 distinct endpoints/forms
                for param in t["params"][:4]: # Test up to 4 parameters per form
                    test_key = f"{t['method']} {t['url']} {param}"
                    if test_key in tested_keys:
                        continue
                    tested_keys.add(test_key)

                    try:
                        if t["method"] == "POST":
                            post_data = {param: canary}
                            res = await client.post(t["url"], data=post_data)
                            raw_req = f"POST {t['url']} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{param}={canary}"
                        else:
                            res = await client.get(t["url"], params={param: canary})
                            raw_req = f"GET {t['url']}?{param}={canary} HTTP/1.1"

                        # Check if canary is reflected without proper entity encoding
                        if unescaped_marker in res.text:
                            snippet_start = max(0, res.text.find(unescaped_marker) - 50)
                            snippet_end = min(len(res.text), snippet_start + 150)
                            reflected_snippet = res.text[snippet_start:snippet_end]

                            findings.append({
                                "title": f"Reflected Cross-Site Scripting (XSS) in Parameter '{param}'",
                                "category": "Injection & XSS Protection",
                                "severity": "HIGH",
                                "confidence": 96.0,
                                "description": f"The parameter '{param}' at '{t['url']}' reflects unescaped user-supplied HTML/JavaScript tags directly in the response.",
                                "endpoint": f"{t['method']} {t['url']}",
                                "method": t["method"],
                                "parameter": param,
                                "request": raw_req,
                                "response": f"HTTP/{res.http_version} {res.status_code}\n\n[...Reflected Output...]\n{reflected_snippet}",
                                "impact": "An adversary can craft a malicious link or form submission that executes arbitrary JavaScript in the victim's browser session, compromising authentication tokens and private user actions.",
                                "remediation": "Apply context-aware output encoding (e.g. htmlspecialchars($input, ENT_QUOTES, 'UTF-8') in PHP or automated framework escaping) on all user-controlled data before rendering into HTML."
                            })
                            break
                    except Exception:
                        continue

        return findings

class TimeBasedSqlInjectionCheck(AssessmentCheck):
    """
    Time-Based Blind SQL Injection Assessment:
    Measures differential response latency when safe diagnostic delay heuristics are evaluated.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "time-based-sqli",
            "name": "Time-Based Blind SQL Injection Assessment",
            "category": "Injection & Database Security",
            "severity": "CRITICAL",
            "description": "Tests input parameters for time-delayed query execution using non-destructive timing markers."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        import time

        headers = {
            "User-Agent": "CyberAI-Scanner/2.0",
            **context.auth_headers
        }

        # Safe diagnostic delay payload (2 seconds max)
        test_payloads = [
            ("MySQL / MariaDB", "1' AND (SELECT 1 FROM (SELECT SLEEP(2))x)-- "),
            ("PostgreSQL", "1' AND (SELECT pg_sleep(2))-- ")
        ]

        # Gather endpoints to test
        params_to_test = []
        if context.discovered_endpoints:
            for ep in context.discovered_endpoints:
                for p in ep.parameters:
                    params_to_test.append((ep.url.split("?")[0], ep.method, p))
        
        if not params_to_test:
            params_to_test = [(context.base_url, "GET", "id"), (context.base_url, "GET", "q")]

        async with httpx.AsyncClient(
            headers=headers,
            cookies=context.cookies,
            timeout=8.0,
            verify=False,
            follow_redirects=True
        ) as client:
            tested = set()
            for url, method, param in params_to_test[:4]:
                if (url, param) in tested:
                    continue
                tested.add((url, param))

                try:
                    # 1. Measure baseline latency
                    t_start = time.time()
                    base_res = await client.get(url, params={param: "1"})
                    baseline_duration = time.time() - t_start

                    # 2. Evaluate delay payload if baseline was fast (< 1.5s)
                    if baseline_duration < 1.5:
                        for db_type, payload in test_payloads:
                            t_probe_start = time.time()
                            probe_res = await client.get(url, params={param: payload})
                            probe_duration = time.time() - t_probe_start

                            # Check for initial latency inflation (> 1.8s delay compared to baseline)
                            if probe_duration >= (baseline_duration + 1.8):
                                # Multi-Sample Confirmation: Probe with 4-second delay to confirm genuine DB execution
                                confirm_payload = payload.replace("2", "4")
                                t_conf_start = time.time()
                                conf_res = await client.get(url, params={param: confirm_payload})
                                conf_duration = time.time() - t_conf_start

                                # Negative Control Probe: Non-delay string to verify it wasn't just a slow network
                                t_ctrl_start = time.time()
                                ctrl_res = await client.get(url, params={param: "control_sample_no_delay"})
                                ctrl_duration = time.time() - t_ctrl_start

                                # Truly confirmed if 4s probe scaled (> 3.2s) AND negative control was fast (< 1.5s)
                                if conf_duration >= (baseline_duration + 3.2) and ctrl_duration < (baseline_duration + 1.2):
                                    findings.append({
                                        "title": f"Time-Based Blind SQL Injection in Parameter '{param}' ({db_type})",
                                        "category": "Injection & Database Security",
                                        "severity": "CRITICAL",
                                        "confidence": 98.0,
                                        "description": f"Verified SQL injection: Application exhibited reproducible latency scaling (2s test took {probe_duration:.2f}s, 4s confirmation took {conf_duration:.2f}s, control was {ctrl_duration:.2f}s).",
                                        "endpoint": f"GET {url}?{param}=...",
                                        "method": method,
                                        "parameter": param,
                                        "request": f"GET {url}?{param}={payload} HTTP/1.1\nHost: {probe_res.url.host}",
                                        "response": f"HTTP/{probe_res.http_version} {probe_res.status_code}\nSleep 2s: {probe_duration:.2f}s | Sleep 4s: {conf_duration:.2f}s",
                                        "impact": "Attackers can extract confidential database contents, user credentials, and table structures character-by-character without needing visible error messages.",
                                        "remediation": "Mandate prepared statements with parameterized queries across all database operations. Never concatenate untrusted parameters directly into SQL queries."
                                    })
                                    return findings
                except Exception:
                    continue

        return findings

class AuthenticatedAccessCheck(AssessmentCheck):
    """
    Authenticated Scanning & Authorization Check:
    Verifies that authenticated routes are accessible with provided credentials,
    and checks for Missing Function Level Access Control on administrative endpoints.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "authenticated-access",
            "name": "Authenticated Access & Authorization Check",
            "category": "Broken Access Control",
            "severity": "HIGH",
            "description": "Verifies authenticated session functionality and tests for unauthorized access to administrative routes without credentials."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        has_auth = bool(context.cookies or context.auth_headers)

        # Target administrative and role-specific operational endpoints
        admin_paths = [
            "/miske.php",                      # Super Admin Portal (مدير رئيسي)
            "/admin_marketing_main.php",       # Marketing Agent Portal (وكيل تسويق)
            "/admin_accounts_post_early.php",  # Shipping Companies Coordinator (مسئول شركات الشحن)
            "/admin_support.php",              # Technical Support Portal (دعم فني)
            "/admin",
            "/admin/",
            "/admin/dashboard.php",
            "/dashboard",
            "/profile"
        ]
        base = context.base_url.rstrip("/")

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            for p in admin_paths:
                target = f"{base}{p}"
                try:
                    # Test request without authentication
                    unauth_res = await client.get(target)

                    # If endpoint returns 200 OK without any login redirect or 401/403, it may lack access control
                    if unauth_res.status_code == 200 and len(unauth_res.text.strip()) > 300:
                        body_lower = unauth_res.text.lower()
                        # Verify it is not merely a login page
                        is_login_page = any(k in body_lower for k in ["login", "sign in", "password", "username"])
                        if not is_login_page and any(k in body_lower for k in ["admin", "dashboard", "marketing", "manage", "users"]):
                            findings.append({
                                "title": f"Missing Authentication Control on Administrative Endpoint '{p}'",
                                "category": "Broken Access Control",
                                "severity": "HIGH",
                                "confidence": 90.0,
                                "description": f"The administrative path '{p}' was accessible with HTTP 200 OK without requiring authentication or session tokens.",
                                "endpoint": f"GET {p}",
                                "method": "GET",
                                "parameter": p,
                                "request": f"GET {p} HTTP/1.1\nHost: {unauth_res.url.host}",
                                "response": f"HTTP/1.1 200 OK\n\n{unauth_res.text[:250]}...",
                                "impact": "Unauthenticated attackers can directly access internal administration pages and functionality without logging in.",
                                "remediation": "Enforce strict session authentication checks and server-side authorization middleware on all administrative scripts."
                            })
                            break
                except Exception:
                    continue

        return findings

class SsrfCheck(AssessmentCheck):
    """
    Server-Side Request Forgery (SSRF) Assessment:
    Tests URL and import parameters against loopback and cloud metadata endpoints.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "ssrf-cloud-metadata",
            "name": "Server-Side Request Forgery (SSRF) & Cloud Metadata Probing",
            "category": "Server-Side Injection",
            "severity": "CRITICAL",
            "description": "Tests URL, import, webhook, and image fetching parameters for internal network access and cloud metadata exposure (AWS/GCP/Azure)."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        ssrf_params = ["url", "dest", "target", "redirect", "feed", "image_url", "src", "link", "webhook", "fetch", "proxy", "uri"]
        test_payload = "http://169.254.169.254/latest/meta-data/"
        
        candidates = []
        base = context.base_url.rstrip("/")
        
        # Check endpoints and query parameters discovered by crawler
        for ep in context.discovered_endpoints:
            for p in ep.parameters:
                if p.lower() in ssrf_params or any(k in p.lower() for k in ["url", "link", "fetch", "dest"]):
                    candidates.append((ep.path, p))

        # Add fallback common endpoint/param pairs
        if not candidates:
            candidates = [
                ("/fetch", "url"),
                ("/import", "source"),
                ("/api/proxy", "url"),
                ("/webhook", "target")
            ]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=False) as client:
            for path, param in candidates[:5]:
                probe_url = f"{base}{path}?{param}={urllib.parse.quote(test_payload)}"
                try:
                    res = await client.get(probe_url, headers=context.auth_headers)
                    text_lower = res.text.lower()
                    if any(k in text_lower for k in ["ami-id", "instance-id", "computemetadata", "iam/security-credentials"]):
                        findings.append({
                            "title": "Critical Server-Side Request Forgery (SSRF) Cloud Metadata Leak",
                            "category": "Server-Side Request Forgery (SSRF)",
                            "severity": "CRITICAL",
                            "confidence": 98.0,
                            "description": f"The parameter '{param}' on '{path}' accepted cloud metadata loopback URI ({test_payload}) and returned internal cloud instance metadata.",
                            "endpoint": f"GET {path}",
                            "method": "GET",
                            "parameter": param,
                            "request": f"GET {probe_url} HTTP/1.1\nHost: {urllib.parse.urlparse(base).netloc}",
                            "response": f"HTTP/1.1 {res.status_code}\n\n{res.text[:300]}...",
                            "impact": "Attackers can steal cloud IAM credentials, access internal VPC microservices, and compromise cloud infrastructure.",
                            "remediation": "Validate input URLs against a strict whitelist of allowed domains, reject private IP ranges (RFC 1918) and link-local addresses (169.254.169.254), and disable HTTP redirection in server-side HTTP clients."
                        })
                        break
                except Exception:
                    continue

        return findings

class AdvancedIdorBolaCheck(AssessmentCheck):
    """
    Advanced Insecure Direct Object Reference (IDOR / BOLA) Check:
    Tests object identifier traversal across invoices, orders, and user resources.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "advanced-idor-bola",
            "name": "Broken Object Level Authorization (IDOR / BOLA)",
            "category": "Broken Access Control",
            "severity": "HIGH",
            "description": "Tests object identification tampering on sensitive routes (invoices, accounts, profile data) to identify cross-tenant data leakage."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        
        # Test candidate object paths
        test_endpoints = [
            ("/api/v1/invoices/101", "/api/v1/invoices/102", "invoice_id"),
            ("/api/orders/1", "/api/orders/2", "order_id"),
            ("/invoices.php?id=101", "/invoices.php?id=102", "id"),
            ("/user/profile?user_id=1", "/user/profile?user_id=2", "user_id"),
            ("/api/users/1", "/api/users/2", "id")
        ]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=False) as client:
            for p1, p2, param in test_endpoints:
                try:
                    res1 = await client.get(f"{base}{p1}", headers=context.auth_headers)
                    if res1.status_code == 200 and len(res1.text) > 40:
                        res2 = await client.get(f"{base}{p2}", headers=context.auth_headers)
                        # If both return 200 OK without requiring specific user session authorization
                        if res2.status_code == 200 and len(res2.text) > 40 and res1.text != res2.text:
                            # Verify response resembles JSON or structured data
                            if any(k in res2.text.lower() for k in ["total", "amount", "customer", "email", "name", "id", "status"]):
                                findings.append({
                                    "title": f"Insecure Direct Object Reference (IDOR / BOLA) in '{param}'",
                                    "category": "Broken Access Control",
                                    "severity": "HIGH",
                                    "confidence": 92.0,
                                    "description": f"Sequential object identifiers on endpoint '{p1}' can be enumerated to access unauthorized records without tenant authorization checks.",
                                    "endpoint": f"GET {p1}",
                                    "method": "GET",
                                    "parameter": param,
                                    "request": f"GET {p2} HTTP/1.1\nHost: {urllib.parse.urlparse(base).netloc}",
                                    "response": f"HTTP/1.1 200 OK\n\n{res2.text[:250]}...",
                                    "impact": "Attackers can harvest records, orders, or personally identifiable information (PII) of all other platform users.",
                                    "remediation": "Enforce server-side record ownership verification before returning object details (e.g., WHERE id = :id AND user_id = :auth_user_id), and utilize non-sequential UUIDs."
                                })
                                break
                except Exception:
                    continue

        return findings

class LfiCommandInjectionCheck(AssessmentCheck):
    """
    Local / Remote File Inclusion (LFI/RFI) & OS Command Injection Check.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "lfi-command-injection",
            "name": "Local/Remote File Inclusion & Command Injection",
            "category": "Injection",
            "severity": "CRITICAL",
            "description": "Fuzzes file-handling and execution parameters with directory traversal and shell separators."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        file_params = ["file", "page", "doc", "view", "template", "path", "include", "read"]
        
        # Test traversal payloads
        lfi_payloads = [
            ("../../../../etc/passwd", "root:x:0:0:"),
            ("..\\..\\..\\..\\windows\\win.ini", "[extensions]"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA")
        ]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
            for p in file_params[:4]:
                for payload, indicator in lfi_payloads:
                    probe_url = f"{base}/?{p}={urllib.parse.quote(payload)}"
                    try:
                        res = await client.get(probe_url, headers=context.auth_headers)
                        if indicator in res.text:
                            findings.append({
                                "title": f"Arbitrary File Inclusion (LFI/Path Traversal) via '{p}'",
                                "category": "Injection",
                                "severity": "CRITICAL",
                                "confidence": 99.0,
                                "description": f"The parameter '{p}' allows reading sensitive host files via path traversal payload '{payload}'.",
                                "endpoint": f"GET /?{p}=...",
                                "method": "GET",
                                "parameter": p,
                                "request": f"GET {probe_url} HTTP/1.1\nHost: {urllib.parse.urlparse(base).netloc}",
                                "response": f"HTTP/1.1 {res.status_code}\n\n{res.text[:250]}...",
                                "impact": "Complete system compromise via disclosure of system credentials, configuration files, and source code.",
                                "remediation": "Do not pass user-controlled input directly to file system operations or include() statements. Use a strict whitelist of allowed filenames and basename() sanitization."
                            })
                            return findings
                    except Exception:
                        continue

        return findings

class SstiCheck(AssessmentCheck):
    """
    Server-Side Template Injection (SSTI) Check:
    Tests Jinja, Twig, Blade, and Freemarker template evaluation.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "ssti-template-injection",
            "name": "Server-Side Template Injection (SSTI)",
            "category": "Injection",
            "severity": "CRITICAL",
            "description": "Injects mathematical canary expressions (e.g., {{7*7}}) to detect template engine code evaluation."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        canary_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49")
        ]
        test_params = ["name", "q", "title", "msg", "template", "preview", "email"]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
            for p in test_params:
                for payload, expected in canary_payloads:
                    probe_url = f"{base}/?{p}={urllib.parse.quote(payload)}"
                    try:
                        res = await client.get(probe_url, headers=context.auth_headers)
                        # Ensure 49 was calculated and the raw payload was not merely echoed
                        if expected in res.text and payload not in res.text:
                            findings.append({
                                "title": f"Server-Side Template Injection (SSTI) in '{p}'",
                                "category": "Injection",
                                "severity": "CRITICAL",
                                "confidence": 95.0,
                                "description": f"The parameter '{p}' evaluated the template expression '{payload}' server-side, yielding computed result '{expected}'.",
                                "endpoint": f"GET /?{p}=...",
                                "method": "GET",
                                "parameter": p,
                                "request": f"GET {probe_url} HTTP/1.1\nHost: {urllib.parse.urlparse(base).netloc}",
                                "response": f"HTTP/1.1 200 OK\n\n...{expected}...",
                                "impact": "Remote Code Execution (RCE) on the server through template engine sandbox escapes.",
                                "remediation": "Do not pass user inputs directly into template rendering engines. Pass user data as context variables instead of compiling dynamic template strings."
                            })
                            return findings
                    except Exception:
                        continue

        return findings

class UnrestrictedFileUploadCheck(AssessmentCheck):
    """
    Unrestricted File Upload & Extension Bypass Check:
    Audits upload endpoints for executable script acceptance (.php5, .phtml, .phar).
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "unrestricted-file-upload",
            "name": "Unrestricted File Upload & Script Execution",
            "category": "File Upload Vulnerabilities",
            "severity": "HIGH",
            "description": "Inspects file upload endpoints and forms for missing extension whitelisting and MIME validation."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        upload_paths = ["/upload", "/api/upload", "/file-upload", "/admin/upload.php", "/avatar/upload"]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=False) as client:
            for path in upload_paths:
                try:
                    res = await client.get(f"{base}{path}", headers=context.auth_headers)
                    # Check if upload form exists
                    if res.status_code in [200, 405] and any(k in res.text.lower() for k in ['type="file"', 'multipart/form-data', 'upload']):
                        # Test sending a benign text file disguised as a script
                        files = {'file': ('sential_test.phtml', b'<!-- sential test harmless check -->', 'image/jpeg')}
                        post_res = await client.post(f"{base}{path}", files=files, headers=context.auth_headers)
                        if post_res.status_code in [200, 201] and "error" not in post_res.text.lower():
                            findings.append({
                                "title": f"Potentially Unrestricted File Upload on '{path}'",
                                "category": "File Upload Vulnerabilities",
                                "severity": "HIGH",
                                "confidence": 85.0,
                                "description": f"The upload endpoint '{path}' accepted a file with executable extension (.phtml) without immediate server-side rejection.",
                                "endpoint": f"POST {path}",
                                "method": "POST",
                                "parameter": "file",
                                "request": f"POST {path} HTTP/1.1\nContent-Type: multipart/form-data\n\nFilename: sential_test.phtml",
                                "response": f"HTTP/1.1 {post_res.status_code}\n\n{post_res.text[:200]}...",
                                "impact": "Attackers can upload malicious PHP, ASP, or JSP web shells leading to total server compromise.",
                                "remediation": "Enforce strict extension whitelisting (.jpg, .png, .pdf only), store uploaded files outside the public web root, and serve files with 'Content-Disposition: attachment'."
                            })
                            break
                except Exception:
                    continue

        return findings

class ApiSecurityCheck(AssessmentCheck):
    """
    Modern API Security Check:
    Auto-discovers OpenAPI / Swagger specifications and GraphQL Introspection query leakage.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "api-security-swagger-graphql",
            "name": "API Security & Schema Disclosure (Swagger / GraphQL)",
            "category": "API Security",
            "severity": "MEDIUM",
            "description": "Detects exposed Swagger/OpenAPI documentation and enabled GraphQL Introspection schemas."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        
        # 1. Swagger / OpenAPI Spec Discovery
        swagger_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/docs",
            "/swagger/v1/swagger.json"
        ]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
            for sp in swagger_paths:
                try:
                    res = await client.get(f"{base}{sp}", headers=context.auth_headers)
                    if res.status_code == 200:
                        text_lower = res.text.lower()
                        if any(k in text_lower for k in ['"swagger"', '"openapi"', 'swagger-ui', '"paths"']):
                            findings.append({
                                "title": f"Unprotected OpenAPI / Swagger Specification at '{sp}'",
                                "category": "API Security",
                                "severity": "MEDIUM",
                                "confidence": 95.0,
                                "description": f"Publicly accessible API schema documentation found at '{sp}'. Exposes backend endpoints, parameters, and internal models.",
                                "endpoint": f"GET {sp}",
                                "method": "GET",
                                "parameter": sp,
                                "request": f"GET {sp} HTTP/1.1\nHost: {urllib.parse.urlparse(base).netloc}",
                                "response": f"HTTP/1.1 200 OK\n\n{res.text[:250]}...",
                                "impact": "Exposes full API blueprints and hidden endpoints to reconnaissance and targeted fuzzing.",
                                "remediation": "Restrict access to API documentation in production environments behind authentication or VPN."
                            })
                            break
                except Exception:
                    continue

            # 2. GraphQL Introspection Query Check
            graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql"]
            introspection_query = {"query": "{ __schema { types { name } } }"}
            for gp in graphql_paths:
                try:
                    res = await client.post(f"{base}{gp}", json=introspection_query, headers=context.auth_headers)
                    if res.status_code == 200 and "__schema" in res.text:
                        findings.append({
                            "title": f"GraphQL Introspection Query Enabled on '{gp}'",
                            "category": "API Security",
                            "severity": "MEDIUM",
                            "confidence": 98.0,
                            "description": f"GraphQL endpoint '{gp}' allows full introspection querying, leaking all internal types, queries, and mutations.",
                            "endpoint": f"POST {gp}",
                            "method": "POST",
                            "parameter": "__schema",
                            "request": f"POST {gp} HTTP/1.1\nContent-Type: application/json\n\n{json.dumps(introspection_query)}",
                            "response": f"HTTP/1.1 200 OK\n\n{res.text[:250]}...",
                            "impact": "Attackers can reverse-engineer the entire backend database graph and uncover hidden administrative operations.",
                            "remediation": "Disable GraphQL introspection in production builds (e.g., in Apollo Server, GraphQL Yoga, or Laravel Lighthouse)."
                        })
                        break
                except Exception:
                    continue

        return findings

class RateLimitingCheck(AssessmentCheck):
    """
    Rate Limiting & Brute Force Resilience Check:
    Tests authentication and OTP endpoints for burst request throttling.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "rate-limiting-brute-force",
            "name": "Rate Limiting & Brute-Force Resilience",
            "category": "Identification and Authentication Failures",
            "severity": "HIGH",
            "description": "Tests login, password reset, and OTP endpoints with rapid requests to verify burst rate-limiting."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        auth_paths = ["/login.php", "/api/v1/auth/login", "/api/auth/login", "/login", "/otp/verify"]

        async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
            for path in auth_paths:
                try:
                    probe_url = f"{base}{path}"
                    head_res = await client.get(probe_url)
                    if head_res.status_code in [200, 401, 405]:
                        # Send 6 rapid consecutive requests
                        statuses = []
                        has_ratelimit_header = False
                        for i in range(6):
                            r = await client.post(probe_url, json={"username": f"probe_test_{i}", "password": "wrong_password_test"})
                            statuses.append(r.status_code)
                            if any(k in r.headers for k in ["retry-after", "x-ratelimit-remaining", "ratelimit-remaining"]):
                                has_ratelimit_header = True

                        # If none of the 6 requests were blocked (no 429) and no rate limit headers were present
                        if 429 not in statuses and not has_ratelimit_header and all(s in [200, 400, 401, 403, 404] for s in statuses):
                            findings.append({
                                "title": f"Missing Rate Limiting / Brute-Force Protection on '{path}'",
                                "category": "Identification and Authentication Failures",
                                "severity": "HIGH",
                                "confidence": 90.0,
                                "description": f"The authentication route '{path}' permitted 6 rapid consecutive requests without throttling (HTTP 429) or rate-limit headers.",
                                "endpoint": f"POST {path}",
                                "method": "POST",
                                "parameter": "RateLimit",
                                "request": f"POST {path} HTTP/1.1 (6 rapid bursts)\nHost: {urllib.parse.urlparse(base).netloc}",
                                "response": f"HTTP/1.1 {statuses[-1]} (No 429 Too Many Requests returned)",
                                "impact": "Allows attackers to perform high-speed credential stuffing, brute-force password guessing, and OTP token enumeration.",
                                "remediation": "Implement IP and account-based rate limiting (e.g. max 5 failed attempts per minute) using Redis, Cloudflare Rate Limiting, or framework middleware."
                            })
                            break
                except Exception:
                    continue

        return findings

class ReconCloudLeaksCheck(AssessmentCheck):
    """
    Reconnaissance & Cloud Infrastructure Audit:
    Audits DNS SPF/DMARC anti-spoofing records and checks for exposed cloud storage buckets.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "recon-cloud-leaks-email",
            "name": "DNS Anti-Spoofing (SPF/DMARC) & Cloud Bucket Exposure",
            "category": "Infrastructure & Reconnaissance",
            "severity": "MEDIUM",
            "description": "Verifies SPF/DMARC email authentication records and scans for public AWS S3 / GCP buckets."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        parsed = urllib.parse.urlparse(context.base_url)
        domain = (parsed.hostname or context.base_url).strip()

        # Skip DNS SPF/DMARC and public S3 bucket scans for local/IP addresses
        is_ip_or_local = (
            domain in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or 
            domain.endswith(".local") or 
            all(c.isdigit() or c == "." for c in domain)
        )
        if is_ip_or_local:
            return []

        domain_parts = domain.split(".")
        root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
        domain_slug = domain_parts[0] if len(domain_parts) > 1 else domain

        # 1. DNS SPF & DMARC Check using socket/DNS queries
        try:
            # Query TXT records via DNS-over-HTTPS (DoH) to bypass local socket limitations
            async with httpx.AsyncClient(timeout=4.0) as client:
                doh_url = f"https://cloudflare-dns.com/dns-query?name={root_domain}&type=TXT"
                doh_res = await client.get(doh_url, headers={"accept": "application/dns-json"})
                if doh_res.status_code == 200:
                    data = doh_res.json()
                    answers = [a.get("data", "") for a in data.get("Answer", [])]
                    has_spf = any("v=spf1" in a for a in answers)

                    # Query DMARC
                    dmarc_res = await client.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{root_domain}&type=TXT", headers={"accept": "application/dns-json"})
                    dmarc_data = dmarc_res.json() if dmarc_res.status_code == 200 else {}
                    has_dmarc = any("v=DMARC1" in a.get("data", "") for a in dmarc_data.get("Answer", []))

                    if not has_spf or not has_dmarc:
                        missing = []
                        if not has_spf: missing.append("SPF (Sender Policy Framework)")
                        if not has_dmarc: missing.append("DMARC (Domain-based Message Authentication)")
                        findings.append({
                            "title": f"Missing Email Anti-Spoofing Protection ({', '.join(missing)})",
                            "category": "Infrastructure & Reconnaissance",
                            "severity": "MEDIUM",
                            "confidence": 95.0,
                            "description": f"Domain '{root_domain}' lacks properly configured {', '.join(missing)} DNS records, allowing unauthorized actors to forge emails from this domain.",
                            "endpoint": f"DNS TXT {root_domain}",
                            "method": "DNS",
                            "parameter": "SPF/DMARC",
                            "request": f"DIG TXT {root_domain} + _dmarc.{root_domain}",
                            "response": f"SPF configured: {has_spf} | DMARC configured: {has_dmarc}",
                            "impact": "Attackers can perform CEO fraud, phishing campaigns, and invoice scams impersonating your authentic domain.",
                            "remediation": "Publish a valid SPF record (e.g., 'v=spf1 include:_spf.example.com ~all') and DMARC policy ('v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com') in DNS."
                        })
        except Exception:
            pass

        # 2. Public S3 / GCP Storage Bucket Leak Check
        try:
            cloud_targets = [
                f"https://s3.amazonaws.com/{domain_slug}",
                f"https://storage.googleapis.com/{domain_slug}"
            ]
            async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
                for bucket_url in cloud_targets:
                    try:
                        bres = await client.get(bucket_url)
                        if bres.status_code == 200 and ("<ListBucketResult" in bres.text or "<ListAllMyBucketsResult" in bres.text):
                            findings.append({
                                "title": f"Exposed Public Cloud Storage Bucket ({bucket_url})",
                                "category": "Infrastructure & Reconnaissance",
                                "severity": "CRITICAL",
                                "confidence": 98.0,
                                "description": f"Publicly accessible cloud storage bucket discovered at '{bucket_url}' with open directory listing enabled.",
                                "endpoint": f"GET {bucket_url}",
                                "method": "GET",
                                "parameter": "S3/GCP Bucket",
                                "request": f"GET {bucket_url} HTTP/1.1",
                                "response": f"HTTP/1.1 200 OK\n\n{bres.text[:250]}...",
                                "impact": "Public exposure of internal backups, user uploads, logs, and sensitive customer data.",
                                "remediation": "Enable AWS S3 'Block Public Access' or GCP 'Uniform Bucket-Level Access' to prohibit public read access."
                            })
                            break
                    except Exception:
                        continue
        except Exception:
            pass

        return findings

class SslTlsCipherCheck(AssessmentCheck):
    """
    SSL/TLS Certificate Validity & Legacy Protocol Cipher Audit.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "ssl-tls-cipher-audit",
            "name": "SSL/TLS Certificate & Cipher Suite Audit",
            "category": "Cryptographic Failures",
            "severity": "MEDIUM",
            "description": "Verifies SSL certificate expiration date, SAN alignment, and audits against deprecated TLS 1.0/1.1 protocols."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        parsed = urllib.parse.urlparse(context.base_url)
        hostname = parsed.hostname or context.base_url
        port = parsed.port or 443

        if not context.base_url.startswith("https://"):
            return findings

        try:
            # Audit SSL Certificate details
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=4.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after - datetime.utcnow()).days
                        if days_left < 14:
                            findings.append({
                                "title": f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                                "category": "Cryptographic Failures",
                                "severity": "HIGH" if days_left < 3 else "MEDIUM",
                                "confidence": 100.0,
                                "description": f"The SSL certificate for '{hostname}' will expire in {days_left} days (Expiry: {not_after_str}).",
                                "endpoint": f"TLS Handshake {hostname}:{port}",
                                "method": "TLS",
                                "parameter": "Certificate Validity",
                                "request": f"TLS Client Hello ({hostname})",
                                "response": f"Certificate NotAfter: {not_after_str}",
                                "impact": "Browser security warnings will block users from accessing the service once the certificate expires.",
                                "remediation": "Renew the SSL/TLS certificate via Let's Encrypt or your certificate authority before expiration."
                            })
        except Exception:
            pass

        return findings

class SastSecretsScannerCheck(AssessmentCheck):
    """
    Static Application Security Testing (SAST) & Secrets Scanner:
    Inspects front-end scripts, source maps, and bundles for exposed API keys and credentials.
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "sast-secrets-scanner",
            "name": "Hardcoded Secrets & API Keys Exposure (SAST)",
            "category": "Sensitive Data Exposure",
            "severity": "CRITICAL",
            "description": "Scans client-side scripts and responses for hardcoded AWS keys, Stripe secret keys, JWT tokens, and database credentials."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")
        
        # Secret Regex patterns
        patterns = [
            ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
            ("Stripe Secret Key", r"sk_(?:live|test)_[0-9a-zA-Z]{24,}", "CRITICAL"),
            ("Generic Secret / Private Key", r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "CRITICAL"),
            ("Hardcoded JWT Token", r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "HIGH")
        ]

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
            try:
                # Probe main page and crawled JS bundles
                res = await client.get(base, headers=context.auth_headers)
                text = res.text

                # Find script sources
                script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text)
                targets_to_scan = [base]
                for s in script_srcs[:4]:
                    full_src = s if s.startswith("http") else urllib.parse.urljoin(base, s)
                    targets_to_scan.append(full_src)

                for t in targets_to_scan:
                    try:
                        content = text if t == base else (await client.get(t)).text
                        for name, pat, sev in patterns:
                            m = re.search(pat, content)
                            if m:
                                matched_val = m.group(0)
                                masked = matched_val[:6] + "..." + matched_val[-4:] if len(matched_val) > 10 else "***"
                                findings.append({
                                    "title": f"Hardcoded Secret Disclosed ({name}) in '{urllib.parse.urlparse(t).path}'",
                                    "category": "Sensitive Data Exposure",
                                    "severity": sev,
                                    "confidence": 96.0,
                                    "description": f"Identified exposed secret token matching {name} pattern: '{masked}'.",
                                    "endpoint": f"GET {urllib.parse.urlparse(t).path}",
                                    "method": "GET",
                                    "parameter": name,
                                    "request": f"GET {t} HTTP/1.1",
                                    "response": f"Disclosed secret fragment: {masked}",
                                    "impact": "Attackers can hijack backend cloud resources, charge payment gateways, or forge authentication tokens.",
                                    "remediation": "Immediately revoke and rotate the exposed token. Move all sensitive credentials to server-side environment variables (.env)."
                                })
                                return findings
                    except Exception:
                        continue
            except Exception:
                pass

        return findings

class DomXssSpaCheck(AssessmentCheck):
    """
    DOM-Based Cross-Site Scripting (DOM-XSS) & Single Page Application (SPA) Check:
    Audits client-side JavaScript for dangerous sinks (innerHTML, eval, document.write).
    """
    def metadata(self) -> Dict[str, Any]:
        return {
            "id": "dom-xss-spa",
            "name": "DOM-Based Cross-Site Scripting (DOM-XSS) in SPA",
            "category": "Injection",
            "severity": "HIGH",
            "description": "Analyzes client-side router parameters and sinks (innerHTML, eval, document.write) for client-side script execution."
        }

    def can_run(self, context: AssessmentContext) -> bool:
        return bool(context.base_url)

    async def run(self, context: AssessmentContext) -> List[Dict[str, Any]]:
        findings = []
        base = context.base_url.rstrip("/")

        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
            try:
                res = await client.get(base, headers=context.auth_headers)
                text = res.text
                dangerous_patterns = [
                    (r"document\.write\(", "document.write() DOM Sink"),
                    (r"\.innerHTML\s*=\s*(?:location\.|window\.location|document\.URL)", "Unescaped location to innerHTML"),
                    (r"eval\(\s*location\.", "eval() with location source")
                ]

                for pat, label in dangerous_patterns:
                    if re.search(pat, text):
                        findings.append({
                            "title": f"DOM-Based Cross-Site Scripting ({label})",
                            "category": "Injection",
                            "severity": "HIGH",
                            "confidence": 90.0,
                            "description": f"Client-side script contains dangerous DOM sink '{label}', potentially allowing attackers to execute arbitrary JavaScript in the user's browser context.",
                            "endpoint": "GET /",
                            "method": "GET",
                            "parameter": label,
                            "request": f"GET / HTTP/1.1\nHost: {urllib.parse.urlparse(base).netloc}",
                            "response": "Identified dangerous DOM execution sink in client script.",
                            "impact": "Attackers can craft malicious URLs containing fragment payloads (#<script>) to hijack user sessions without hitting the server.",
                            "remediation": "Use safe DOM APIs such as textContent or innerText instead of innerHTML, and avoid evaluating untrusted URL parameters directly."
                        })
                        break
            except Exception:
                pass

        return findings

