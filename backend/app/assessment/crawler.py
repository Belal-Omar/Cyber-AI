import re
import urllib.parse
from html.parser import HTMLParser
from typing import List, Dict, Set, Any, Optional
import httpx

from app.assessment.interfaces import DiscoveredEndpoint

class LinkAndFormParser(HTMLParser):
    def __init__(self, current_url: str):
        super().__init__()
        self.current_url = current_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        # 1. Extract Links (a, link, script, iframe)
        target_attr = "href" if tag in ("a", "link") else ("src" if tag in ("script", "iframe") else None)
        if target_attr and target_attr in attr_dict:
            href = attr_dict[target_attr].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urllib.parse.urljoin(self.current_url, href)
                self.links.add(full_url)

        # 2. Extract Forms (action, method)
        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            form_url = urllib.parse.urljoin(self.current_url, action) if action else self.current_url
            self._current_form = {
                "action": form_url,
                "method": method,
                "inputs": []
            }

        # 3. Extract Form Inputs (input, textarea, select)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                input_type = attr_dict.get("type", "text")
                value = attr_dict.get("value", "")
                self._current_form["inputs"].append({
                    "name": name,
                    "type": input_type,
                    "default_value": value
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def extract_js_endpoints(self, html_content: str):
        """Extract JavaScript API endpoints and AJAX paths (e.g., fetch, axios, location.href)."""
        patterns = [
            r'''(?:fetch|axios(?:\.get|\.post)?)\s*\(\s*['"]([^'"]+)['"]''',
            r'''(?:location\.href|\.location)\s*=\s*['"]([^'"]+)['"]''',
            r'''(?:url|endpoint|action)\s*:\s*['"]([^'"]+)['"]''',
            r'''\$\.ajax\s*\(\s*\{\s*url\s*:\s*['"]([^'"]+)['"]'''
        ]
        for p in patterns:
            for match in re.findall(p, html_content, re.IGNORECASE):
                clean = match.strip()
                if clean and not clean.startswith(("http://", "https://", "//", "javascript:", "#")):
                    full = urllib.parse.urljoin(self.current_url, clean)
                    self.links.add(full)

class WebCrawler:
    """
    Intelligent Web Crawler / Spider for discovery of internal web application routes,
    URL parameters, and HTML forms with authenticated session support.
    """
    def __init__(
        self,
        base_url: str,
        allowed_hosts: Optional[List[str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        max_depth: int = 2,
        max_pages: int = 40,
        excluded_paths: Optional[str] = None
    ):
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        self.base_url = base_url
        parsed = urllib.parse.urlparse(base_url)
        self.base_netloc = parsed.netloc.lower()
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or [self.base_netloc])]
        if self.base_netloc not in self.allowed_hosts:
            self.allowed_hosts.append(self.base_netloc)

        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.max_depth = max(1, min(max_depth, 4))
        self.max_pages = max(5, min(max_pages, 120))
        self.excluded_paths = [p.strip().lower().rstrip("*") for p in (excluded_paths or "").split(",") if p.strip()]

        # Standard security reconnaissance paths to verify if exposed
        self.known_interesting_paths = [
            "/", "/robots.txt", "/sitemap.xml", "/.env", "/openapi.json", "/.well-known/security.txt"
        ]

    def _is_allowed(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme.startswith("http"):
                return False
            # Check host against allowed hosts
            netloc = parsed.netloc.lower()
            if not (netloc in self.allowed_hosts or netloc.split(":")[0] in self.allowed_hosts):
                return False

            # Check excluded paths
            path = parsed.path.lower()
            for ex in self.excluded_paths:
                if ex and (ex in path or path.startswith(ex)):
                    return False

            return True
        except Exception:
            return False

    async def crawl(self) -> List[DiscoveredEndpoint]:
        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(self.base_url, 0)]
        endpoints_map: Dict[str, DiscoveredEndpoint] = {}

        # Add initial known paths to probe (up to 45 paths for deep crawls)
        seed_limit = 45 if self.max_depth >= 2 else 15
        for p in self.known_interesting_paths[:seed_limit]:
            candidate = urllib.parse.urljoin(self.base_url, p)
            queue.append((candidate, 1))

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
            "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            **self.auth_headers
        }

        async with httpx.AsyncClient(
            headers=headers,
            cookies=self.cookies,
            timeout=7.0,
            verify=False,
            follow_redirects=True
        ) as client:
            while queue and len(visited) < self.max_pages:
                current_url, depth = queue.pop(0)
                # Normalize URL (remove fragment)
                parsed = urllib.parse.urlparse(current_url)
                normalized_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""
                ))

                if normalized_url in visited or not self._is_allowed(normalized_url):
                    continue

                visited.add(normalized_url)

                try:
                    res = await client.get(normalized_url)
                except Exception:
                    continue

                # Extract query parameters
                query_params = list(urllib.parse.parse_qs(parsed.query).keys())

                # Parse HTML content
                parser = LinkAndFormParser(normalized_url)
                content_type = res.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    try:
                        parser.feed(res.text)
                        parser.extract_js_endpoints(res.text)
                    except Exception:
                        pass

                # Only record as discovered endpoint if the route actually exists on target
                # (2xx, 3xx, or 401/403 auth barrier). 404 or server errors mean route does not exist.
                if res.status_code < 400 or res.status_code in (401, 403):
                    endpoint_record = DiscoveredEndpoint(
                        url=normalized_url,
                        path=parsed.path or "/",
                        method="GET",
                        parameters=query_params,
                        forms=parser.forms,
                        status_code=res.status_code,
                        is_authenticated=bool(self.cookies or self.auth_headers)
                    )
                    endpoints_map[normalized_url] = endpoint_record

                # Record form endpoints
                for form in parser.forms:
                    form_url = form.get("action") or normalized_url
                    form_method = form.get("method", "GET")
                    form_params = [inp["name"] for inp in form.get("inputs", []) if "name" in inp]
                    if form_url not in endpoints_map:
                        endpoints_map[form_url] = DiscoveredEndpoint(
                            url=form_url,
                            path=urllib.parse.urlparse(form_url).path or "/",
                            method=form_method,
                            parameters=form_params,
                            forms=[form],
                            status_code=res.status_code,
                            is_authenticated=bool(self.cookies or self.auth_headers)
                        )
                    else:
                        endpoints_map[form_url].forms.append(form)
                        endpoints_map[form_url].parameters = list(set(endpoints_map[form_url].parameters + form_params))

                # Queue next links if depth permits
                if depth < self.max_depth:
                    for link in parser.links:
                        link_clean = link.split("#")[0]
                        if link_clean not in visited and self._is_allowed(link_clean):
                            queue.append((link_clean, depth + 1))

        return list(endpoints_map.values())
