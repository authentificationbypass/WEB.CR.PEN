"""JavaScript Library Vulnerability Scanner.

Detects outdated JavaScript libraries with known CVEs by analysing:
  1. External script URLs  (pattern-matched for library name + version in path)
  2. Inline script content (regex-matched for version declaration strings)

No network requests are made — all analysis is performed on already-collected
ScriptRecord objects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import ScriptRecord


@dataclass(slots=True)
class JsVulnFinding:
    library: str       # "jQuery"
    version: str       # detected version string, e.g. "3.2.1"
    cve: str           # "CVE-2020-11022"  (or "GHSA-…" / advisory ID)
    severity: str      # "critical" | "high" | "medium" | "low"
    description: str   # human-readable summary
    fix_version: str   # first safe version
    source: str        # script URL / "inline"


# Version comparison (no external deps)
def _parse_ver(s: str) -> tuple[int, ...]:
    """'3.2.1-beta' → (3, 2, 1)"""
    parts: list[int] = []
    for part in re.split(r"[.\-]", s.strip().lstrip("v")):
        if part.isdigit():
            parts.append(int(part))
        else:
            break
    return tuple(parts) if parts else (0,)


def _ver_lt(detected: str, threshold: str) -> bool:
    """Return True if detected version is older than threshold."""
    a = _parse_ver(detected)
    b = _parse_ver(threshold)
    # Pad shorter tuple
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


# Library database
# Each entry:
#   "url_patterns":     list[re.Pattern] — captures version from script URL
#   "content_patterns": list[re.Pattern] — captures version from inline content
#   "display_name":     str
#   "vulns":            list[tuple[fix_version, severity, cve_id, description]]

_LIB_DB: dict[str, dict] = {

    # jQuery
    "jquery": {
        "display_name": "jQuery",
        "url_patterns": [
            re.compile(r"jquery[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"/jquery/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'jQuery\s+v(\d+\.\d+\.?\d*)', re.I),
            re.compile(r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"jquery":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r"jQuery JavaScript Library v(\d+\.\d+\.?\d*)", re.I),
        ],
        "vulns": [
            ("3.5.0", "high",   "CVE-2020-11022", "XSS via HTML parsing in jQuery.htmlPrefilter()"),
            ("3.5.0", "high",   "CVE-2020-11023", "XSS via self-closing HTML tags in jQuery.htmlPrefilter()"),
            ("3.4.0", "medium", "CVE-2019-11358", "Prototype pollution via $.extend(true, …)"),
            ("3.0.0", "medium", "CVE-2015-9251",  "XSS via jQuery.ajax() cross-domain requests"),
            ("1.12.0","medium", "CVE-2012-6708",  "XSS via location.hash"),
        ],
    },

    # jQuery UI
    "jquery-ui": {
        "display_name": "jQuery UI",
        "url_patterns": [
            re.compile(r"jquery[.\-_]ui[.\-_]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"jquery-ui/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'jQuery UI - v(\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"jquery-ui":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("1.13.2", "medium", "CVE-2022-31160", "XSS in the checkboxradio widget"),
            ("1.13.0", "medium", "CVE-2021-41184", "XSS in the datepicker widget via the altField option"),
            ("1.12.0", "medium", "CVE-2016-7103",  "XSS in dialog closeText option"),
        ],
    },

    # Bootstrap
    "bootstrap": {
        "display_name": "Bootstrap",
        "url_patterns": [
            re.compile(r"bootstrap[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"bootstrap/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'Bootstrap v(\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"bootstrap":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("5.3.3", "medium", "CVE-2024-6484",  "XSS in the Bootstrap tooltip/popover data-bs-title attribute"),
            ("4.3.1", "medium", "CVE-2019-8331",  "XSS in tooltip/popover data-template option"),
            ("4.0.0", "medium", "CVE-2018-14042", "XSS via data-container attribute in popovers"),
            ("3.4.0", "medium", "CVE-2018-14040", "XSS via the href attribute"),
            ("3.4.1", "medium", "CVE-2019-8331",  "XSS in tooltip/popover data-template (3.x branch)"),
        ],
    },

    # AngularJS (1.x legacy)
    "angularjs": {
        "display_name": "AngularJS",
        "url_patterns": [
            re.compile(r"angular(?:js)?[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"angular\.js/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'AngularJS v(\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"full":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r'angular\.version\s*=\s*\{[^}]*"full":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("1.9.0", "high",   "CVE-2022-25869", "XSS via SVG animate attributes — all 1.x versions"),
            ("1.8.0", "medium", "CVE-2020-7676",  "XSS in ng-style directive on IE"),
            ("1.7.9", "medium", "CVE-2019-14863", "XSS via ng-attr-* directives"),
            ("1.6.9", "medium", "CVE-2018-1000873","ReDoS in $http URL parameter handling"),
        ],
    },

    # Lodash
    "lodash": {
        "display_name": "Lodash",
        "url_patterns": [
            re.compile(r"lodash(?:\.min)?[.\-_]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"lodash/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'lodash v(\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"lodash":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r'Lodash \(Custom Build\) .*?lodash v(\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("4.17.21", "high",   "CVE-2021-23337", "Command injection via _.template"),
            ("4.17.21", "medium", "CVE-2020-28500", "ReDoS via _.trim and other string methods"),
            ("4.17.12", "high",   "CVE-2019-10744", "Prototype pollution via defaultsDeep / merge"),
            ("4.17.5",  "medium", "CVE-2018-16487", "Prototype pollution via _.merge on object with __proto__"),
            ("4.17.4",  "medium", "CVE-2018-3721",  "Prototype pollution via _.merge / _.extend"),
        ],
    },

    # Underscore.js
    "underscore": {
        "display_name": "Underscore.js",
        "url_patterns": [
            re.compile(r"underscore[.\-_]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"underscore/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'Underscore\.js (\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"underscore":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("1.13.0", "medium", "CVE-2021-23358", "Arbitrary code execution via template function"),
        ],
    },

    # Handlebars
    "handlebars": {
        "display_name": "Handlebars",
        "url_patterns": [
            re.compile(r"handlebars[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"handlebars/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'Handlebars\.VERSION\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"handlebars":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("4.7.7", "high",   "CVE-2021-23369", "Remote code execution via prototype pollution"),
            ("4.7.7", "high",   "CVE-2021-23383", "Prototype pollution in compileInput"),
            ("4.7.6", "high",   "CVE-2019-19919", "Prototype pollution and code execution in partial lookups"),
            ("4.7.6", "high",   "CVE-2019-20920", "Prototype pollution via lookupProperty"),
            ("4.5.3", "high",   "CVE-2019-20922", "ReDoS via specially crafted template"),
        ],
    },

    # Moment.js
    "moment": {
        "display_name": "Moment.js",
        "url_patterns": [
            re.compile(r"moment(?:\.min)?[.\-_]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"moment/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'moment\.version\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"moment":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r'//! moment\.js\s+version\s*:\s*(\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("2.29.4", "high",   "CVE-2022-31129", "ReDoS in rfc2822 and ISO 8601 parsing"),
            ("2.29.2", "medium", "CVE-2022-24785", "Path traversal in locale parsing"),
        ],
    },

    # Vue.js
    "vue": {
        "display_name": "Vue.js",
        "url_patterns": [
            re.compile(r"vue(?:\.min)?[.\-_]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"vue/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"vue":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r'Vue\.js v(\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("2.6.14", "medium", "CVE-2021-23382", "ReDoS in SSR rendering — only affects server-side use"),
        ],
    },

    # Axios
    "axios": {
        "display_name": "Axios",
        "url_patterns": [
            re.compile(r"axios[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"axios/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'"axios":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r"axios/(\d+\.\d+\.?\d*)/axios", re.I),
        ],
        "vulns": [
            ("1.6.0",  "medium", "CVE-2023-45857", "CSRF token leakage via custom headers in cross-site redirects"),
            ("0.21.3", "medium", "CVE-2021-3749",  "ReDoS via specially crafted URL path"),
            ("0.21.1", "high",   "CVE-2020-28168", "SSRF via server-side requests with arbitrary URL"),
        ],
    },

    # Socket.IO
    "socket.io": {
        "display_name": "Socket.IO",
        "url_patterns": [
            re.compile(r"socket\.io[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
            re.compile(r"socket\.io/(\d+\.\d+\.?\d*)/", re.I),
        ],
        "content_patterns": [
            re.compile(r'"socket\.io":\s*"(\d+\.\d+\.?\d*)"', re.I),
            re.compile(r'Socket\.IO v(\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("4.6.2", "high",   "CVE-2022-2421",  "Improper input validation allows ReDoS"),
            ("2.5.0", "medium", "CVE-2020-28481", "Cross-tenant namespace access with wildcard middleware"),
        ],
    },

    # Prototype.js (legacy)
    "prototype": {
        "display_name": "Prototype.js",
        "url_patterns": [
            re.compile(r"prototype[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'Prototype JavaScript framework, version (\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("99.0.0", "medium", "CVE-2008-7220",
             "Prototype.js is unmaintained since 2015. Multiple unpatched XSS/prototype-pollution issues."),
        ],
    },

    # MooTools (legacy)
    "mootools": {
        "display_name": "MooTools",
        "url_patterns": [
            re.compile(r"mootools[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'MooTools: the javascript framework\s*\n.*?version:\s*\'(\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("99.0.0", "low", "ADVISORY-MOOTOOLS-EOL",
             "MooTools is end-of-life (last release 2016). No security patches will be issued."),
        ],
    },

    # Highlight.js
    "highlight.js": {
        "display_name": "Highlight.js",
        "url_patterns": [
            re.compile(r"highlight(?:\.min)?[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'Highlight\.js (\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("10.7.2", "high", "CVE-2021-23358",
             "Prototype pollution via specially crafted CSS payload (affects server-side rendering)"),
        ],
    },

    # Marked (Markdown parser)
    "marked": {
        "display_name": "Marked",
        "url_patterns": [
            re.compile(r"marked[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'"marked":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("4.0.10", "high",   "CVE-2022-21681", "ReDoS via table cell tokens"),
            ("4.0.10", "high",   "CVE-2022-21680", "ReDoS via block code tokens"),
            ("2.1.3",  "medium", "CVE-2021-21306", "XSS via data: URI in href attribute"),
        ],
    },

    # DOMPurify
    "dompurify": {
        "display_name": "DOMPurify",
        "url_patterns": [
            re.compile(r"dompurify[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'DOMPurify[,\s]+version[:\s]+(\d+\.\d+\.?\d*)', re.I),
            re.compile(r'"dompurify":\s*"(\d+\.\d+\.?\d*)"', re.I),
        ],
        "vulns": [
            ("3.1.6", "high",   "CVE-2024-47875", "mXSS bypass via DOM clobbering of prototype attributes"),
            ("2.4.0", "high",   "CVE-2024-48910", "mXSS bypass in certain SVG+HTML combinations"),
            ("2.3.5", "medium", "CVE-2022-38900", "Bypass via mutation XSS in nesting context"),
        ],
    },

    # CKEditor
    "ckeditor": {
        "display_name": "CKEditor",
        "url_patterns": [
            re.compile(r"ckeditor[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'CKEditor Version (\d+\.\d+\.?\d*)', re.I),
            re.compile(r'var CKEDITOR_VERSION\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("4.24.0", "medium", "CVE-2024-43407", "XSS via code block plugin in CKEditor 4"),
            ("4.22.0", "medium", "CVE-2023-28439", "XSS via crafted file name in media embed plugin"),
            ("4.17.2", "high",   "CVE-2021-41164", "XSS via crafted content in inline styles"),
        ],
    },

    # Backbone.js
    "backbone": {
        "display_name": "Backbone.js",
        "url_patterns": [
            re.compile(r"backbone[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'Backbone\.VERSION\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("99.0.0", "low", "ADVISORY-BACKBONE-EOL",
             "Backbone.js has had no releases since 2019. Security patches are not being issued for known issues."),
        ],
    },

    # Knockout.js
    "knockout": {
        "display_name": "Knockout.js",
        "url_patterns": [
            re.compile(r"knockout[.\-_/]v?(\d+\.\d+\.?\d*)", re.I),
        ],
        "content_patterns": [
            re.compile(r'ko\.version\s*=\s*["\'](\d+\.\d+\.?\d*)', re.I),
            re.compile(r'Knockout JavaScript library v(\d+\.\d+\.?\d*)', re.I),
        ],
        "vulns": [
            ("3.5.1", "medium", "CVE-2019-14862",
             "XSS via the 'css' binding — unsanitised class names injected into DOM"),
        ],
    },
}


# Core scanner
def scan_js_vulnerabilities(scripts: list[ScriptRecord]) -> list[JsVulnFinding]:
    """
    Scan a list of ScriptRecord objects for outdated JavaScript libraries.

    Returns one JsVulnFinding per (library, version, CVE) combination found.
    Deduplicates: the same CVE detected from multiple scripts is reported once.
    """
    findings: list[JsVulnFinding] = []
    seen: set[tuple[str, str, str]] = set()  # (lib_key, version, cve)

    def _record(lib_key: str, version: str, source: str) -> None:
        lib = _LIB_DB[lib_key]
        for fix_version, severity, cve, description in lib["vulns"]:
            if _ver_lt(version, fix_version):
                dedup = (lib_key, version, cve)
                if dedup not in seen:
                    seen.add(dedup)
                    findings.append(JsVulnFinding(
                        library=lib["display_name"],
                        version=version,
                        cve=cve,
                        severity=severity,
                        description=description,
                        fix_version=fix_version,
                        source=source,
                    ))

    for script in scripts:
        source = script.source
        if not source:
            continue

        if not script.inline:
            # External script: analyse URL
            for lib_key, lib in _LIB_DB.items():
                for pat in lib["url_patterns"]:
                    m = pat.search(source)
                    if m:
                        _record(lib_key, m.group(1), source)
                        break
        else:
            # Inline script: analyse text content
            for lib_key, lib in _LIB_DB.items():
                for pat in lib["content_patterns"]:
                    m = pat.search(source)
                    if m:
                        _record(lib_key, m.group(1), source[:120] + "…" if len(source) > 120 else source)
                        break

    # Sort: critical first, then high, then alphabetically by library
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (_sev_order.get(f.severity, 9), f.library))
    return findings
