from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from app.models import CmsComponent, CmsVulnFinding, RequestRecord, ScriptRecord


@dataclass(slots=True)
class _CveRecord:
    fixed_in: str
    severity: str
    cve: str
    description: str


def _parse_ver(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for part in re.split(r"[.\-]", version.strip().lstrip("vV")):
        if part.isdigit():
            parts.append(int(part))
        else:
            break
    return tuple(parts) if parts else (0,)


def _ver_lt(detected: str, fixed_in: str) -> bool:
    a = _parse_ver(detected)
    b = _parse_ver(fixed_in)
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


_WORDPRESS_PLUGIN_CVES: dict[str, tuple[str, list[_CveRecord]]] = {
    "contact-form-7": (
        "Contact Form 7",
        [
            _CveRecord("5.3.2", "high", "CVE-2020-35489", "Unrestricted file upload can lead to remote code execution."),
        ],
    ),
    "elementor": (
        "Elementor",
        [
            _CveRecord("3.11.7", "high", "CVE-2023-0329", "Privilege escalation vulnerability in Elementor Pro workflows."),
            _CveRecord("3.18.2", "high", "CVE-2023-48777", "Stored XSS vulnerability in widget rendering paths."),
        ],
    ),
    "woocommerce": (
        "WooCommerce",
        [
            _CveRecord("8.8.3", "high", "CVE-2024-27956", "SQL injection in analytics query building on older versions."),
        ],
    ),
    "revslider": (
        "Slider Revolution",
        [
            _CveRecord("6.7.0", "high", "CVE-2023-6528", "Sensitive information disclosure via AJAX actions."),
        ],
    ),
    "wp-file-manager": (
        "WP File Manager",
        [
            _CveRecord("7.2.1", "critical", "CVE-2020-25213", "Unauthenticated RCE via vulnerable connector endpoint."),
        ],
    ),
    "all-in-one-seo-pack": (
        "All in One SEO",
        [
            _CveRecord("4.1.5.3", "high", "CVE-2021-24307", "Authenticated SQL injection in plugin settings handlers."),
        ],
    ),
    "wordfence": (
        "Wordfence",
        [
            _CveRecord("7.11.5", "medium", "CVE-2024-8543", "Reflected XSS in diagnostic endpoints on older builds."),
        ],
    ),
}

_WORDPRESS_CORE_CVES: list[_CveRecord] = [
    _CveRecord("6.5.5", "high", "CVE-2024-4439", "Core object injection and hardening fixes are missing."),
    _CveRecord("6.4.4", "high", "CVE-2024-31210", "Core XSS hardening updates missing in script module handling."),
    _CveRecord("6.3.3", "high", "CVE-2023-39999", "Core security patchset from 6.3.3 not present."),
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _extract_version_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key in ("ver", "version", "v"):
        vals = query.get(key)
        if not vals:
            continue
        candidate = vals[0].strip()
        if re.match(r"^v?\d+(?:\.\d+){1,4}$", candidate, re.I):
            return candidate.lstrip("vV")

    # Common fallback in path segments, e.g. /plugin/1.2.3/file.js
    path_match = re.search(r"/(\d+(?:\.\d+){1,4})(?:/|$)", parsed.path)
    if path_match:
        return path_match.group(1)
    return None


def _extract_wp_plugin_slug(url: str) -> str | None:
    parsed = urlparse(url)
    match = re.search(r"/wp-content/plugins/([a-z0-9\-_.]+)/", parsed.path, re.I)
    if not match:
        return None
    return match.group(1).lower()


def _extract_wp_core_version(url: str) -> str | None:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if "/wp-includes/" not in path and "/wp-admin/" not in path:
        return None
    return _extract_version_from_url(url)


def _humanize_slug(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ").title()


def analyze_cms_vulnerabilities(
    requests: list[RequestRecord],
    scripts: list[ScriptRecord],
    response_headers: dict[str, str] | None = None,
) -> tuple[list[CmsComponent], list[CmsVulnFinding]]:
    components: list[CmsComponent] = []
    vulns: list[CmsVulnFinding] = []

    urls: list[str] = [r.url for r in requests if r.url]
    urls.extend(s.source for s in scripts if s.source and not s.inline)

    is_wordpress = any("/wp-content/" in (urlparse(url).path.lower()) for url in urls)

    plugin_sources: dict[str, list[tuple[str, str | None]]] = {}
    core_versions: list[str] = []

    for url in urls:
        slug = _extract_wp_plugin_slug(url)
        if slug:
            plugin_sources.setdefault(slug, []).append((url, _extract_version_from_url(url)))

        core_version = _extract_wp_core_version(url)
        if core_version:
            core_versions.append(core_version)

    header_version: str | None = None
    if response_headers:
        header_generator = response_headers.get("x-generator") or response_headers.get("X-Generator")
        if header_generator:
            match = re.search(r"wordpress\s*/?\s*(\d+(?:\.\d+){1,4})", header_generator, re.I)
            if match:
                header_version = match.group(1)
                core_versions.append(header_version)
                is_wordpress = True

    if is_wordpress:
        core_version = Counter(core_versions).most_common(1)[0][0] if core_versions else None
        components.append(
            CmsComponent(
                cms="wordpress",
                component_type="core",
                component_name="WordPress Core",
                slug="wordpress-core",
                version=core_version,
                source="header" if header_version else "asset",
                confidence="high" if core_version else "medium",
            )
        )

        seen_components: set[tuple[str, str | None]] = set()
        for slug, entries in plugin_sources.items():
            versions = [version for _, version in entries if version]
            plugin_version = Counter(versions).most_common(1)[0][0] if versions else None
            key = (slug, plugin_version)
            if key in seen_components:
                continue
            seen_components.add(key)
            display_name = _WORDPRESS_PLUGIN_CVES.get(slug, (_humanize_slug(slug), []))[0]
            components.append(
                CmsComponent(
                    cms="wordpress",
                    component_type="plugin",
                    component_name=display_name,
                    slug=slug,
                    version=plugin_version,
                    source=entries[0][0],
                    confidence="high" if plugin_version else "medium",
                )
            )

        seen_vulns: set[tuple[str, str, str]] = set()
        if core_version:
            for cve in _WORDPRESS_CORE_CVES:
                if _ver_lt(core_version, cve.fixed_in):
                    dedup = ("wordpress-core", core_version, cve.cve)
                    if dedup in seen_vulns:
                        continue
                    seen_vulns.add(dedup)
                    vulns.append(
                        CmsVulnFinding(
                            cms="wordpress",
                            component_type="core",
                            component_name="WordPress Core",
                            slug="wordpress-core",
                            version=core_version,
                            cve=cve.cve,
                            severity=cve.severity,
                            description=cve.description,
                            fixed_in=cve.fixed_in,
                            source="header" if header_version else "asset",
                        )
                    )

        for comp in components:
            if comp.component_type != "plugin" or not comp.version:
                continue
            db_entry = _WORDPRESS_PLUGIN_CVES.get(comp.slug)
            if not db_entry:
                continue
            _, cves = db_entry
            for cve in cves:
                if _ver_lt(comp.version, cve.fixed_in):
                    dedup = (comp.slug, comp.version, cve.cve)
                    if dedup in seen_vulns:
                        continue
                    seen_vulns.add(dedup)
                    vulns.append(
                        CmsVulnFinding(
                            cms="wordpress",
                            component_type="plugin",
                            component_name=comp.component_name,
                            slug=comp.slug,
                            version=comp.version,
                            cve=cve.cve,
                            severity=cve.severity,
                            description=cve.description,
                            fixed_in=cve.fixed_in,
                            source=comp.source,
                        )
                    )

    components.sort(key=lambda c: (c.cms, c.component_type, c.component_name.lower()))
    vulns.sort(key=lambda v: (_SEV_ORDER.get(v.severity, 9), v.component_type, v.component_name.lower()))
    return components, vulns
