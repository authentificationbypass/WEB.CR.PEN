from app.analysis.cms_vulns import analyze_cms_vulnerabilities
from app.models import RequestRecord, ScriptRecord


def test_detects_wordpress_plugin_and_cve() -> None:
    requests = [
        RequestRecord(
            url="https://target.example/wp-content/plugins/contact-form-7/includes/js/scripts.js?ver=5.2.1",
            domain="target.example",
            method="GET",
            resource_type="script",
            protocol="https",
            page_url="https://target.example",
        )
    ]
    scripts = [
        ScriptRecord(
            source="https://target.example/wp-includes/js/wp-emoji-release.min.js?ver=6.4.3",
            script_type="text/javascript",
            inline=False,
        )
    ]

    components, vulns = analyze_cms_vulnerabilities(requests, scripts)

    assert any(c.component_type == "core" and c.cms == "wordpress" for c in components)
    assert any(c.component_type == "plugin" and c.slug == "contact-form-7" and c.version == "5.2.1" for c in components)
    assert any(v.cve == "CVE-2020-35489" for v in vulns)


def test_header_generator_detects_wordpress_core() -> None:
    requests: list[RequestRecord] = []
    scripts: list[ScriptRecord] = []

    components, vulns = analyze_cms_vulnerabilities(
        requests,
        scripts,
        {"x-generator": "WordPress 6.3.0"},
    )

    assert any(c.component_type == "core" and c.version == "6.3.0" for c in components)
    assert any(v.component_type == "core" for v in vulns)
