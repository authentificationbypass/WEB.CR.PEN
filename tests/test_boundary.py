from app.crawler.boundary import is_same_site, normalize_url, registrable_domain


def test_normalize_url_removes_fragment() -> None:
    assert normalize_url("/docs#section", "https://example.com/start") == "https://example.com/docs"


def test_same_site_uses_registrable_domain() -> None:
    assert is_same_site("https://app.example.com", "https://cdn.example.com/script.js") is True
    assert is_same_site("https://example.com", "https://example.org") is False


def test_registrable_domain_extracts_root_domain() -> None:
    assert registrable_domain("https://subdomain.example.co.uk") == "example.co.uk"
