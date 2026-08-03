from app.analysis.cookies import analyze_cookies, classify_cookie_purpose


def test_classify_cookie_purpose_known_cookies() -> None:
    assert "Analytics" in classify_cookie_purpose("_ga")
    assert "Analytics" in classify_cookie_purpose("_gid")
    assert "Advertising" in classify_cookie_purpose("_fbp")
    assert "Session" in classify_cookie_purpose("sessionid")


def test_analyze_cookies_first_party_detection() -> None:
    raw = [
        {"name": "_ga", "value": "abc", "domain": ".example.com", "path": "/", "expires": None, "secure": True, "httpOnly": False},
        {"name": "tracker", "value": "xyz", "domain": ".thirdparty.com", "path": "/", "expires": 1735689600, "secure": True, "httpOnly": True},
    ]
    analyzed = analyze_cookies(raw, "example.com")
    assert len(analyzed) == 2
    assert analyzed[0].first_party is True
    assert analyzed[1].first_party is False
    assert analyzed[1].lifespan != "Session"
