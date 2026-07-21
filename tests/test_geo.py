from app.analysis.geo import GeoResolver, GeoRecord


def test_geo_resolver_caches_results() -> None:
    resolver = GeoResolver()
    record1 = resolver._cache.get("example.com")
    assert record1 is None

    # Populate cache manually
    resolver._cache["example.com"] = GeoRecord(ip_address="93.184.216.34", country="United States")

    record2 = resolver._cache.get("example.com")
    assert record2 is not None
    assert record2.ip_address == "93.184.216.34"
    assert record2.country == "United States"
