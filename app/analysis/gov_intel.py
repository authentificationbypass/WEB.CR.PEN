"""Government and state-entity connection detection.

Checks domain names and ISP/org strings returned by ip-api for indicators
of government, intelligence, law-enforcement or military infrastructure.
"""
from __future__ import annotations

# Government TLD suffixes
# A domain that ends with any of these belongs to a government / state entity.
GOV_TLDS: tuple[str, ...] = (
    # Generic
    ".gov", ".mil",
    # United Kingdom
    ".gov.uk", ".mod.uk", ".police.uk", ".nhs.uk",
    # France
    ".gouv.fr",
    # Germany
    ".bund.de", ".bundeswehr.de",
    # Austria
    ".gv.at",
    # Switzerland
    ".admin.ch",
    # Canada
    ".gc.ca", ".canada.ca",
    # Australia
    ".gov.au",
    # New Zealand
    ".govt.nz",
    # Japan
    ".go.jp",
    # China
    ".gov.cn",
    # Russia
    ".gov.ru",
    # Brazil
    ".gov.br",
    # Spain
    ".gob.es",
    # Mexico
    ".gob.mx",
    # India
    ".gov.in",
    # EU institutions
    ".europa.eu",
)

# Known government / intelligence / law-enforcement domains
GOV_DOMAINS: frozenset[str] = frozenset({
    # US intelligence & law enforcement
    "nsa.gov", "cia.gov", "fbi.gov", "dhs.gov", "dod.gov", "dia.mil",
    "nro.gov", "dni.gov", "state.gov", "whitehouse.gov",
    # UK intelligence
    "gchq.gov.uk", "mi5.gov.uk", "sis.gov.uk",
    # Germany
    "bnd.bund.de", "verfassungsschutz.de", "bka.de", "bfv.bund.de",
    # International law enforcement
    "interpol.int", "europol.europa.eu", "frontex.europa.eu",
    # Five Eyes
    "cse-cst.gc.ca", "asio.gov.au", "asis.gov.au", "gcsb.govt.nz", "nzsis.govt.nz",
})

# Org / ISP keywords indicating government affiliation
# Matched case-insensitively against the "org" field from ip-api.
GOV_ORG_KEYWORDS: tuple[str, ...] = (
    "government", "ministry", "ministère", "ministerium", "ministerio",
    "department of", "bundesministerium", "bundesamt", "bundesbehörde",
    "bundeskriminalamt", "bka", "bundesnachrichtendienst", "bnd",
    "verfassungsschutz", "bundespolizei", "polizei", "police",
    "homeland security", "department of defense", "department of justice",
    "intelligence", "national security", "geheimdienst",
    "nsa", "cia", "fbi", "gchq", "mi5", "mi6",
    "interpol", "europol", "frontex",
    "military", "bundeswehr", "armed forces",
    "state department", "auswärtiges amt",
    "justizministerium", "innenministerium",
)


def classify_gov_connection(domain: str, org: str | None) -> str | None:
    """Return a short reason string if this domain/org is government-affiliated, else None."""
    domain_lower = domain.lower()

    # 1. Exact known-domain match
    if domain_lower in GOV_DOMAINS:
        return "Known government / intelligence domain"

    # 2. Government TLD suffix
    for tld in GOV_TLDS:
        if domain_lower.endswith(tld):
            return f"Government TLD ({tld})"

    # 3. Org / ISP keyword match
    if org:
        org_lower = org.lower()
        for keyword in GOV_ORG_KEYWORDS:
            if keyword in org_lower:
                return f"Government-affiliated operator: {org}"

    return None
