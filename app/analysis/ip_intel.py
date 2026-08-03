"""IP Intelligence — classifies IP addresses against known government,
military, and intelligence-agency infrastructure.

Data sources used (all public / open):
  • IANA IPv4 Special-Purpose Address Registry
  • Publicly documented DoD / US-Federal CIDR allocations (ARIN data)
  • RIPE / ARIN / APNIC ASN registry name patterns
  • Reverse-DNS hostname TLD and subdomain pattern analysis
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


# Data class
@dataclass(slots=True)
class IpIntelRecord:
    ip: str
    rdns: str | None
    asn: str | None          # e.g. "AS749"
    asname: str | None       # e.g. "DOD-NIC"
    org: str | None
    country: str | None
    is_hosting: bool
    is_proxy: bool
    gov_label: str | None    # None = no government match
    gov_confidence: str      # "confirmed" | "probable" | "possible" | "none"
    ip_type: str             # "government" | "datacenter/cdn" | "proxy/vpn" | "residential/isp" | "unknown"
    tags: list[str] = field(default_factory=list)


# Known government / military IPv4 CIDR blocks
# Source: IANA IPv4 Address Space Registry (public record)
_RAW_CIDR_BLOCKS: list[tuple[str, str, str]] = [
    # US Department of Defense — DISA-managed Class A allocations
    ("6.0.0.0/8",          "US DoD – DISA",                         "military"),
    ("7.0.0.0/8",          "US DoD – DISA",                         "military"),
    ("11.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("21.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("22.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("26.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("28.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("29.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("30.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("33.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("55.0.0.0/8",         "US DoD – DISA",                         "military"),
    ("214.0.0.0/8",        "US DoD – DISA",                         "military"),
    ("215.0.0.0/8",        "US DoD – DISA",                         "military"),
    # US Government agencies
    ("149.101.0.0/16",     "US General Services Administration",     "government"),
    ("159.142.0.0/16",     "US Dept. of Justice",                    "government"),
    ("164.49.0.0/16",      "US Dept. of the Interior",               "government"),
    ("170.114.0.0/16",     "US Dept. of Energy",                     "government"),
    ("192.104.0.0/16",     "US Dept. of Agriculture",                "government"),
    ("140.23.0.0/16",      "NASA",                                   "government"),
    ("198.32.0.0/16",      "US Government",                          "government"),
    # NATO
    ("62.233.44.0/24",     "NATO",                                   "military"),
    ("193.110.130.0/24",   "NATO Communications & Information Agency","military"),
    # EU institutions
    ("147.67.0.0/16",      "European Commission",                    "government"),
    ("158.169.0.0/16",     "European Commission",                    "government"),
    ("193.193.136.0/21",   "European Parliament",                    "government"),
    # German federal
    ("193.18.0.0/16",      "BSI – German Federal IT Security",       "government"),
    ("194.8.236.0/24",     "German Federal Network Agency (BNetzA)", "government"),
    # UK Government
    ("194.72.0.0/20",      "UK Government",                          "government"),
    # United Nations
    ("158.68.0.0/16",      "United Nations",                         "government"),
    # Swiss Federal Administration
    ("152.96.0.0/16",      "Swiss Federal Administration",           "government"),
    # Australian Government
    ("192.188.0.0/16",     "Australian Government",                  "government"),
]

_GOV_CIDR_BLOCKS: list[tuple[ipaddress.IPv4Network, str, str]] = []
for _cidr, _label, _cat in _RAW_CIDR_BLOCKS:
    try:
        _GOV_CIDR_BLOCKS.append((ipaddress.IPv4Network(_cidr, strict=False), _label, _cat))
    except ValueError:
        pass


# ASN name / org name patterns
_GOV_ASN_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # US military / DoD
    (re.compile(r"\bdisa\b|\bdefense\s*information\s*systems", re.I),
     "US DoD – DISA", "military"),
    (re.compile(r"\bdepartment\s*of\s*defense\b|\bdept\.?\s*of\s*defense\b|\bdo[d]\b", re.I),
     "US Department of Defense", "military"),
    (re.compile(r"\bu\.?s\.?\s*army\b|\bunited\s*states\s*army\b", re.I),
     "US Army", "military"),
    (re.compile(r"\bu\.?s\.?\s*navy\b|\bnaval\s*(air|sea|station|base|reserve)\b", re.I),
     "US Navy", "military"),
    (re.compile(r"\bair\s*force\b|\busaf\b", re.I),
     "US Air Force", "military"),
    (re.compile(r"\bmarine\s*corps\b|\busmc\b", re.I),
     "US Marine Corps", "military"),
    (re.compile(r"\bcoast\s*guard\b|\buscg\b", re.I),
     "US Coast Guard", "military"),
    # US Intelligence
    (re.compile(r"\bnational\s*security\s*agency\b|\bnsa\b", re.I),
     "NSA", "intelligence"),
    (re.compile(r"\bcentral\s*intelligence\s*agency\b|\bcia\b", re.I),
     "CIA", "intelligence"),
    (re.compile(r"\bfederal\s*bureau\s*of\s*investigation\b|\bfbi\b", re.I),
     "FBI", "intelligence"),
    (re.compile(r"\bhomeland\s*security\b|\bdhs\b", re.I),
     "US Dept. of Homeland Security", "government"),
    (re.compile(r"\bdrug\s*enforcement\s*(admin|agency)?\b|\bdea\b", re.I),
     "DEA", "intelligence"),
    (re.compile(r"\bsecret\s*service\b", re.I),
     "US Secret Service", "intelligence"),
    (re.compile(r"\bdefense\s*intelligence\s*agency\b|\bdia\b", re.I),
     "Defense Intelligence Agency (DIA)", "intelligence"),
    # US Government civilian
    (re.compile(r"\bdepartment\s*of\s*state\b|\bstate\s*dept\b", re.I),
     "US Dept. of State", "government"),
    (re.compile(r"\binternal\s*revenue\s*(service)?\b|\birs\b", re.I),
     "IRS", "government"),
    (re.compile(r"\bnasa\b|\bnational\s*aeronautics\b", re.I),
     "NASA", "government"),
    (re.compile(r"\bfederal\s*reserve\b", re.I),
     "US Federal Reserve", "government"),
    (re.compile(r"\bgeneral\s*services\s*administration\b|\bgsa\b", re.I),
     "US General Services Administration", "government"),
    # German government
    (re.compile(r"\bbundeskriminalamt\b|\bbka\b", re.I),
     "Bundeskriminalamt (BKA)", "intelligence"),
    (re.compile(r"\bbundesnachrichtendienst\b|\bbnd\b", re.I),
     "Bundesnachrichtendienst (BND)", "intelligence"),
    (re.compile(r"\bverfassungsschutz\b|\bbfv\b|\blkv\b", re.I),
     "Verfassungsschutz", "intelligence"),
    (re.compile(r"\bbundesministerium\b|\bbmvj\b|\bbmi\b|\bbmvg\b", re.I),
     "German Federal Ministry", "government"),
    (re.compile(r"\bbundesamt\b|\bbsi\b", re.I),
     "German Federal Authority / BSI", "government"),
    (re.compile(r"\bbundespolizei\b|\bbpol\b", re.I),
     "Bundespolizei", "government"),
    (re.compile(r"\blandeskriminalamt\b|\blka\b", re.I),
     "Landeskriminalamt (LKA)", "intelligence"),
    (re.compile(r"\bzollkriminalamt\b|\bzka\b", re.I),
     "Zollkriminalamt", "intelligence"),
    (re.compile(r"\bbundeswehr\b", re.I),
     "Bundeswehr", "military"),
    # UK government
    (re.compile(r"\bgchq\b|\bgovernment\s*communications\s*hq\b", re.I),
     "GCHQ", "intelligence"),
    (re.compile(r"\bmi5\b|\bmi6\b|\b(secret\s*intelligence\s*service)\b|\bsis\b", re.I),
     "UK Intelligence (MI5/MI6/SIS)", "intelligence"),
    (re.compile(r"\bministry\s*of\s*defence\b|\bmod\b", re.I),
     "UK Ministry of Defence", "military"),
    (re.compile(r"\bnational\s*crime\s*agency\b|\bnca\b", re.I),
     "UK National Crime Agency", "intelligence"),
    (re.compile(r"\bhome\s*office\b", re.I),
     "UK Home Office", "government"),
    # French government
    (re.compile(r"\bdirection\s*(g[eé]n[eé]rale)?\s*de\s*la\s*s[eé]curit[eé]\b|\bdgsi\b|\bdgse\b", re.I),
     "French Intelligence (DGSI/DGSE)", "intelligence"),
    (re.compile(r"\bgendarmerie\b", re.I),
     "Gendarmerie Nationale", "government"),
    (re.compile(r"\bpolice\s*nationale\b", re.I),
     "Police Nationale (FR)", "government"),
    # EU / International
    (re.compile(r"\beuropol\b", re.I),
     "Europol", "intelligence"),
    (re.compile(r"\binterpol\b", re.I),
     "Interpol", "intelligence"),
    (re.compile(r"\bnato\b|\bshape\b|\ballied\s*(command|force)", re.I),
     "NATO", "military"),
    (re.compile(r"\beuropean\s*commission\b", re.I),
     "European Commission", "government"),
    (re.compile(r"\beuropean\s*parliament\b", re.I),
     "European Parliament", "government"),
    (re.compile(r"\bunited\s*nations\b", re.I),
     "United Nations", "government"),
    # Generic fallback
    (re.compile(r"\bmilitary\b|\barmed\s*forces\b", re.I),
     "Military", "military"),
    (re.compile(r"\bintelligence\s*(agency|service|bureau)\b", re.I),
     "Intelligence Agency", "intelligence"),
]


# Reverse-DNS hostname patterns
_GOV_RDNS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\.gov(\.|\b)",          re.I), "US Government (.gov)",              "government"),
    (re.compile(r"\.mil(\.|\b)",          re.I), "US Military (.mil)",                "military"),
    (re.compile(r"\.govt\.nz",            re.I), "New Zealand Government",            "government"),
    (re.compile(r"\.gov\.au",             re.I), "Australian Government",             "government"),
    (re.compile(r"\.gov\.uk",             re.I), "UK Government",                     "government"),
    (re.compile(r"\.gov\.ca",             re.I), "Canadian Government",               "government"),
    (re.compile(r"\.gov\.in",             re.I), "Indian Government",                 "government"),
    (re.compile(r"\.gov\.br",             re.I), "Brazilian Government",              "government"),
    (re.compile(r"\.bund\.de",            re.I), "German Federal (.bund.de)",         "government"),
    (re.compile(r"\.bundeswehr\.de",      re.I), "Bundeswehr",                        "military"),
    (re.compile(r"\.bundespolizei\.de",   re.I), "Bundespolizei",                     "government"),
    (re.compile(r"\.police\.uk",          re.I), "UK Police",                         "government"),
    (re.compile(r"\.mod\.uk",             re.I), "UK Ministry of Defence",            "military"),
    (re.compile(r"\.parliament\.uk",      re.I), "UK Parliament",                     "government"),
    (re.compile(r"\.nato\.int",           re.I), "NATO",                              "military"),
    (re.compile(r"\.europa\.eu",          re.I), "EU Institutions",                   "government"),
    (re.compile(r"\.un\.org",             re.I), "United Nations",                    "government"),
    (re.compile(r"\.gouv\.fr",            re.I), "French Government (.gouv.fr)",      "government"),
    (re.compile(r"\.gv\.at",              re.I), "Austrian Government (.gv.at)",      "government"),
    (re.compile(r"\.gc\.ca",              re.I), "Canadian Government (.gc.ca)",      "government"),
    (re.compile(r"\.mil\.br",             re.I), "Brazilian Military (.mil.br)",      "military"),
    (re.compile(r"\.admin\.ch",           re.I), "Swiss Federal Administration",      "government"),
    (re.compile(r"\.gob\.es",             re.I), "Spanish Government (.gob.es)",      "government"),
    (re.compile(r"\.gov\.pl",             re.I), "Polish Government (.gov.pl)",       "government"),
    (re.compile(r"\.gov\.cn",             re.I), "Chinese Government (.gov.cn)",      "government"),
    (re.compile(r"\.gov\.ru|\.fso\.gov\.ru|\.fsb\.ru", re.I), "Russian Government / FSB", "intelligence"),
    (re.compile(r"\.police\.",            re.I), "Police",                            "government"),
]


# Public classification function
def _check_cidr(ip: str) -> tuple[str, str] | None:
    """Return (label, category) if IP is inside a known government CIDR block."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for network, label, category in _GOV_CIDR_BLOCKS:
        if addr in network:
            return label, category
    return None


def classify_ip(
    ip: str,
    org: str | None,
    asn: str | None,
    asname: str | None,
    rdns: str | None,
    is_hosting: bool,
    is_proxy: bool,
    country: str | None,
) -> IpIntelRecord:
    """
    Classify an IP against known government/military infrastructure.

    Returns an IpIntelRecord with full intelligence summary.
    Checks in order: CIDR block → reverse-DNS → ASN name → org name.
    """
    gov_label: str | None = None
    gov_confidence = "none"
    tags: list[str] = []

    # 1. CIDR match — highest confidence
    cidr_match = _check_cidr(ip)
    if cidr_match:
        gov_label, cat = cidr_match
        gov_confidence = "confirmed"
        tags += [cat, "cidr-match"]

    # 2. Reverse DNS TLD / pattern match
    if rdns and not gov_label:
        for pattern, label, category in _GOV_RDNS_PATTERNS:
            if pattern.search(rdns):
                gov_label = label
                gov_confidence = "confirmed"
                tags += [category, "rdns-match"]
                break

    # 3. ASN name check
    combined_asn = f"{asname or ''} {asn or ''}".strip()
    if combined_asn and not gov_label:
        for pattern, label, category in _GOV_ASN_PATTERNS:
            if pattern.search(combined_asn):
                gov_label = label
                gov_confidence = "probable"
                tags += [category, "asn-match"]
                break

    # 4. Org / ISP name fallback
    if org and not gov_label:
        for pattern, label, category in _GOV_ASN_PATTERNS:
            if pattern.search(org):
                gov_label = label
                gov_confidence = "possible"
                tags += [category, "org-match"]
                break

    # Determine human-readable IP type
    if gov_label:
        ip_type = "government"
    elif is_proxy:
        ip_type = "proxy/vpn"
        tags.append("proxy")
    elif is_hosting:
        ip_type = "datacenter/cdn"
        tags.append("hosting")
    else:
        ip_type = "residential/isp"
        tags.append("residential")

    return IpIntelRecord(
        ip=ip,
        rdns=rdns,
        asn=asn,
        asname=asname,
        org=org,
        country=country,
        is_hosting=is_hosting,
        is_proxy=is_proxy,
        gov_label=gov_label,
        gov_confidence=gov_confidence,
        ip_type=ip_type,
        tags=list(dict.fromkeys(tags)),  # deduplicate, preserve order
    )
