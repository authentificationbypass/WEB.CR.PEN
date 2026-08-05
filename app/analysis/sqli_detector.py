from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


# Error-based payload set inspired by common SQLi fuzzing patterns.
SQLI_PAYLOADS: tuple[str, ...] = (
    "'123",
    "''123",
    "`123",
    '")123',
    '"))123',
    "`)123",
    "`))123",
    "'))123",
    "')123\"123",
    "[]123",
    '""123',
    "'\"123",
    "\"'123",
    "\\123",
)

# A compact subset of broad DB error signatures used for error-based detection.
SQL_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql_syntax", re.compile(r"SQL syntax.*?MySQL", re.I)),
    ("mysql_warning", re.compile(r"Warning.*?\\Wmysqli?_", re.I)),
    ("mysql_exception", re.compile(r"MySQLSyntaxErrorException|MySqlException", re.I)),
    ("mysql_sqlstate", re.compile(r"SQLSTATE\\[\\d+\\]: Syntax error or access violation", re.I)),
    ("postgres_error", re.compile(r"PostgreSQL.*?ERROR|PG::SyntaxError|Npgsql\\.", re.I)),
    ("postgres_parse", re.compile(r"ERROR:\\s?syntax error at or near", re.I)),
    ("mssql_exception", re.compile(r"SQLServer|SqlException|ODBC SQL Server Driver", re.I)),
    ("sqlite_exception", re.compile(r"SQLite\\.Exception|\\[SQLITE_ERROR\\]|sqlite3\\.OperationalError", re.I)),
    ("oracle_error", re.compile(r"\\bORA-\\d{5}|Oracle.*?Driver|quoted string not properly terminated", re.I)),
    ("db2_error", re.compile(r"DB2 SQL error|SQLCODE[=:\\d, -]+SQLSTATE", re.I)),
    ("generic_sql", re.compile(r"(?:syntax error|unterminated|unclosed quotation).{0,80}(?:sql|query)", re.I)),
)


@dataclass(frozen=True, slots=True)
class SqliProbe:
    original_url: str
    injected_url: str
    parameter: str
    payload: str


def has_query_params(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.query and parse_qsl(parsed.query, keep_blank_values=True))


def generate_sqli_probes(url: str, payload_limit: int = 6, param_limit: int = 4) -> list[SqliProbe]:
    parsed = urlparse(url)
    items = parse_qsl(parsed.query, keep_blank_values=True)
    if not items:
        return []

    probes: list[SqliProbe] = []
    payloads = SQLI_PAYLOADS[: max(1, payload_limit)]
    scoped_items = items[: max(1, param_limit)]

    for idx, (key, value) in enumerate(scoped_items):
        for payload in payloads:
            mutated_items = list(items)
            mutated_items[idx] = (key, f"{value}{payload}")
            injected_query = urlencode(mutated_items, doseq=True)
            injected_url = urlunparse(parsed._replace(query=injected_query))
            probes.append(SqliProbe(original_url=url, injected_url=injected_url, parameter=key, payload=payload))

    return probes


def build_boolean_pair(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)
    items = parse_qsl(parsed.query, keep_blank_values=True)
    if not items:
        return None

    first_key, _ = items[0]
    true_items = list(items)
    false_items = list(items)
    true_items[0] = (first_key, "1' OR '1'='1")
    false_items[0] = (first_key, "1' OR '1'='2")

    true_url = urlunparse(parsed._replace(query=urlencode(true_items, doseq=True)))
    false_url = urlunparse(parsed._replace(query=urlencode(false_items, doseq=True)))
    return true_url, false_url


def match_sql_errors(text: str) -> list[str]:
    haystack = text or ""
    hits: list[str] = []
    for name, pattern in SQL_ERROR_PATTERNS:
        if pattern.search(haystack):
            hits.append(name)
    return hits
