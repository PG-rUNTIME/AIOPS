"""PII redaction applied before telemetry is stored or shown to an LLM.

Covers card PANs (Luhn-checked), bank account numbers and IBANs, national IDs
used by our target markets (South Africa, Zimbabwe, Kenya, Nigeria), e-mail
addresses and MSISDNs. The same rules are mirrored in the OTel Collector
``transform`` processor (config/otel-collector/collector.yaml); this module is
the defence-in-depth copy used by ingest-gateway and agent-gateway.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    accept: Callable[[re.Match[str]], bool] = lambda m: True


def _pan_ok(m: re.Match[str]) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


RULES: tuple[Rule, ...] = (
    Rule("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")),
    # Zimbabwe national ID, e.g. 63-1234567A12 / 631234567A12
    Rule("ZW_ID", re.compile(r"\b\d{2}-?\d{6,7}-?[A-Z]-?\d{2}\b")),
    # South African ID: YYMMDD SSSS C A Z (13 digits)
    Rule(
        "ZA_ID",
        re.compile(r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{7}(?!\d)"),
        lambda m: luhn_ok(m.group(0)),
    ),
    Rule("PAN", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _pan_ok),
    # Keyword-anchored numbers: account numbers, Kenyan ID, Nigerian NIN/BVN
    Rule(
        "ACCOUNT",
        re.compile(
            r"(?i)\b(?:acc(?:oun)?t|acct|a/c|iban|nin|bvn|national[_ ]?id|id[_ ]?no)"
            r"(?:\s*(?:no|number|num|#))?\s*[:=#]?\s*\d[\d -]{5,20}\d"
        ),
    ),
    Rule("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    Rule("MSISDN", re.compile(r"(?<![\w+])\+?(?:2[0-9]{2})[ -]?\d{2,3}[ -]?\d{3}[ -]?\d{3,4}\b")),
)


def redact(text: str, rules: tuple[Rule, ...] = RULES) -> tuple[str, dict[str, int]]:
    """Return redacted text and a count of redactions per rule."""
    counts: dict[str, int] = {}
    for rule in rules:

        def _sub(m: re.Match[str], rule: Rule = rule) -> str:
            if not rule.accept(m):
                return m.group(0)
            counts[rule.name] = counts.get(rule.name, 0) + 1
            return f"[REDACTED:{rule.name}]"

        text = rule.pattern.sub(_sub, text)
    return text, counts


def redact_str(text: str) -> str:
    return redact(text)[0]
