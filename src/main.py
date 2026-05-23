"""
==============================================================================
ALU Regex Data Extraction & Secure Validation
==============================================================================

Extracts and validates 4 data types from realistic, messy text:

    1. Email addresses     (with ALU-specific sub-classification)
    2. Credit card numbers (Luhn-validated)
    3. URLs                (scheme-restricted; private hosts rejected)
    4. Phone numbers       (international + local formats)

SECURITY POSTURE
----------------
This program treats every byte of `raw-text.txt` as UNTRUSTED user-generated
content. Decisions reflecting that belief:

    * No `eval`, `exec`, or shell interpolation of input
    * Input size capped (DoS prevention)
    * Match count capped per category
    * No catastrophic-backtracking regex patterns (no `(a+)+` antipattern)
    * Sensitive matches (cards, emails) are MASKED in output
    * Full values never written to logs or printed to the console
    * URL schemes are allow-listed (http/https only); `javascript:`, `data:`,
      `file:`, `vbscript:`, `ftp:` are rejected AND audit-logged
    * Private/loopback hosts (127.x, 10.x, 192.168.x, localhost) rejected
    * Email parser explicitly rejects SQL fragments, double-@, control chars
    * No network calls — extraction is offline and deterministic
    * All rejected values are HTML-escaped before storage (XSS prevention)

To run:
    python3 src/main.py
"""

from __future__ import annotations

import html
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# ------------------------------------------------------------------------------
# PATHS
# Resolved relative to the project root (the parent of /src) so the program
# works no matter where you run `python` from.
# ------------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_ROOT / "input" / "raw-text.txt"
OUTPUT_FILE = PROJECT_ROOT / "output" / "sample-output.json"

# ------------------------------------------------------------------------------
# DEFENSIVE LIMITS
# A hostile input could otherwise exhaust memory or produce a giant JSON file.
# ------------------------------------------------------------------------------
MAX_INPUT_BYTES = 5 * 1024 * 1024       # 5 MB
MAX_MATCHES_PER_CATEGORY = 1000


# ==============================================================================
# 1. EMAIL ADDRESSES
# ==============================================================================
#
# The pattern is intentionally STRICTER than RFC 5322. RFC-compliant emails
# allow exotic constructs (quoted local parts, comments, IP-literal domains)
# that are almost never seen in real production text and that are common
# vectors for parser-confusion attacks. We accept the practical 99%:
#
#     local-part : letters, digits, and the printable specials  . _ % + -
#                  (must not start or end with a dot; no consecutive dots)
#     @
#     domain     : labels of letters/digits/hyphen separated by dots
#     TLD        : at least 2 letters
#
# Word boundaries (\b) prevent partial matches inside larger tokens.
# ==============================================================================
EMAIL_PATTERN = re.compile(
    r"""
    \b                          # word boundary — stops us matching the tail of
                                # a longer token like "not-an-email@@bad.com"
    (?P<local>                  # named group so we can pull the local part out
                                # later for length and safety checks
        [A-Za-z0-9_%+\-]+       # one or more allowed chars: letters, digits,
                                # and the four printable specials _ % + -
                                # NOTE: dot is NOT allowed here — this prevents
                                # a leading dot such as ".user@example.com"
        (?:\.[A-Za-z0-9_%+\-]+)*  # zero or more dot-then-chars blocks, e.g.
                                  # the ".doe" in "jane.doe@example.com"
                                  # Using non-capturing (?:...) because we only
                                  # need the whole local part, not each segment
    )
    @                           # literal @ — exactly one; double-@ like
                                # "user@@evil.com" won't match because the
                                # domain group below requires a letter/digit
                                # immediately after @
    (?P<domain>                 # named group for the domain half
        (?:                     # non-capturing group for one domain label
            [A-Za-z0-9]         # label must START with a letter or digit
                                # (hyphens at the start are invalid per RFC 1035)
            (?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?  # optional middle: up to 61
                                # letters/digits/hyphens followed by a
                                # letter/digit — max label length is 63 chars
            \.                  # each label ends with a literal dot
        )+                      # one or more labels required (e.g. "mail.google.")
        [A-Za-z]{2,24}          # TLD: letters only, 2 chars minimum (.io, .uk)
                                # up to 24 to cover long TLDs like .cancerresearch
    )
    \b                          # word boundary on the right — prevents matching
                                # "user@example.com123" as a valid address
    """,
    re.VERBOSE,
)

# ALU-specific domain rules.
# Per assignment: validate emails ending with these three domains specifically.
# Comparisons are done case-insensitively because email domains are not
# case-sensitive (RFC 1035).
ALU_DOMAIN_OFFICIAL = "alueducation.com"
ALU_DOMAIN_ALUMNI = "alumni.alueducation.com"
ALU_DOMAIN_SI = "si.alueducation.com"


def classify_alu_email(domain_lower: str) -> str | None:
    """Return the ALU category for an email domain, or None if non-ALU."""
    if domain_lower == ALU_DOMAIN_OFFICIAL:
        return "alu_official"
    if domain_lower == ALU_DOMAIN_ALUMNI:
        return "alu_alumni"
    if domain_lower == ALU_DOMAIN_SI:
        return "alu_si"
    return None


def is_email_safe(local: str, domain: str) -> tuple[bool, str]:
    """
    Defense-in-depth checks AFTER the regex match.
    Catches malformed inputs that slip past the regex shape, plus common
    injection patterns. Returns (ok, reason); reason is "" when ok.
    """
    # RFC 5321 caps local at 64 chars and the whole address at 254.
    if len(local) > 64:
        return False, "local_part_too_long"
    if len(local) + 1 + len(domain) > 254:
        return False, "email_too_long"

    # No consecutive dots in local part (RFC violation + common bug).
    if ".." in local:
        return False, "consecutive_dots_in_local"

    # No control characters. Catches \x00 \r \n smuggling attempts which can
    # be used for SMTP header injection downstream.
    if any(ord(c) < 0x20 for c in local + domain):
        return False, "control_character"

    # SQL fragments and quote chars have no business in an email; if the
    # regex still let one through, refuse. (Belt and suspenders.)
    for bad in ("'", '"', ";", "--", "<", ">"):
        if bad in local or bad in domain:
            return False, "suspicious_character"

    return True, ""


# ==============================================================================
# 2. CREDIT CARD NUMBERS
# ==============================================================================
#
# Strategy:
#   (a) Regex matches any plausibly card-shaped digit sequence, allowing
#       single spaces or hyphens as separators (the two formats humans
#       actually type).
#   (b) Strip separators; run the LUHN checksum. Luhn rules out the vast
#       majority of random 16-digit strings.
#   (c) Apply IIN/BIN prefix rules to identify the brand (Visa, MC, Amex,
#       Discover). Cards passing Luhn but matching no known brand are
#       reported as `unknown_brand` instead of being silently dropped.
#
# Lookarounds (?<!\d) / (?!\d) prevent matching only PART of a longer digit
# string. Without them, "4532015112830366999" would match the first 16
# digits, which is almost certainly the wrong interpretation.
# ==============================================================================
CREDIT_CARD_PATTERN = re.compile(
    r"""
    (?<!\d)                         # negative lookbehind — no digit immediately
                                    # before the match; prevents grabbing the
                                    # last 16 digits of a longer number like
                                    # a 20-digit account ID
    (
        \d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}
                                    # most common printed format: four groups
                                    # of 4 digits separated by a space OR hyphen
                                    # e.g. "4111 1111 1111 1111" or
                                    #      "4111-1111-1111-1111"
                                    # [ -] is a character class matching exactly
                                    # one space or one hyphen — NOT a range
        |
        \d{4}[ -]\d{6}[ -]\d{5}     # American Express format: 4-6-5 grouping
                                    # e.g. "3782 822463 10005"
                                    # Amex cards are always 15 digits total
        |
        \d{13,19}                   # bare digit run with no separators
                                    # 13 = shortest real card (old Visa)
                                    # 19 = longest issued today (some Maestro)
                                    # Luhn + length check below will reject
                                    # anything that isn't a real card number
    )
    (?!\d)                          # negative lookahead — no digit immediately
                                    # after; mirrors the lookbehind above
    """,
    re.VERBOSE,
)


def luhn_check(digits: str) -> bool:
    """
    Classic Luhn / mod-10 checksum.
    Process from rightmost digit. Double every second digit; if the doubled
    value > 9, subtract 9 (equivalent to summing its two digits). Number is
    valid iff the total is divisible by 10.
    """
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def identify_brand(digits: str) -> str:
    """Return the card brand from the IIN prefix, or 'unknown_brand'."""
    n = len(digits)
    if n == 15 and (digits.startswith("34") or digits.startswith("37")):
        return "amex"
    if n == 16 and digits.startswith("4"):
        return "visa"
    if n == 16 and digits[:2] in {"51", "52", "53", "54", "55"}:
        return "mastercard"
    # Mastercard 2-series (2221-2720), added 2017
    if n == 16 and digits[:4].isdigit() and 2221 <= int(digits[:4]) <= 2720:
        return "mastercard"
    if n == 16 and (digits.startswith("6011") or digits[:2] == "65"):
        return "discover"
    return "unknown_brand"


def mask_card(digits: str) -> str:
    """PCI-safe display form: first 4 and last 4 only."""
    if len(digits) < 8:
        return "*" * len(digits)
    return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}"


# ==============================================================================
# 3. URLs
# ==============================================================================
#
# We accept ONLY http and https schemes. Anything else — `javascript:`,
# `data:`, `file:`, `vbscript:`, `ftp:` — is rejected because those are the
# classic vectors for XSS / SSRF / link-injection attacks.
#
# The path/query/fragment portion allows any non-whitespace character except
# angle brackets and quotes (which indicate a malformed copy/paste).
# ==============================================================================
URL_PATTERN = re.compile(
    r"""
    \b                              # word boundary so we don't match a URL
                                    # that is glued to surrounding text
    (?P<scheme>https?)://           # allow-list: ONLY http or https
                                    # the '?' makes the 's' optional so one
                                    # pattern covers both schemes
                                    # anything else (ftp, javascript, data…)
                                    # is caught by UNSAFE_SCHEME_PATTERN below
    (?P<host>                       # named group — extracted for safety checks
        (?:                         # non-capturing group for one hostname label
            [A-Za-z0-9]             # label must start with alphanumeric
            (?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?  # optional body: letters,
                                    # digits, hyphens; max 63 chars per label
                                    # (RFC 1035 limit)
            \.                      # dot separator between labels
        )+                          # one or more labels, e.g. "www.google."
        [A-Za-z]{2,24}              # TLD: letters only, 2–24 chars
                                    # raw IPv4 hosts (192.168.x.x) won't match
                                    # here because digits-only TLDs are excluded
    )
    (?::(?P<port>\d{1,5}))?         # optional port number after a colon
                                    # 1–5 digits covers 1 to 99999; we validate
                                    # the actual value (≤ 65535) in is_url_safe()
    (?P<path>/[^\s<>"']*)?          # optional path + query + fragment
                                    # [^\s<>"'] stops at whitespace or the four
                                    # chars most likely to indicate the URL has
                                    # ended inside HTML or a quoted string
    """,
    re.VERBOSE,
)

# Pattern used purely for AUDIT LOGGING of unsafe schemes. We don't add these
# to valid_urls — but surfacing them in `rejected` lets a reviewer SEE that
# the defense fired, instead of wondering why a URL disappeared.
# UNSAFE_SCHEME_PATTERN — audit-only; matches known dangerous URI schemes.
# javascript: can execute code in a browser (XSS).
# data:       can embed arbitrary base64 payloads (XSS / data exfiltration).
# vbscript:   legacy IE code-execution vector.
# file:       exposes the local filesystem to the browser.
# ftp:        unencrypted transfer; also used in SSRF probes.
# [^\s<>"']{1,200} — capture up to 200 non-whitespace chars of the payload
# so the rejection log is informative but can't be bloated by a huge string.
UNSAFE_SCHEME_PATTERN = re.compile(
    r"\b(?P<scheme>javascript|data|vbscript|file|ftp):[^\s<>\"']{1,200}",
    re.IGNORECASE,
)

# Same idea for URLs whose host is a raw IPv4 address — common SSRF /
# internal-network red flag. These don't match URL_PATTERN (which requires
# a DNS-style TLD), so without this audit pass they would vanish silently.
# IP_URL_PATTERN — catches http(s) URLs whose host is a raw IPv4 address.
# These are a classic SSRF (Server-Side Request Forgery) red flag: an attacker
# supplies a URL like http://169.254.169.254/latest/meta-data/ to make the
# server fetch its own cloud metadata endpoint.
# \d{1,3}(?:\.\d{1,3}){3}  matches four dot-separated octet-like groups;
# we don't validate the numeric range here — that's intentional, because
# even an out-of-range octet string is suspicious and should be rejected.
IP_URL_PATTERN = re.compile(
    r"\bhttps?://(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

# Private / loopback / link-local IPv4 prefixes (RFC 1918 + RFC 3927).
PRIVATE_HOST_PREFIXES = (
    "127.", "10.",
    "192.168.",
    "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

# Brands that attackers commonly embed as subdomains or path segments to
# make a phishing URL look legitimate at a glance, e.g.:
#   https://alu-education.com.phishing-domain.ru/login
# The real registrable domain (eTLD+1) is "phishing-domain.ru", not
# "alueducation.com". We extract the registrable domain by taking the
# last two labels of the host and check that none of the protected brand
# keywords appear in the NON-registrable portion (i.e. the subdomains).
PROTECTED_BRAND_KEYWORDS = (
    "alueducation",
    "alu-education",
    "alu_education",
)


def _registrable_domain(host_lower: str) -> tuple[str, str]:
    """
    Split host into (subdomains_prefix, registrable_domain).
    'alu-education.com.phishing-domain.ru' -> ('alu-education.com.', 'phishing-domain.ru')
    'portal.alueducation.com'              -> ('portal.', 'alueducation.com')
    """
    labels = host_lower.split(".")
    if len(labels) < 2:
        return "", host_lower
    registrable = ".".join(labels[-2:])   # last two labels = eTLD+1 approximation
    prefix = ".".join(labels[:-2])        # everything before
    return prefix, registrable


def is_url_safe(host: str, port: str | None) -> tuple[bool, str]:
    """Reject URLs pointing at internal infrastructure or with bogus ports."""
    host_lower = host.lower()
    if host_lower == "localhost" or host_lower.startswith(PRIVATE_HOST_PREFIXES):
        return False, "private_or_loopback_host"
    if port is not None:
        p = int(port)
        if p == 0 or p > 65535:
            return False, "invalid_port"
    # Subdomain-hijack / homograph phishing check.
    # If a protected brand keyword appears in the subdomain portion but the
    # registrable domain is NOT an official ALU domain, the URL is a spoof.
    # e.g. "alu-education.com.phishing-domain.ru" has registrable domain
    # "phishing-domain.ru" — clearly not alueducation.com — so it's rejected.
    prefix, registrable = _registrable_domain(host_lower)
    if registrable not in ("alueducation.com", "alumni.alueducation.com", "si.alueducation.com"):
        for keyword in PROTECTED_BRAND_KEYWORDS:
            if keyword in prefix or keyword in registrable:
                return False, "phishing_domain_spoof"
    return True, ""


# ==============================================================================
# 4. PHONE NUMBERS
# ==============================================================================
#
# Phone formats in the wild are wildly inconsistent. We match common shapes
# permissively, then validate by digit count after stripping separators.
# Accepted:
#   +CC followed by 6-14 more digits, with optional spaces / dots / hyphens
#   / parentheses around the area code. Plain 10-digit US-style numbers
#   (with or without separators) too.
#
# E.164 allows up to 15 digits total (including country code).
# ==============================================================================
PHONE_PATTERN = re.compile(
    r"""
    (?<!\w)                     # negative lookbehind for a word character —
                                # prevents matching digit runs inside words or
                                # identifiers like "order#2507881234"
    (
        \+?                     # optional leading '+' for international format
                                # e.g. +1, +44, +250
        \d{1,3}                 # country code OR first digit group: 1–3 digits
        [\s.\-]?                # optional separator after country code:
                                # space, dot, or hyphen — all common in practice
        (?:\(\d{1,4}\)[\s.\-]?)? # optional area code in parentheses
                                # e.g. (415) or (078); non-capturing group
                                # because we only need the whole match
        \d{1,4}[\s.\-]?         # first subscriber digit group (1–4 digits)
                                # followed by an optional separator
        \d{1,4}[\s.\-]?         # second subscriber digit group
        \d{1,9}                 # final digit group — intentionally wide (1–9)
                                # to accommodate long international suffixes
                                # without needing a separate pattern per country
    )
    (?!\w)                      # negative lookahead — not followed by a word
                                # character; mirrors the lookbehind above
    """,
    re.VERBOSE,
)

# False positives to filter out — the phone regex catches these because they
# happen to have enough digits, but they are CLEARLY not phone numbers:
_DATE_LIKE = re.compile(r"^\d{4}[-./]\d{1,2}[-./]\d{1,2}$")       # 2026-01-14
_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")               # 192.168.1.1
_DOTTED_DECIMAL = re.compile(r"^\d+\.\d+$")                       # 2401.12345


def looks_like_non_phone(raw: str) -> bool:
    """Pre-filter for things that have a phone-like digit count but aren't."""
    s = raw.strip()
    return bool(_DATE_LIKE.match(s) or _IP_LIKE.match(s) or _DOTTED_DECIMAL.match(s))


def normalize_phone(raw: str) -> str:
    """Strip everything except digits and a leading '+'."""
    cleaned = re.sub(r"[^\d+]", "", raw)
    if cleaned.startswith("+"):
        cleaned = "+" + cleaned.lstrip("+")
    return cleaned


def is_phone_valid(normalized: str) -> tuple[bool, str]:
    """E.164-ish validation: 7-15 digits, optional leading '+'."""
    digits = normalized.lstrip("+")
    if not digits.isdigit():
        return False, "non_digit_content"
    if not (7 <= len(digits) <= 15):
        return False, "wrong_digit_count"
    if set(digits) == {"0"}:
        return False, "all_zeros"
    return True, ""


# ==============================================================================
# OUTPUT MASKING HELPERS
# ==============================================================================
def mask_email(addr: str) -> str:
    """
    Obfuscate emails in output/logs to prevent unnecessary exposure.
    'jane.doe@example.com' -> 'j******e@example.com'
    """
    if "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    if len(local) <= 2:
        masked = local[0] + "*"
    else:
        masked = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{masked}@{domain}"


def _dedup(items: Iterable[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# ==============================================================================
# RESULT CONTAINER
# ==============================================================================
@dataclass
class ExtractionResult:
    """Holds one run's findings. Mutable, filled by the extractor functions."""
    valid_emails: list[dict] = field(default_factory=list)
    valid_credit_cards: list[dict] = field(default_factory=list)
    valid_urls: list[dict] = field(default_factory=list)
    valid_phones: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)

    def reject(self, category: str, value: str, reason: str) -> None:
        """Log a rejection. Sensitive values are masked before storing.
        All values are HTML-escaped before storage to prevent XSS if the
        JSON output is ever rendered in a web context.
        """
        display = value
        if category == "credit_card":
            digits = re.sub(r"\D", "", value)
            display = mask_card(digits) if digits else value
        elif category == "email":
            display = mask_email(value)
        # html.escape neutralises <, >, &, ", ' — prevents XSS if this JSON
        # is ever embedded in an HTML page or web dashboard.
        self.rejected.append(
            {"category": category, "value": html.escape(display), "reason": reason}
        )

    def to_dict(self, source_filename: str) -> dict:
        return {
            "source": source_filename,
            "summary": {
                "emails": len(self.valid_emails),
                "credit_cards": len(self.valid_credit_cards),
                "urls": len(self.valid_urls),
                "phones": len(self.valid_phones),
                "rejected": len(self.rejected),
            },
            "valid_emails": self.valid_emails,
            "valid_credit_cards": self.valid_credit_cards,
            "valid_urls": self.valid_urls,
            "valid_phones": self.valid_phones,
            "rejected": self.rejected,
        }


# ==============================================================================
# EXTRACTORS
# ==============================================================================
def extract_emails(text: str, result: ExtractionResult) -> None:
    found_raw = [m.group(0) for m in EMAIL_PATTERN.finditer(text)]
    for raw in _dedup(found_raw)[:MAX_MATCHES_PER_CATEGORY]:
        m = EMAIL_PATTERN.fullmatch(raw)
        if not m:
            result.reject("email", raw, "regex_resync_failed")
            continue
        local = m.group("local")
        domain = m.group("domain")
        ok, reason = is_email_safe(local, domain)
        if not ok:
            result.reject("email", raw, reason)
            continue
        domain_lower = domain.lower()
        alu_category = classify_alu_email(domain_lower)
        result.valid_emails.append({
            "masked": mask_email(raw),                # never expose full value
            "domain": domain_lower,
            "alu_category": alu_category,             # None if non-ALU
            "is_alu": alu_category is not None,
        })


def extract_credit_cards(text: str, result: ExtractionResult) -> None:
    found_raw = [m.group(1) for m in CREDIT_CARD_PATTERN.finditer(text)]
    for raw in _dedup(found_raw)[:MAX_MATCHES_PER_CATEGORY]:
        digits = re.sub(r"[ -]", "", raw)
        if not digits.isdigit():
            result.reject("credit_card", raw, "non_digit_after_strip")
            continue
        if not (13 <= len(digits) <= 19):
            result.reject("credit_card", raw, "wrong_length")
            continue
        if not luhn_check(digits):
            result.reject("credit_card", raw, "luhn_failed")
            continue
        result.valid_credit_cards.append({
            "masked": mask_card(digits),              # PCI-safe display only
            "brand": identify_brand(digits),
            "length": len(digits),
        })


def extract_urls(text: str, result: ExtractionResult) -> None:
    # AUDIT PASS 1 — unsafe schemes (javascript:, data:, file:, etc.)
    for m in UNSAFE_SCHEME_PATTERN.finditer(text):
        snippet = m.group(0)
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."           # truncate payloads
        result.reject("url", snippet, f"unsafe_scheme:{m.group('scheme').lower()}")

    # AUDIT PASS 2 — http(s) URLs with raw IPv4 host (SSRF red flag)
    for m in IP_URL_PATTERN.finditer(text):
        result.reject("url", m.group(0), "ip_literal_host")

    # MAIN PASS — only http/https URLs with named hosts
    seen: set[str] = set()
    for m in URL_PATTERN.finditer(text):
        full = m.group(0)
        if full in seen:
            continue
        seen.add(full)
        scheme = m.group("scheme").lower()
        host = m.group("host").lower()
        port = m.group("port")
        ok, reason = is_url_safe(host, port)
        if not ok:
            result.reject("url", full, reason)
            continue
        result.valid_urls.append({
            "url": full,
            "scheme": scheme,
            "host": host,
            "port": int(port) if port else None,
            "secure": scheme == "https",
        })
        if len(result.valid_urls) >= MAX_MATCHES_PER_CATEGORY:
            break


def extract_phones(text: str, result: ExtractionResult) -> None:
    # PRE-PROCESSING: blank out spans of text already claimed by URLs or
    # credit-card-shaped tokens. This prevents:
    #   - Phone-shaped substrings inside DOIs / URLs being reported as phones
    #   - Partial digit-runs from inside credit-card numbers
    # We replace each claimed span with spaces of equal length to preserve
    # surrounding character offsets.
    masked = list(text)

    def blank(start: int, end: int) -> None:
        for i in range(start, end):
            if masked[i] != "\n":
                masked[i] = " "

    for m in URL_PATTERN.finditer(text):
        blank(m.start(), m.end())
    # Blank ANY credit-card-shaped token (Luhn-pass OR Luhn-fail). A
    # Luhn-failed card is still a credit-card-shaped object, not a phone.
    for m in CREDIT_CARD_PATTERN.finditer(text):
        blank(m.start(1), m.end(1))

    cleaned_text = "".join(masked)

    found_raw = [m.group(1).strip() for m in PHONE_PATTERN.finditer(cleaned_text)]
    seen_normalized: set[str] = set()
    for raw in found_raw[:MAX_MATCHES_PER_CATEGORY * 2]:
        if looks_like_non_phone(raw):
            continue
        normalized = normalize_phone(raw)
        # Require SOME signal this is a phone (not just a random digit run):
        # leading '+' OR at least one separator in the original.
        has_separator = any(c in raw for c in " .-()")
        if not normalized.startswith("+") and not has_separator:
            continue
        ok, reason = is_phone_valid(normalized)
        if not ok:
            # Silently drop very common false positives (short digit runs
            # like years, ticket numbers) but log interesting rejects.
            if reason == "wrong_digit_count" and len(normalized.lstrip("+")) < 7:
                continue
            result.reject("phone", raw, reason)
            continue
        if normalized in seen_normalized:
            continue
        seen_normalized.add(normalized)
        result.valid_phones.append({
            "raw": raw,
            "normalized": normalized,
            "country_code_present": normalized.startswith("+"),
        })


# ==============================================================================
# DRIVER
# ==============================================================================
def load_input() -> str:
    """Read the input file with size guard + UTF-8 hardening."""
    if not INPUT_FILE.exists():
        print(f"ERROR: input file not found at {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)
    size = INPUT_FILE.stat().st_size
    if size > MAX_INPUT_BYTES:
        print(f"ERROR: input file exceeds {MAX_INPUT_BYTES} bytes "
              f"({size} bytes) — refusing to process", file=sys.stderr)
        sys.exit(2)
    # errors='replace' so a stray bad byte can't crash the parser; the
    # replacement char won't satisfy any of our regexes anyway.
    return INPUT_FILE.read_text(encoding="utf-8", errors="replace")


def print_summary(result: ExtractionResult) -> None:
    """Console summary. Counts only — no sensitive values printed."""
    print("=" * 60)
    print("  Extraction summary")
    print("=" * 60)
    print(f"  Emails (valid)        : {len(result.valid_emails)}")
    alu_buckets = {"alu_official": 0, "alu_alumni": 0, "alu_si": 0}
    for e in result.valid_emails:
        if e["alu_category"] in alu_buckets:
            alu_buckets[e["alu_category"]] += 1
    print(f"      • ALU official    : {alu_buckets['alu_official']}")
    print(f"      • ALU alumni      : {alu_buckets['alu_alumni']}")
    print(f"      • ALU SI          : {alu_buckets['alu_si']}")
    print(f"  Credit cards (Luhn OK): {len(result.valid_credit_cards)}")
    by_brand: dict[str, int] = {}
    for c in result.valid_credit_cards:
        by_brand[c["brand"]] = by_brand.get(c["brand"], 0) + 1
    for brand, n in sorted(by_brand.items()):
        print(f"      • {brand:<15} : {n}")
    print(f"  URLs (http/https)     : {len(result.valid_urls)}")
    print(f"  Phones (E.164-ish)    : {len(result.valid_phones)}")
    print(f"  Rejected items        : {len(result.rejected)}")
    print("=" * 60)
    print(f"  Detailed output -> {html.escape(str(OUTPUT_FILE))}")
    print("=" * 60)


def main() -> int:
    text = load_input()
    result = ExtractionResult()
    extract_emails(text, result)
    extract_credit_cards(text, result)
    extract_urls(text, result)
    extract_phones(text, result)        # runs LAST: needs URL/card spans

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(result.to_dict(INPUT_FILE.name), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print_summary(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())