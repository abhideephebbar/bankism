"""Bankism firewall: normalization, obfuscation handling, threat analysis,
deterministic parsing, risk classification and the final decision.

Design rules (all enforced here)
--------------------------------
1. Security decisions live ONLY on the backend. Client input never carries a
   verdict, risk score or intent.
2. Fail closed. Any exception, malformed analyzer result or unexpected state
   produces a BLOCK verdict with no side effects.
3. Recipient and amount are extracted ONLY from the cleaned ``message``. Decoded
   (attacker-controlled) content is used for *detection*, never as transaction
   input. ``memo`` is data only.
4. Never guess. Exactly one supported intent plus all required fields, or BLOCK.
5. The analyzer is an interface. Heuristics are deterministic; there is no LLM
   in the baseline. Whatever the analyzer returns is validated before use.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .banking import CURRENCY, MAX_TRANSACTION_AMOUNT, BankingService
from .schemas import (
    Decision,
    Intent,
    RiskLevel,
    ThreatCategory,
    ThreatResult,
    TransactionDetails,
    Verdict,
)

# --------------------------------------------------------------------------- #
# Tunable safety bounds
# --------------------------------------------------------------------------- #
MAX_DECODE_DEPTH = 2          # how many nested encoding layers we peel
MAX_DECODED_SIZE = 2000       # max characters per decoded candidate
MAX_CANDIDATES = 8            # max decoded candidates per field
MEMO_MAX_LEN = 140


# --------------------------------------------------------------------------- #
# Character classes
# --------------------------------------------------------------------------- #
_ZERO_WIDTH_CHARS = set(
    chr(c)
    for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF, 0x00AD)
)
_BIDI_CHARS = set(chr(c) for c in range(0x202A, 0x202F)) | set(
    chr(c) for c in range(0x2066, 0x206A)
)
_CONTROL_CHARS = set(
    chr(c) for c in range(0x00, 0x20) if c not in (0x09, 0x0A, 0x0D)
) | {chr(0x7F)}
_INVISIBLE_CHARS = _ZERO_WIDTH_CHARS | _BIDI_CHARS | _CONTROL_CHARS

# Common homoglyphs (Greek / Cyrillic / look-alikes) -> ASCII.
_HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u0491": "g", "\u0501": "d", "\u04bb": "h", "\u0500": "d",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X", "\u0410": "A",
    "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u0423": "Y", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u0131": "i", "\u2113": "l", "\u2170": "i", "\u217c": "l",
    "\uff49": "i", "\uff4c": "l",
}

# Leetspeak -> letters. Used for DETECTION ONLY (never for amount parsing).
_LEET_MAP: Dict[int, str] = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
     "9": "g", "@": "a", "$": "s", "!": "i", "|": "l"}
)
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPH_MAP)

_DOTTED_INSERTION = re.compile(r"(?<=\w)\.(?=\w)")


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def strip_invisibles(text: str) -> str:
    """Remove zero-width, bidi, and Unicode control/format characters.

    Ordinary tab/newline/carriage-return are retained temporarily so the later
    whitespace-collapsing step turns them into separators instead of merging
    adjacent words. Other Unicode Cc/Cf characters are removed.
    """
    kept = []
    for ch in text:
        if ch in "\t\n\r":
            kept.append(ch)
            continue
        if ch in _INVISIBLE_CHARS or unicodedata.category(ch) in {"Cc", "Cf"}:
            continue
        kept.append(ch)
    return "".join(kept)


def clean_text(text: str) -> str:
    """Conservative cleaning used for *parsing* transaction fields.

    NFKC-normalizes, strips invisibles and collapses whitespace. It does NOT
    apply leetspeak/homoglyph mapping, so numeric amounts stay intact.
    """
    if text is None:
        return ""
    normalized = unicodedata.normalize("NFKC", str(text))
    normalized = strip_invisibles(normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def fold_text(text: str) -> str:
    """Aggressive normalization used ONLY for attack detection."""
    folded = clean_text(text)
    folded = folded.translate(_HOMOGLYPH_TABLE).translate(_LEET_MAP)
    folded = folded.casefold()
    # collapse dotted insertion: "i.g.n.o.r.e" -> "ignore"
    folded = _DOTTED_INSERTION.sub("", folded)
    # punctuation becomes whitespace so word-boundary patterns still match
    folded = re.sub(r"[^\w\s]", " ", folded)
    return re.sub(r"\s+", " ", folded).strip()


# --------------------------------------------------------------------------- #
# Bounded decoding of encodings (base64, hex, URL, ROT13)
# --------------------------------------------------------------------------- #
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9a-fA-F]{16,})(?![0-9A-Za-z])")
_URL_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return printable / len(text) >= 0.9


def _try_base64(token: str) -> Optional[str]:
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return decoded if _is_mostly_printable(decoded) else None


def _try_hex(token: str) -> Optional[str]:
    value = token[2:] if token.lower().startswith("0x") else token
    if len(value) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if _is_mostly_printable(decoded) else None


def _single_layer_decodes(text: str) -> List[Tuple[str, str]]:
    """Return ``(decoded_text, label)`` pairs for one decoding layer."""
    results: List[Tuple[str, str]] = []
    for match in _B64_RE.finditer(text):
        decoded = _try_base64(match.group(1))
        if decoded:
            results.append((decoded, "base64"))
    for match in _HEX_RE.finditer(text):
        decoded = _try_hex(match.group(1))
        if decoded:
            results.append((decoded, "hex"))
    if _URL_RE.search(text):
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            results.append((decoded, "url"))
    rotated = codecs.decode(text, "rot13")
    if rotated != text:
        results.append((rotated, "rot13"))
    return results


def build_candidates(text: str) -> Tuple[List[Tuple[str, str]], Set[str]]:
    """Build bounded decode candidates for ``text``.

    Returns ``(candidates, encoding_labels)`` where each candidate is
    ``(text, label)`` and ``label`` is one of raw/base64/hex/url/rot13.
    Depth, size and count are all bounded.
    """
    candidates: List[Tuple[str, str]] = [(text, "raw")]
    labels: Set[str] = set()
    seen: Set[str] = {text}
    frontier: List[str] = [text]

    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: List[str] = []
        for candidate in frontier:
            for decoded, label in _single_layer_decodes(candidate):
                if len(decoded) > MAX_DECODED_SIZE or decoded in seen:
                    continue
                seen.add(decoded)
                candidates.append((decoded, label))
                labels.add(label)
                next_frontier.append(decoded)
                if len(candidates) >= MAX_CANDIDATES:
                    return candidates, labels
        frontier = next_frontier
        if not frontier:
            break
    return candidates, labels


# --------------------------------------------------------------------------- #
# ThreatAnalyzer interface + deterministic heuristic implementation
# --------------------------------------------------------------------------- #
class AnalyzerError(Exception):
    """Raised internally when an analyzer fails or returns something invalid."""


class ThreatAnalyzer(ABC):
    """Interface for pluggable threat analysis.

    Implementations MUST be deterministic for the baseline. Any future
    implementation (including an LLM) returns a :class:`ThreatResult` that the
    firewall re-validates; a bad result fails closed.
    """

    @abstractmethod
    def analyze(self, text: str) -> ThreatResult:  # pragma: no cover - interface
        raise NotImplementedError


# Regex patterns run against *folded* text (see fold_text).
_PATTERNS: Dict[ThreatCategory, List[re.Pattern]] = {
    ThreatCategory.PROMPT_INJECTION: [
        re.compile(r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)?\s*(instructions?|prompts?|rules?|directions?)\b"),
        re.compile(r"\bdisregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)?\s*(instructions?|prompts?|rules?)\b"),
        re.compile(r"\bforget\s+(all\s+|your\s+|the\s+)?(previous|prior|instructions?|rules?|guidelines?)\b"),
        re.compile(r"\b(new|updated|revised)\s+instructions?\b"),
        re.compile(r"\bsystem\s+prompt\b"),
        re.compile(r"\byou\s+are\s+(now|no\s+longer)\b"),
        re.compile(r"\bdo\s+not\s+follow\b"),
        re.compile(r"\boverride\s+(the\s+)?(instructions?|system)\b"),
        re.compile(r"\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?)\b"),
        re.compile(r"\bprint\s+(your\s+)?(system\s+)?(prompt|instructions?)\b"),
        re.compile(r"\bprompt\s+injection\b"),
        re.compile(r"\bend\s+of\s+(system|prompt)\b"),
    ],
    ThreatCategory.ROLEPLAY_JAILBREAK: [
        re.compile(r"\b(pretend|act|roleplay|role\s*play|behave)\s+(you\s+are|you\s+re|as\s+if|to\s+be|as)\b"),
        re.compile(r"\bdon\s+t\s+have\s+any\s+(rules|restrictions|limits)\b"),
        re.compile(r"\bno\s+(rules|restrictions|limits|filters|guardrails)\b"),
        re.compile(r"\bunrestricted\b"),
        re.compile(r"\bwithout\s+any\s+(rules|restrictions|limits|filters)\b"),
        re.compile(r"\bdeveloper\s+mode\b"),
        re.compile(r"\bdo\s+anything\s+now\b"),
        re.compile(r"\bjailbreak\b"),
        re.compile(r"\bsimulate\s+being\b"),
        re.compile(r"\bimagine\s+you\s+are\b"),
        re.compile(r"\bact\s+as\s+(a|an|the)\b"),
    ],
    ThreatCategory.POLICY_OVERRIDE: [
        re.compile(r"\boverride\s+(the\s+)?(policy|policies|security|safety|limit|limits|validation|guardrails?|cap)\b"),
        re.compile(r"\bignore\s+(the\s+)?(policy|policies|security|safety|limit|limits|validation|cap)\b"),
        # Instructions to ignore/disregard safety or banking rules. The original
        # patterns above only allow an optional "the" between the verb and the
        # noun, so an attacker could slip a quantifier or domain adjective in
        # between ("ignore ALL security rules"). Bounded filler/adjective runs
        # close that obvious evasion without matching benign memos. Not claimed
        # to be complete detection.
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip|circumvent)\s+"
            r"(?:(?:all|any|the|these|those|your|my|our|previous|prior|existing|"
            r"current|new|and|of)\s+)*"
            r"(?:(?:banking|security|safety|financial|compliance|fraud|payment|"
            r"transfer|transaction|account|confidential|privacy)\s+)*"
            r"(?:rules?|polic(?:y|ies)|protocols?|procedures?|guidelines?|"
            r"restrictions?|limits?|checks?|controls?|safeguards?)\b"
        ),
        re.compile(r"\b(disable|turn\s+off|bypass|circumvent|skip)\s+(the\s+)?(security|safety|validation|checks?|filters?|limits?|firewall|approval)\b"),
        re.compile(r"\b(admin|administrator|root|superuser|system)\s+mode\b"),
        re.compile(r"\b(as|in)\s+(an?\s+)?(admin|administrator|root|superuser)\b"),
        re.compile(r"\b(raise|increase|lift|remove|change)\s+(the\s+)?(limit|limits|cap|maximum|max)\b"),
        re.compile(r"\bexempt\s+(me|this|the)\b"),
        re.compile(r"\bapprove\s+(this|it|the)\s+(transfer|transaction|payment)\b"),
        re.compile(r"\bmark\s+(this|it)\s+as\s+(approved|safe|ok)\b"),
        re.compile(r"\bno\s+need\s+(for\s+)?(verification|approval|checks?)\b"),
        re.compile(r"\bskip\s+(the\s+)?(approval|verification|checks?)\b"),
    ],
    ThreatCategory.DATA_EXFILTRATION: [
        re.compile(r"\b(all|every|other)\s+(users?|customers?|accounts?)\b"),
        re.compile(r"\blist\s+(all\s+|the\s+)?(accounts?|users?|customers?|balances?)\b"),
        # Requests to reveal/expose confidential or private data. The original
        # patterns covered "system/server/database" secrets and account lists,
        # but not a direct request for confidential/private account or banking
        # information. Requires a secrecy adjective so ordinary "show details"
        # wording is not flagged. Not claimed to be complete detection.
        re.compile(
            r"\b(?:reveal|expose|disclose|leak|divulge|show|share|print|output|dump)\s+"
            r"(?:(?:me|us|the|all|any|your|my|our|other|and|of)\s+)*"
            r"(?:confidential|private|sensitive|secret|hidden|internal|restricted)\s+"
            r"(?:(?:bank|banking|financial|account|customer|user|client|personal|payment)\s+)*"
            r"(?:data|information|info|details|records?|balances?|transactions?|"
            r"history|credentials?|documents?)\b"
        ),
        # Direct requests for banking/account specifics with no secrecy
        # adjective ("rent for October reveal bank details"): the secrecy-gated
        # pattern above misses those because "bank" is neither filler nor a
        # secrecy word. Limited to explicit exfiltration verbs and an
        # account/banking target so benign memos stay clear. Not claimed to be
        # complete detection.
        re.compile(
            r"\b(?:reveal|disclose|extract|expose|leak|divulge)\s+"
            r"(?:(?:me|us|the|all|any|your|my|our|their|other|and|of)\s+)*"
            r"(?:bank|banking|bank\s+account|account|financial)\s+"
            r"(?:details|information|info|data|records?|numbers?|credentials?|"
            r"statements?|documents?)\b"
        ),
        re.compile(r"\bexport\b"),
        re.compile(r"\bdump\b"),
        re.compile(r"\b(password|passwords|pin|pins|otp|otps|credential|credentials|secret|secrets|api\s+key|api\s+keys)\b"),
        re.compile(r"\b(system|server|internal|database)\s+(info|information|details|prompt|credentials?)\b"),
        re.compile(r"\bdatabase\b"),
        re.compile(r"\banother\s+(user|customer|account|person)\b"),
        re.compile(r"\buser\s*\d+\b"),
        re.compile(r"\bbalance\s+of\s+(user|account|customer|the\s+other)\b"),
    ],
}


class HeuristicThreatAnalyzer(ThreatAnalyzer):
    """Deterministic pattern-based analyzer. No external LLM, no API keys."""

    def analyze(self, text: str) -> ThreatResult:
        folded = fold_text(text)
        categories: List[ThreatCategory] = []
        signals: List[str] = []

        for category, patterns in _PATTERNS.items():
            for pattern in patterns:
                if pattern.search(folded):
                    if category not in categories:
                        categories.append(category)
                    signals.append(f"{category.value.lower()}_pattern")
                    break  # one hit per category is enough

        if not categories:
            return ThreatResult(
                threat_category=ThreatCategory.NONE,
                risk_level=RiskLevel.LOW,
                signals=[],
                categories=[],
            )

        top = max(categories, key=severity_of)
        return ThreatResult(
            threat_category=top,
            risk_level=risk_level_for(top),
            signals=signals,
            categories=categories,
        )


def get_threat_analyzer() -> ThreatAnalyzer:
    """FastAPI dependency for the analyzer. Overridable in tests."""
    return HeuristicThreatAnalyzer()


# --------------------------------------------------------------------------- #
# Severity / risk classification
# --------------------------------------------------------------------------- #
_SEVERITY: Dict[ThreatCategory, int] = {
    ThreatCategory.PROMPT_INJECTION: 90,
    ThreatCategory.POLICY_OVERRIDE: 85,
    ThreatCategory.ROLEPLAY_JAILBREAK: 80,
    ThreatCategory.MEMO_INJECTION: 75,
    ThreatCategory.DATA_EXFILTRATION: 70,
    ThreatCategory.OBFUSCATION: 60,
    ThreatCategory.UNSUPPORTED_OPERATION: 40,
    ThreatCategory.VALIDATION_FAILURE: 30,
    ThreatCategory.NONE: 0,
}

_RISK: Dict[ThreatCategory, RiskLevel] = {
    ThreatCategory.PROMPT_INJECTION: RiskLevel.CRITICAL,
    ThreatCategory.POLICY_OVERRIDE: RiskLevel.CRITICAL,
    ThreatCategory.ROLEPLAY_JAILBREAK: RiskLevel.HIGH,
    ThreatCategory.MEMO_INJECTION: RiskLevel.HIGH,
    ThreatCategory.DATA_EXFILTRATION: RiskLevel.HIGH,
    ThreatCategory.OBFUSCATION: RiskLevel.HIGH,
    ThreatCategory.UNSUPPORTED_OPERATION: RiskLevel.MEDIUM,
    ThreatCategory.VALIDATION_FAILURE: RiskLevel.MEDIUM,
    ThreatCategory.NONE: RiskLevel.LOW,
}

#: Categories that are security threats (everything except parse outcomes).
_SECURITY_CATEGORIES = {
    ThreatCategory.PROMPT_INJECTION,
    ThreatCategory.ROLEPLAY_JAILBREAK,
    ThreatCategory.POLICY_OVERRIDE,
    ThreatCategory.MEMO_INJECTION,
    ThreatCategory.OBFUSCATION,
    ThreatCategory.DATA_EXFILTRATION,
}

_RATIONALES: Dict[ThreatCategory, str] = {
    ThreatCategory.PROMPT_INJECTION: "Request attempted to manipulate the assistant's instructions and was blocked.",
    ThreatCategory.ROLEPLAY_JAILBREAK: "Request attempted a role-play / jailbreak to bypass safety rules and was blocked.",
    ThreatCategory.POLICY_OVERRIDE: "Request attempted to override security policy or limits and was blocked.",
    ThreatCategory.MEMO_INJECTION: "The payment memo contained instruction-like content and was blocked; memos are data only.",
    ThreatCategory.OBFUSCATION: "Request used encoding or hidden characters to obscure its content and was blocked.",
    ThreatCategory.DATA_EXFILTRATION: "Request attempted to access data outside the caller's own account and was blocked.",
    ThreatCategory.VALIDATION_FAILURE: "Request could not be validated deterministically and was blocked.",
    ThreatCategory.UNSUPPORTED_OPERATION: "Only balance inquiry and peer-to-peer transfer to a known payee are supported.",
    ThreatCategory.NONE: "Request approved.",
}


def severity_of(category: ThreatCategory) -> int:
    return _SEVERITY.get(category, 0)


def risk_level_for(category: ThreatCategory) -> RiskLevel:
    return _RISK.get(category, RiskLevel.MEDIUM)


# --------------------------------------------------------------------------- #
# Analyzer result validation (fail closed)
# --------------------------------------------------------------------------- #
def _analyze_safe(analyzer: ThreatAnalyzer, text: str) -> ThreatResult:
    """Run the analyzer and validate its result. Raises AnalyzerError on failure."""
    if analyzer is None:
        raise AnalyzerError("no analyzer configured")
    try:
        raw = analyzer.analyze(text)
    except AnalyzerError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed on any analyzer failure
        raise AnalyzerError(f"analyzer raised {type(exc).__name__}") from exc

    return _validate_threat_result(raw)


def _validate_threat_result(raw) -> ThreatResult:
    """Validate type and enum values of an analyzer result."""
    if not isinstance(raw, ThreatResult):
        raise AnalyzerError("analyzer returned a non-ThreatResult value")
    try:
        # Force enum membership checks even if the object bypassed validation.
        ThreatCategory(raw.threat_category)
        RiskLevel(raw.risk_level)
        for category in raw.categories:
            ThreatCategory(category)
        for signal in raw.signals:
            if not isinstance(signal, str):
                raise TypeError("signal must be a string")
    except (ValueError, TypeError) as exc:
        raise AnalyzerError("analyzer result failed validation") from exc
    return raw


# --------------------------------------------------------------------------- #
# Obfuscation detection
# --------------------------------------------------------------------------- #
def _structural_obfuscation(raw_text: str) -> Set[str]:
    signals: Set[str] = set()
    if any(ch in _ZERO_WIDTH_CHARS for ch in raw_text):
        signals.add("zero_width_characters_removed")
    if any(ch in _BIDI_CHARS for ch in raw_text):
        signals.add("bidi_control_characters_present")
    if any(ch in _CONTROL_CHARS for ch in raw_text) or any(
        unicodedata.category(ch) == "Cc" and ch not in "\t\n\r"
        for ch in raw_text
    ):
        signals.add("control_characters_present")
    if any(unicodedata.category(ch) == "Cf" for ch in raw_text):
        signals.add("format_control_characters_present")
    if any(ch in _HOMOGLYPH_MAP for ch in raw_text):
        signals.add("homoglyph_characters_present")
    if _DOTTED_INSERTION.search(raw_text) and re.search(r"(?:\w\.){2,}\w", raw_text):
        signals.add("dotted_character_insertion")
    return signals


def _obfuscation_signals(
    raw_message: str,
    raw_memo: Optional[str],
    encoding_labels: Set[str],
    attack_labels: Set[str],
) -> Set[str]:
    """Flag obfuscation, including harmless-looking encoding payloads."""
    signals = _structural_obfuscation(raw_message)
    if raw_memo:
        signals |= _structural_obfuscation(raw_memo)

    for label in encoding_labels:
        if label in ("base64", "hex", "url"):
            signals.add(f"{label}_payload_detected")
    if "rot13" in attack_labels:
        signals.add("rot13_payload_detected")
    return signals


# --------------------------------------------------------------------------- #
# Identity resolution (demo selectors, NOT authentication)
# --------------------------------------------------------------------------- #
def _norm_selector(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned.lower() if cleaned else None


def resolve_identity(
    user_id: Optional[str],
    header_user: Optional[str],
    banking: BankingService,
) -> Tuple[Optional[str], List[str], List[str]]:
    """Resolve the demo sender identity.

    Returns ``(sender, validation_errors, signals)``. ``sender`` is None when
    identity is missing, unknown, or the two selectors conflict.
    """
    body = _norm_selector(user_id)
    header = _norm_selector(header_user)

    # Header values bypass Pydantic, so enforce selector length here too.
    if (body and len(body) > 64) or (header and len(header) > 64):
        return None, ["demo identity selector exceeds the size limit"], [
            "identity_selector_too_long"
        ]

    if body and header and body != header:
        return None, ["user_id and X-Demo-User disagree (identity conflict)"], [
            "identity_source_conflict"
        ]
    sender = body or header
    if not sender:
        return None, ["no demo identity provided (user_id or X-Demo-User required)"], [
            "identity_missing"
        ]
    if not banking.user_exists(sender):
        return None, ["unknown demo identity"], ["identity_unknown"]
    return sender, [], []


# --------------------------------------------------------------------------- #
# Deterministic parsing (message only)
# --------------------------------------------------------------------------- #
_TRANSFER_VERB = re.compile(r"\b(send|transfer|pay|remit|wire)\b", re.IGNORECASE)
_BALANCE_KW = re.compile(r"\bbalance\b", re.IGNORECASE)
_SCI_NOTATION = re.compile(r"\d(?:\.\d+)?[eE][+-]?\d")
_NEGATIVE = re.compile(r"-\s*\d")
_AMBIGUOUS_SEP = re.compile(r"\d[\d,]*,\d")
_AMOUNT_TOKEN = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)(?![\w.])")

# Only INR is supported. Never silently reinterpret an explicitly stated
# foreign-currency amount (for example, "$500") as INR 500.
_FOREIGN_CURRENCY = re.compile(
    r"(?:[$€£¥]|\b(?:USD|US\s+dollars?|dollars?|EUR|euros?|GBP|pounds?|"
    r"AUD|Australian\s+dollars?|CAD|Canadian\s+dollars?|JPY|yen)\b)",
    re.IGNORECASE,
)

# Actions outside the deliberately small supported scope must not be ignored
# just because a message also contains a supported keyword such as "balance".
_UNSUPPORTED_ACTION = re.compile(
    r"\b(?:withdraw(?:al)?|deposit|invest(?:ment)?|buy|purchase|sell|trade|"
    r"close|open|delete|export|list|update|change|modify|reset|freeze|"
    r"unfreeze|borrow|loan|schedule|cancel|email|message)\b",
    re.IGNORECASE,
)
_NEGATED_TRANSFER = re.compile(
    r"\b(?:do\s+not|don't|dont|never|cancel|stop|not)\s+"
    r"(?:please\s+)?(?:actually\s+)?(?:send|transfer|pay|remit|wire)\b|"
    r"\b(?:do\s+not|don't|dont|never)\s+(?:actually\s+)?"
    r"(?:want|wish|need)\s+to\s+(?:send|transfer|pay|remit|wire)\b",
    re.IGNORECASE,
)

# Balance inquiries use bounded whole-message patterns. A stray occurrence of
# "balance" inside an unsupported or multi-intent request is not enough.
_BALANCE_QUERY = re.compile(
    r"^(?:please\s+)?(?:(?:can|could|would)\s+you\s+)?"
    r"(?:check|show|get|view|display|tell\s+me|what\s+is|what's|whats)\s+"
    r"(?:me\s+)?(?:(?:my|the)\s+)?(?:current\s+)?(?:account\s+)?"
    r"balance(?:\s+please)?[?.!]*$",
    re.IGNORECASE,
)

# Conservative allowlist for memo characters. Memos are data, not commands.
_MEMO_ALLOWED = re.compile(r"^[\w\s.,#()/'&:+\-]*$", re.UNICODE)

# Keep transfer parsing intentionally narrow: otherwise a lone number in a
# date ("transfer to Priya on 12 October") could be mistaken for the amount.
_AMOUNT_SHAPE = r"(?:(?:₹|INR\s+|Rs\.?\s*)?\d+(?:\.\d+)?(?:\s*(?:INR|rupees?))?)"
def _supported_transfer_syntax(message: str, sender: str, banking: BankingService) -> bool:
    """Match a narrow transfer grammar against this sender's known payees.

    Matching the recipient against the directory (rather than a generic name
    token) prevents trailing words like "tomorrow" from being mistaken for part
    of a recipient name while a nearby number is silently treated as the amount.
    """
    names = sorted(
        (entry["name"] for entry in banking.list_payees(sender).values()),
        key=len,
        reverse=True,
    )
    if not names:
        return False
    recipient = "(?:" + "|".join(re.escape(name) for name in names) + ")"
    shapes = (
        re.compile(rf"^\s*(?:please\s+)?(?:send|transfer|remit|wire)\s+{_AMOUNT_SHAPE}\s+to\s+{recipient}[.!?]?\s*$", re.IGNORECASE),
        re.compile(rf"^\s*(?:please\s+)?pay\s+{recipient}\s+{_AMOUNT_SHAPE}[.!?]?\s*$", re.IGNORECASE),
        re.compile(rf"^\s*(?:please\s+)?pay\s+{_AMOUNT_SHAPE}\s+to\s+{recipient}[.!?]?\s*$", re.IGNORECASE),
        re.compile(rf"^\s*(?:please\s+)?(?:send|transfer|remit|wire)\s+to\s+{recipient}\s+(?:amount\s+)?{_AMOUNT_SHAPE}[.!?]?\s*$", re.IGNORECASE),
    )
    return any(pattern.fullmatch(message) for pattern in shapes)


_DATA_READ_VERB = re.compile(
    r"\b(?:show|tell|get|give|fetch|read|display|reveal|retrieve|look\s+up|"
    r"list|access|download)\b",
    re.IGNORECASE,
)
_DATA_OBJECT = re.compile(
    r"\b(?:data|details|information|info|profile|address|email|phone|"
    r"transactions?|history|records?|account|balances?)\b",
    re.IGNORECASE,
)


def _extract_amount(message: str) -> Tuple[Optional[Decimal], List[str]]:
    """Extract exactly one valid Decimal amount, or explain why not."""
    if _SCI_NOTATION.search(message):
        return None, ["amount must not use scientific notation"]
    if _NEGATIVE.search(message):
        return None, ["amount must be positive"]
    if _AMBIGUOUS_SEP.search(message):
        return None, ["amount uses ambiguous separators"]

    tokens = _AMOUNT_TOKEN.findall(message)
    if not tokens:
        return None, ["amount is missing"]
    if len(set(tokens)) > 1:
        return None, ["amount is ambiguous (multiple numbers found)"]

    try:
        amount = Decimal(tokens[0])
    except InvalidOperation:
        return None, ["amount is invalid"]

    if not amount.is_finite() or amount.is_nan():
        return None, ["amount is invalid"]
    if amount <= 0:
        return None, ["amount must be greater than zero"]
    if amount.as_tuple().exponent < -2:
        return None, ["amount must have at most 2 decimal places"]
    if amount > MAX_TRANSACTION_AMOUNT:
        return None, ["amount exceeds the per-transaction cap"]
    return amount, []


def _extract_recipient(
    message: str, sender: str, banking: BankingService
) -> Tuple[Optional[Dict[str, str]], List[str]]:
    """Match exactly one known payee for the sender."""
    payees = banking.list_payees(sender)
    lowered = message.lower()
    matches: List[Dict[str, str]] = []
    for name, payee in payees.items():
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", lowered):
            matches.append(payee)

    if len(matches) == 1:
        return matches[0], []
    if not matches:
        return None, ["recipient is missing or not a known payee"]
    return None, ["recipient is ambiguous (multiple known payees matched)"]


def _mentions_other_user(message: str, sender: str, banking: BankingService) -> bool:
    lowered = message.lower()
    for uid, display in banking.users().items():
        if uid == sender:
            continue
        for token in {uid, display.lower()}:
            if re.search(rf"(?<!\w){re.escape(token)}(?!\w)", lowered):
                return True
    return False


# --------------------------------------------------------------------------- #
# Firewall
# --------------------------------------------------------------------------- #
class Firewall:
    """Stateless decision engine. Holds only injected collaborators."""

    def __init__(self, banking: BankingService, analyzer: ThreatAnalyzer) -> None:
        self.banking = banking
        self.analyzer = analyzer

    # -- public API ------------------------------------------------------- #
    def evaluate(
        self,
        message: str,
        memo: Optional[str],
        user_id: Optional[str],
        header_user: Optional[str],
    ) -> Verdict:
        """Return a verdict. Never raises; fails closed to BLOCK."""
        request_id = "req-" + uuid.uuid4().hex
        try:
            return self._evaluate(request_id, message, memo, user_id, header_user)
        except AnalyzerError:
            return _block(
                request_id,
                ThreatCategory.VALIDATION_FAILURE,
                RiskLevel.HIGH,
                Intent.NONE,
                signals=["analyzer_failure"],
                errors=["security analysis failed validation"],
                rationale="Security analysis could not be validated; failing closed.",
            )
        except Exception:  # noqa: BLE001 - fail closed on ANY unexpected error
            return _block(
                request_id,
                ThreatCategory.VALIDATION_FAILURE,
                RiskLevel.CRITICAL,
                Intent.NONE,
                signals=["internal_error"],
                errors=["internal evaluation error"],
                rationale="Internal evaluation error; failing closed.",
            )

    # -- internals -------------------------------------------------------- #
    def _evaluate(
        self,
        request_id: str,
        message: str,
        memo: Optional[str],
        user_id: Optional[str],
        header_user: Optional[str],
    ) -> Verdict:
        # 1. Resolve identity, but do not short-circuit threat inspection. When
        # identity and a security threat both fail, return the most severe threat
        # and retain the identity conflict among the signals/errors.
        sender, id_errors, id_signals = resolve_identity(
            user_id, header_user, self.banking
        )

        # Check raw lengths BEFORE normalization/decoding so direct callers
        # cannot force expensive work on oversized values.
        if not isinstance(message, str) or len(message) > 500:
            return _block(
                request_id, ThreatCategory.VALIDATION_FAILURE, RiskLevel.MEDIUM,
                Intent.NONE, signals=["oversized_message"],
                errors=["message exceeds the size limit"],
                rationale=_RATIONALES[ThreatCategory.VALIDATION_FAILURE],
            )
        if memo is not None and (not isinstance(memo, str) or len(memo) > MEMO_MAX_LEN):
            return _block(
                request_id, ThreatCategory.VALIDATION_FAILURE, RiskLevel.MEDIUM,
                Intent.NONE, signals=["oversized_memo"],
                errors=["memo exceeds the size limit or has an invalid type"],
                rationale=_RATIONALES[ThreatCategory.VALIDATION_FAILURE],
            )

        clean_message = clean_text(message)
        clean_memo = clean_text(memo) if memo is not None else None

        # 2. Analyze cleaned message and memo, plus bounded decoded variants.
        signals: Set[str] = set()
        categories: Set[ThreatCategory] = set()

        msg_candidates, msg_labels = build_candidates(clean_message)
        msg_found, msg_signals = self._scan(self.analyzer, msg_candidates)
        signals |= msg_signals
        for cats in msg_found.values():
            categories |= cats
        msg_attack_labels = {label for label, cats in msg_found.items() if cats}

        memo_attack = False
        memo_labels: Set[str] = set()
        memo_attack_labels: Set[str] = set()
        if clean_memo:
            memo_candidates, memo_labels = build_candidates(clean_memo)
            memo_found, memo_signals = self._scan(self.analyzer, memo_candidates)
            signals |= memo_signals
            memo_attack = any(cats for cats in memo_found.values())
            memo_attack_labels = {label for label, cats in memo_found.items() if cats}
            # A memo is data, so any attack found in it is classified as
            # MEMO_INJECTION regardless of which pattern matched.
            if memo_attack:
                categories.add(ThreatCategory.MEMO_INJECTION)
                signals.add("memo_contains_attack_instructions")

        # 3. Obfuscation is a signal on its own, even if content looks harmless.
        obf_signals = _obfuscation_signals(
            message,
            memo,
            msg_labels | memo_labels,
            msg_attack_labels | memo_attack_labels,
        )
        if obf_signals:
            signals |= obf_signals
            categories.add(ThreatCategory.OBFUSCATION)

        # 4. Deterministic parse of the cleaned message. Do not parse or approve
        # transaction details when the demo identity cannot be established.
        if sender is None:
            intent, details = Intent.NONE, None
            parse_errors = list(id_errors)
            parse_categories = {ThreatCategory.VALIDATION_FAILURE}
            parse_signals = set(id_signals)
        else:
            intent, details, parse_errors, parse_categories, parse_signals = self._parse(
                clean_message, clean_memo, sender
            )
        signals |= parse_signals
        categories |= parse_categories

        # Memo content has a small allowlist. Any disallowed character causes a
        # validation block; threat findings still take precedence below.
        if clean_memo is not None and not _MEMO_ALLOWED.fullmatch(clean_memo):
            parse_errors.append("memo contains unsupported characters")
            parse_categories.add(ThreatCategory.VALIDATION_FAILURE)
            signals.add("memo_character_validation_failed")

        # 5. Decide. Security threats outrank parse/validation outcomes.
        security = {c for c in categories if c in _SECURITY_CATEGORIES}
        if security:
            top = max(security, key=severity_of)
            return _block(
                request_id,
                top,
                risk_level_for(top),
                intent,
                signals=sorted(signals),
                errors=sorted(set(parse_errors)),
                rationale=_RATIONALES[top],
            )

        if ThreatCategory.UNSUPPORTED_OPERATION in categories:
            return _block(
                request_id,
                ThreatCategory.UNSUPPORTED_OPERATION,
                risk_level_for(ThreatCategory.UNSUPPORTED_OPERATION),
                Intent.UNSUPPORTED,
                signals=sorted(signals),
                errors=sorted(set(parse_errors)),
                rationale=_RATIONALES[ThreatCategory.UNSUPPORTED_OPERATION],
            )

        if ThreatCategory.VALIDATION_FAILURE in categories or parse_errors:
            return _block(
                request_id,
                ThreatCategory.VALIDATION_FAILURE,
                risk_level_for(ThreatCategory.VALIDATION_FAILURE),
                intent,
                signals=sorted(signals),
                errors=sorted(set(parse_errors)),
                rationale=_RATIONALES[ThreatCategory.VALIDATION_FAILURE],
            )

        # Approved: only balance inquiry or a fully-specified known-payee transfer.
        if intent == Intent.TRANSFER and details is not None:
            rationale = "Transfer to a known payee within limits; approved."
        else:
            rationale = "Balance inquiry for the caller's own account; approved."
        return Verdict(
            request_id=request_id,
            decision=Decision.APPROVE,
            risk_level=RiskLevel.LOW,
            threat_category=ThreatCategory.NONE,
            rationale=rationale,
            intent=intent,
            transaction_details=details,
            validation_errors=[],
            signals=sorted(signals),
        )

    # -- helpers ---------------------------------------------------------- #
    def _scan(
        self, analyzer: ThreatAnalyzer, candidates: Sequence[Tuple[str, str]]
    ) -> Tuple[Dict[str, Set[ThreatCategory]], Set[str]]:
        """Run the (validated) analyzer over each candidate."""
        found: Dict[str, Set[ThreatCategory]] = {}
        signals: Set[str] = set()
        for text, label in candidates:
            result = _analyze_safe(analyzer, text)
            signals |= set(result.signals)
            cats = set(result.categories)
            if result.threat_category != ThreatCategory.NONE:
                cats.add(result.threat_category)
            if cats:
                found.setdefault(label, set()).update(cats)
        return found, signals

    def _parse(
        self, message: str, memo: Optional[str], sender: str
    ) -> Tuple[Intent, Optional[TransactionDetails], List[str], Set[ThreatCategory], Set[str]]:
        """Return (intent, details, errors, categories, signals)."""
        errors: List[str] = []
        categories: Set[ThreatCategory] = set()
        signals: Set[str] = set()

        transfer_matches = list(_TRANSFER_VERB.finditer(message))
        has_transfer = bool(transfer_matches)
        has_balance = bool(_BALANCE_KW.search(message))

        # Do not downgrade requests for another named user's non-balance data
        # to a generic unsupported operation. They are attempted exfiltration.
        if (
            _mentions_other_user(message, sender, self.banking)
            and _DATA_READ_VERB.search(message)
            and _DATA_OBJECT.search(message)
        ):
            return (
                Intent.UNSUPPORTED,
                None,
                ["request references data belonging to another demo user"],
                {ThreatCategory.DATA_EXFILTRATION},
                {"other_user_data_reference"},
            )

        if has_transfer and has_balance:
            # Multi-intent requests are never guessed at.
            return (
                Intent.UNSUPPORTED,
                None,
                ["multiple intents detected; send one request per action"],
                {ThreatCategory.UNSUPPORTED_OPERATION},
                {"multi_intent_request"},
            )

        if has_transfer and len(transfer_matches) > 1:
            return (
                Intent.UNSUPPORTED,
                None,
                ["multiple action verbs detected; send one request per action"],
                {ThreatCategory.UNSUPPORTED_OPERATION},
                {"multiple_transfer_verbs"},
            )

        if has_transfer and _NEGATED_TRANSFER.search(message):
            return (
                Intent.UNSUPPORTED,
                None,
                ["negated or cancelled transfer requests cannot be executed"],
                {ThreatCategory.UNSUPPORTED_OPERATION},
                {"negated_transfer_intent"},
            )

        if _UNSUPPORTED_ACTION.search(message):
            return (
                Intent.UNSUPPORTED,
                None,
                ["unsupported or additional operation detected"],
                {ThreatCategory.UNSUPPORTED_OPERATION},
                {"unsupported_operation_present"},
            )

        if has_transfer:
            return self._parse_transfer(message, memo, sender)

        if has_balance:
            if _mentions_other_user(message, sender, self.banking):
                return (
                    Intent.BALANCE_INQUIRY,
                    None,
                    ["balance request references another user"],
                    {ThreatCategory.DATA_EXFILTRATION},
                    {"other_user_reference"},
                )
            if not _BALANCE_QUERY.fullmatch(message):
                return (
                    Intent.UNSUPPORTED,
                    None,
                    ["request is not a supported standalone balance inquiry"],
                    {ThreatCategory.UNSUPPORTED_OPERATION},
                    {"unsupported_balance_phrase"},
                )
            return Intent.BALANCE_INQUIRY, None, [], set(), set()

        # Neither supported intent was found.
        return (
            Intent.UNSUPPORTED,
            None,
            ["unsupported operation; only balance inquiry and transfer are supported"],
            {ThreatCategory.UNSUPPORTED_OPERATION},
            {"unsupported_operation"},
        )

    def _parse_transfer(
        self, message: str, memo: Optional[str], sender: str
    ) -> Tuple[Intent, Optional[TransactionDetails], List[str], Set[ThreatCategory], Set[str]]:
        if _FOREIGN_CURRENCY.search(message):
            return (
                Intent.TRANSFER,
                None,
                ["only INR currency is supported"],
                {ThreatCategory.VALIDATION_FAILURE},
                {"unsupported_currency"},
            )

        amount, amount_errors = _extract_amount(message)
        payee, recipient_errors = _extract_recipient(message, sender, self.banking)
        errors = amount_errors + recipient_errors

        if errors:
            return (
                Intent.TRANSFER,
                None,
                errors,
                {ThreatCategory.VALIDATION_FAILURE},
                {"transfer_validation_failed"},
            )

        if not _supported_transfer_syntax(message, sender, self.banking):
            return (
                Intent.TRANSFER,
                None,
                ["transfer wording is ambiguous or outside supported patterns"],
                {ThreatCategory.VALIDATION_FAILURE},
                {"ambiguous_transfer_syntax"},
            )

        # Firewall-side balance / cap check (banking re-checks independently).
        balance = self.banking.get_balance(sender)
        if amount > balance:
            return (
                Intent.TRANSFER,
                None,
                ["insufficient funds"],
                {ThreatCategory.VALIDATION_FAILURE},
                {"insufficient_funds"},
            )

        details = TransactionDetails(
            recipient=payee["name"],
            amount=str(amount.quantize(Decimal("0.01"))),
            currency=CURRENCY,
            memo=memo,
        )
        return Intent.TRANSFER, details, [], set(), set()


# --------------------------------------------------------------------------- #
# Verdict builders
# --------------------------------------------------------------------------- #
def _block(
    request_id: str,
    category: ThreatCategory,
    risk: RiskLevel,
    intent: Intent,
    signals: List[str],
    errors: List[str],
    rationale: str,
) -> Verdict:
    return Verdict(
        request_id=request_id,
        decision=Decision.BLOCK,
        risk_level=risk,
        threat_category=category,
        rationale=rationale,
        intent=intent,
        transaction_details=None,
        validation_errors=list(errors),
        signals=list(signals),
    )
