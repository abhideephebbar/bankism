"""Dictionary-based threat detection for Bankism.

This module is the EASY place to tune detection: it is plain word and phrase
lists, grouped by threat category. The heuristic analyzer scans folded text
against these lists in addition to its regex patterns, so adding an entry here
never weakens existing detection — it only adds signals.

Conventions
-----------
* Text is matched in "folded" form (lowercase, NFKC, homoglyphs/leet mapped,
  punctuation turned into spaces), so list entries must be lowercase words and
  space-separated phrases only.
* ``BLOCKED_PHRASES`` match as substrings of the folded text.
* ``BLOCKED_WORDS`` match as whole words (tokens).
* ``BENIGN_WORDS`` is an allowlist reference: these words must never appear in
  any blocked list. A test enforces that, so plain banking vocabulary
  ("rupees", "rent", "balance", payee names, ...) cannot be blocked by mistake.

Not claimed to be complete detection — same honesty as the pattern layer.
"""

from __future__ import annotations

from typing import Dict, Set

from .schemas import ThreatCategory

#: Multi-word phrases, per category. Matched as substrings of folded text.
BLOCKED_PHRASES: Dict[ThreatCategory, Set[str]] = {
    ThreatCategory.PROMPT_INJECTION: {
        "ignore previous instructions",
        "ignore all instructions",
        "ignore the instructions",
        "ignore your instructions",
        "disregard previous instructions",
        "disregard all instructions",
        "forget previous instructions",
        "forget all instructions",
        "reveal system prompt",
        "reveal the system prompt",
        "reveal your instructions",
        "system prompt",
        "new instructions",
        "override the instructions",
        "do not follow",
    },
    ThreatCategory.ROLEPLAY_JAILBREAK: {
        "developer mode",
        "no rules",
        "no restrictions",
        "no limits",
        "without restrictions",
        "pretend you are",
        "act as if you",
        "roleplay",
        "do anything now",
        "simulate being",
    },
    ThreatCategory.POLICY_OVERRIDE: {
        "override security",
        "bypass security",
        "disable security",
        "ignore security",
        "ignore safety",
        "skip approval",
        "skip verification",
        "approve this transfer",
        "approve this transaction",
        "approve this payment",
        "raise the limit",
        "remove the limit",
        "no need approval",
        "no need verification",
        "without approval",
    },
    ThreatCategory.DATA_EXFILTRATION: {
        "bank details",
        "account details",
        "bank account details",
        "account number",
        "account numbers",
        "confidential data",
        "confidential information",
        "reveal bank",
        "extract account",
        "expose financial",
        "disclose banking",
        "disclose financial",
        "customer data",
        "customer information",
        "user data",
        "list all accounts",
        "all account balances",
    },
    ThreatCategory.OBFUSCATION: {
        # NOTE: entries must be in FOLDED form (fold_text maps leet digits):
        # "base64" folds to "base6a", "rot13" folds to "rotie".
        "base6a",
        "rotie",
        "hex encoded",
        "zero width",
        "homoglyph",
        "hidden characters",
    },
}

#: High-signal single words, per category. Matched as whole tokens only.
BLOCKED_WORDS: Dict[ThreatCategory, Set[str]] = {
    ThreatCategory.ROLEPLAY_JAILBREAK: {
        "jailbreak",
        "unrestricted",
    },
    ThreatCategory.DATA_EXFILTRATION: {
        "credentials",
        "passwords",
        "exfiltrate",
    },
}

#: Benign banking/daily vocabulary. Must stay disjoint from every blocked
#: list; a test enforces this. Extend freely — this is the "unblocked words"
#: dictionary.
BENIGN_WORDS: Set[str] = {
    "rupee",
    "rupees",
    "inr",
    "rent",
    "dinner",
    "split",
    "balance",
    "salary",
    "groceries",
    "october",
    "invoice",
    "gift",
    "family",
    "friend",
    "priya",
    "rahul",
    "meera",
    "arjun",
    "kiran",
    "deepa",
    "sana",
    "vikram",
}
