# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.2 — PII detection and redaction tests.

Covers the regex-based fallback path (no spaCy/Presidio required in CI):
  - Email, phone, credit card detection and masking via anonymize_text_regex()
  - Luhn checksum validation for credit cards (luhn_ok)
  - False-positive suppression (is_false_positive)
  - Regex patterns for API key and JWT formats
"""

import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# anonymize_text_regex — pure regex path (USE_PRESIDIO=False)
# ---------------------------------------------------------------------------


class TestEmailRedaction:
    def _redact(self, text):
        from app.policies import anonymize_text_regex
        return anonymize_text_regex(text)

    def test_email_detected(self):
        _, reasons = self._redact("Contact us at alice@example.com for help")
        assert any("email" in r for r in reasons)

    def test_email_redacted_from_output(self):
        redacted, _ = self._redact("Email: bob@company.org")
        assert "bob@company.org" not in redacted

    def test_multiple_emails_redacted(self):
        text = "From: a@x.com To: b@y.co"
        redacted, reasons = self._redact(text)
        assert "a@x.com" not in redacted
        assert "b@y.co" not in redacted

    def test_no_email_no_reason(self):
        _, reasons = self._redact("The sky is blue today.")
        assert not any("email" in r for r in reasons)


class TestPhoneRedaction:
    def _redact(self, text):
        from app.policies import anonymize_text_regex
        return anonymize_text_regex(text)

    def test_phone_dashes_detected(self):
        _, reasons = self._redact("Call 555-867-5309 for details")
        assert any("phone" in r for r in reasons)

    def test_phone_dots_detected(self):
        _, reasons = self._redact("Reach us at 415.555.1234")
        assert any("phone" in r for r in reasons)

    def test_phone_redacted_from_output(self):
        redacted, _ = self._redact("Phone: 555-867-5309")
        assert "5309" not in redacted or "*" in redacted


class TestCreditCardRedaction:
    def _redact(self, text):
        from app.policies import anonymize_text_regex
        return anonymize_text_regex(text)

    def test_valid_luhn_card_detected(self):
        # 4532015112830366 is a valid test Visa number (Luhn-valid)
        _, reasons = self._redact("Card: 4532015112830366")
        assert any("card" in r for r in reasons)

    def test_invalid_luhn_card_not_detected(self):
        # 1234567890123456 fails Luhn check
        _, reasons = self._redact("Not a card: 1234567890123456")
        assert not any("card" in r for r in reasons)

    def test_card_with_spaces_detected(self):
        # 4532 0151 1283 0366 — valid Visa with spaces
        _, reasons = self._redact("4532 0151 1283 0366")
        assert any("card" in r for r in reasons)


# ---------------------------------------------------------------------------
# luhn_ok — credit card checksum
# ---------------------------------------------------------------------------


class TestLuhnOk:
    def test_valid_visa(self):
        from app.policies import luhn_ok
        assert luhn_ok("4532015112830366") is True

    def test_valid_mastercard(self):
        from app.policies import luhn_ok
        assert luhn_ok("5425233430109903") is True

    def test_invalid_number(self):
        from app.policies import luhn_ok
        assert luhn_ok("1234567890123456") is False

    def test_all_zeros_invalid(self):
        from app.policies import luhn_ok
        assert luhn_ok("0000000000000000") is False

    def test_single_digit_invalid(self):
        from app.policies import luhn_ok
        assert luhn_ok("0") is False


# ---------------------------------------------------------------------------
# is_false_positive — SSN suppression in password fields
# ---------------------------------------------------------------------------


class TestFalsePositive:
    def test_ssn_in_password_field_is_false_positive(self):
        from app.policies import is_false_positive
        assert is_false_positive("US_SSN", "password", "123-45-6789") is True

    def test_ssn_in_ssn_field_is_not_false_positive(self):
        from app.policies import is_false_positive
        assert is_false_positive("US_SSN", "social_security_number", "123-45-6789") is False

    def test_non_ssn_entity_not_suppressed(self):
        from app.policies import is_false_positive
        assert is_false_positive("EMAIL_ADDRESS", "email", "test@example.com") is False

    def test_ssn_all_same_digit_is_false_positive(self):
        from app.policies import is_false_positive
        # 111111111 — all same digit
        assert is_false_positive("US_SSN", "", "111111111") is True


# ---------------------------------------------------------------------------
# API key and JWT regex patterns
# ---------------------------------------------------------------------------


class TestApiKeyPattern:
    """Verify custom recognizer patterns match expected formats."""

    def test_openai_sk_key_matches(self):
        import re
        pattern = r"(?:sk|pk|AKIA|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,40}"
        assert re.search(pattern, "sk_test_abcdefghij1234567890") is not None

    def test_aws_akia_key_matches(self):
        import re
        pattern = r"(?:sk|pk|AKIA|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,40}"
        assert re.search(pattern, "AKIA_abc123def456ghi789") is not None

    def test_github_pat_matches(self):
        import re
        pattern = r"(?:sk|pk|AKIA|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,40}"
        assert re.search(pattern, "ghp_ABCDEFGHIJKLMNOPabcdefgh1234") is not None

    def test_random_word_does_not_match(self):
        import re
        pattern = r"(?:sk|pk|AKIA|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,40}"
        assert re.search(pattern, "hello world") is None


class TestJwtPattern:
    def test_jwt_format_matches(self):
        import re
        pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
        sample = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert re.search(pattern, sample) is not None

    def test_non_jwt_does_not_match(self):
        import re
        pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
        assert re.search(pattern, "Bearer some_opaque_token") is None


# ---------------------------------------------------------------------------
# entity_type_to_placeholder
# ---------------------------------------------------------------------------


class TestPlaceholders:
    def test_email_placeholder(self):
        from app.policies import entity_type_to_placeholder
        assert entity_type_to_placeholder("EMAIL_ADDRESS") == "[REDACTED_EMAIL]"

    def test_ssn_placeholder(self):
        from app.policies import entity_type_to_placeholder
        assert entity_type_to_placeholder("US_SSN") == "[REDACTED_SSN]"

    def test_api_key_placeholder(self):
        from app.policies import entity_type_to_placeholder
        assert entity_type_to_placeholder("API_KEY") == "[REDACTED_API_KEY]"

    def test_jwt_placeholder(self):
        from app.policies import entity_type_to_placeholder
        assert entity_type_to_placeholder("JWT_TOKEN") == "[REDACTED_JWT]"

    def test_unknown_type_has_sensible_default(self):
        from app.policies import entity_type_to_placeholder
        result = entity_type_to_placeholder("UNKNOWN_ENTITY")
        assert result.startswith("[")
