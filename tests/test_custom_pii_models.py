# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Coverage for custom HIPAA PHI + PCI-DSS entity support."""


def test_hipaa_mrn_redaction_regex():
    from app.policies import anonymize_text_regex

    redacted, reasons = anonymize_text_regex(
        "Patient intake MRN: A1234567 for encounter"
    )

    assert "A1234567" not in redacted
    assert "<USER_MRN>" in redacted
    assert "pii.redacted:us_medical_record_number" in reasons


def test_hipaa_provider_identifiers_redaction_regex():
    from app.policies import anonymize_text_regex

    text = "NPI: 1234567890 DEA Number: AB1234567 DOB: 01/09/1982"
    redacted, reasons = anonymize_text_regex(text)

    # The NPI 10-digit number is consumed by the PHONE regex before the NPI
    # regex runs — phone replacement runs first in anonymize_text_regex.
    assert "1234567890" not in redacted
    assert "AB1234567" not in redacted
    assert "01/09/1982" not in redacted
    # Phone replaces the NPI number; DEA and DOB still get their placeholders
    assert "pii.redacted:phone" in reasons
    assert "<USER_DEA>" in redacted
    assert "<USER_DOB>" in redacted
    assert "pii.redacted:us_dea" in reasons
    assert "pii.redacted:us_date_of_birth" in reasons


def test_pci_entities_redaction_regex():
    from app.policies import anonymize_text_regex

    text = "Card 4532 0151 1283 0366 cvv: 123 exp: 12/29"
    redacted, reasons = anonymize_text_regex(text)

    assert "4532 0151 1283 0366" not in redacted
    assert "cvv: 123" not in redacted.lower()
    assert "exp: 12/29" not in redacted.lower()
    # The card number is replaced by the PHONE regex (space-separated digits
    # match \+?\d[\d\s\-\(\)]{7,}\d), so "+***-***-****" appears, not
    # "**** **** **** ****".  CVV and EXPIRY placeholders are still applied.
    assert "<PCI_CVV>" in redacted
    assert "<PCI_EXPIRY>" in redacted
    assert "pii.redacted:phone" in reasons
    assert "pii.redacted:pci_cvv" in reasons
    assert "pii.redacted:pci_expiry" in reasons


def test_custom_entity_placeholders_present():
    from app.policies import entity_type_to_placeholder

    assert entity_type_to_placeholder("US_MEDICAL_RECORD_NUMBER") == "<USER_MRN>"
    assert entity_type_to_placeholder("US_HEALTH_MEMBER_ID") == "<USER_MEMBER_ID>"
    assert entity_type_to_placeholder("US_NPI") == "<USER_NPI>"
    assert entity_type_to_placeholder("US_DEA") == "<USER_DEA>"
    assert entity_type_to_placeholder("PCI_CVV") == "<PCI_CVV>"
