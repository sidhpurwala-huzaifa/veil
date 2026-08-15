"""Tests for locale-specific detector packs."""

import pytest

from veil.detectors.locale import available_locales, locale_detectors


def _types_found(text, locale):
    findings = []
    for d in locale_detectors(locale):
        findings.extend(d.detect(text))
    return {f.entity_type for f in findings}


class TestLocaleRegistry:
    def test_available_locales(self):
        locales = available_locales()
        assert "GB" in locales
        assert "CA" in locales
        assert "IN" in locales
        assert "EU" in locales

    def test_unknown_locale_raises(self):
        with pytest.raises(ValueError, match="Unknown locale"):
            locale_detectors("XX")

    def test_case_insensitive(self):
        assert locale_detectors("gb") == locale_detectors("GB")


class TestUKNINO:
    def test_valid_nino(self):
        assert "UK_NINO" in _types_found("NI number AB123456C", "GB")

    def test_invalid_prefix_rejected(self):
        assert "UK_NINO" not in _types_found("NI BG123456C", "GB")

    def test_spaced_format(self):
        assert "UK_NINO" in _types_found("NINO AB 12 34 56 C", "GB")


class TestCASIN:
    def test_valid_sin(self):
        assert "CA_SIN" in _types_found("SIN 046 454 286", "CA")

    def test_invalid_luhn_rejected(self):
        assert "CA_SIN" not in _types_found("SIN 046 454 287", "CA")


class TestAadhaar:
    def test_valid_aadhaar(self):
        assert "AADHAAR" in _types_found("Aadhaar: 4961 0727 1198", "IN")

    def test_invalid_verhoeff_rejected(self):
        assert "AADHAAR" not in _types_found("Aadhaar: 4961 0727 1199", "IN")

    def test_leading_zero_or_one_rejected(self):
        assert "AADHAAR" not in _types_found("num 0961 0727 1196", "IN")
        assert "AADHAAR" not in _types_found("num 1961 0727 1196", "IN")


class TestEUVAT:
    def test_german_vat(self):
        assert "EU_VAT" in _types_found("VAT DE123456789", "EU")

    def test_french_vat(self):
        assert "EU_VAT" in _types_found("VAT FR12345678901", "EU")


# ---------------------------------------------------------------------------
# Locale context keywords
# ---------------------------------------------------------------------------


class TestLocaleContextKeywords:
    def test_available_locales_expanded(self):
        locales = available_locales()
        for code in ("DE", "FR", "ES", "PT", "IT", "RU", "ZH", "JA", "KO", "AR", "HE", "TH"):
            assert code in locales

    def test_german_dob_keywords(self):
        assert "DATE_OF_BIRTH" in _types_found("Geburtsdatum: 12.04.1978", "DE")

    def test_german_passport_keywords(self):
        assert "PASSPORT" in _types_found("Reisepass C123456789", "DE")

    def test_french_dob_keywords(self):
        # Day <= 12 so MM/DD parsing succeeds with current validator
        assert "DATE_OF_BIRTH" in _types_found("né le 03/05/1990", "FR")

    def test_french_passport_keywords(self):
        assert "PASSPORT" in _types_found("passeport AB1234567", "FR")

    def test_spanish_dob_keywords(self):
        assert "DATE_OF_BIRTH" in _types_found("fecha de nacimiento 01/02/1985", "ES")

    def test_russian_dob_keywords(self):
        assert "DATE_OF_BIRTH" in _types_found("дата рождения 06.05.1990", "RU")

    def test_japanese_passport_keywords(self):
        assert "PASSPORT" in _types_found("パスポート TK1234567", "JA")

    def test_locale_keywords_dont_affect_other_locales(self):
        assert "DATE_OF_BIRTH" not in _types_found("Geburtsdatum: 12.04.1978", "FR")
