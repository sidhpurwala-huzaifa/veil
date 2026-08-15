"""Tests for ContextBooster keyword-proximity confidence scoring."""

from pytest import approx

from veil.detectors.base import RegexDetector
from veil.detectors.context import ContextBooster


def _make_booster(confidence=0.45, boost=0.40, window=80, require_context=True):
    inner = RegexDetector("TEST_ENTITY", r"\b\d{4}-\d{4}\b", confidence=confidence)
    return ContextBooster(
        inner,
        keywords=["account", "id number"],
        boost=boost,
        window=window,
        require_context=require_context,
    )


class TestContextBooster:
    def test_boost_when_keyword_present(self):
        b = _make_booster()
        findings = b.detect("account 1234-5678")
        assert len(findings) == 1
        assert findings[0].confidence == approx(0.85)

    def test_dropped_without_keyword_when_required(self):
        b = _make_booster()
        findings = b.detect("value 1234-5678 here")
        assert findings == []

    def test_kept_without_keyword_when_not_required(self):
        b = _make_booster(require_context=False)
        findings = b.detect("value 1234-5678 here")
        assert len(findings) == 1
        assert findings[0].confidence == 0.45  # no boost

    def test_keyword_case_insensitive(self):
        b = _make_booster()
        findings = b.detect("ACCOUNT 1234-5678")
        assert len(findings) == 1

    def test_keyword_outside_window_dropped(self):
        b = _make_booster(window=5)
        text = "account " + "x" * 20 + " 1234-5678"
        findings = b.detect(text)
        assert findings == []

    def test_keyword_within_window_boosted(self):
        b = _make_booster(window=50)
        text = "account " + "x" * 10 + " 1234-5678"
        findings = b.detect(text)
        assert len(findings) == 1
        assert findings[0].confidence == approx(0.85)

    def test_confidence_clamped_at_one(self):
        b = _make_booster(confidence=0.80, boost=0.50)
        findings = b.detect("account 1234-5678")
        assert findings[0].confidence == 1.0

    def test_name_delegates_to_inner(self):
        b = _make_booster()
        assert b.name == "regex:test_entity"

    def test_multi_keyword_match(self):
        b = _make_booster()
        findings = b.detect("id number 1234-5678")
        assert len(findings) == 1
        assert findings[0].confidence == approx(0.85)
