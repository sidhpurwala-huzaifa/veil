"""Tests for the Tier 2 NER detector.

These tests require spaCy and the ``en_core_web_sm`` model.  Skip the
entire module if either is missing so the Tier 1 test suite stays
zero-dependency.
"""

import pytest

spacy = pytest.importorskip("spacy", reason="spaCy not installed")

try:
    spacy.load("en_core_web_sm")
except OSError:
    pytest.skip("en_core_web_sm model not installed", allow_module_level=True)

from veil.detectors.ner import (
    DEFAULT_CONFIDENCE_MAP,
    DEFAULT_ENTITY_MAP,
    NerDetector,
    ner_detectors,
)
from veil.types import Finding


@pytest.fixture(scope="module")
def detector():
    return NerDetector()


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


class TestNerDetectorBasic:
    def test_finds_person_name(self, detector):
        findings = detector.detect("John Smith went to the store.")
        types = {f.entity_type for f in findings}
        assert "PERSON_NAME" in types

    def test_finds_organization(self, detector):
        findings = detector.detect("She works at Google in California.")
        types = {f.entity_type for f in findings}
        assert "ORGANIZATION" in types

    def test_finds_location(self, detector):
        findings = detector.detect("He traveled from London to Paris last summer.")
        types = {f.entity_type for f in findings}
        assert "LOCATION" in types

    def test_finds_norp_group(self, detector):
        findings = detector.detect("The French delegation arrived yesterday.")
        types = {f.entity_type for f in findings}
        assert "NORP_GROUP" in types

    def test_finds_date_time(self, detector):
        findings = detector.detect("The meeting is on January 15, 2025.")
        types = {f.entity_type for f in findings}
        assert "DATE_TIME" in types

    def test_empty_text(self, detector):
        assert detector.detect("") == []

    def test_no_entities(self, detector):
        findings = detector.detect("the quick brown fox")
        person_findings = [f for f in findings if f.entity_type == "PERSON_NAME"]
        assert person_findings == []

    def test_multiple_entities_one_pass(self, detector):
        text = "John Smith works at Microsoft in Seattle."
        findings = detector.detect(text)
        types = {f.entity_type for f in findings}
        assert len(types) >= 2


# ---------------------------------------------------------------------------
# Finding properties
# ---------------------------------------------------------------------------


class TestFindingProperties:
    def test_offsets_are_correct(self, detector):
        text = "Contact John Smith for details."
        findings = [f for f in detector.detect(text) if f.entity_type == "PERSON_NAME"]
        assert len(findings) >= 1
        f = findings[0]
        assert text[f.start : f.end] == f.text

    def test_confidence_matches_map(self, detector):
        findings = detector.detect("John Smith lives in London.")
        for f in findings:
            expected = DEFAULT_CONFIDENCE_MAP.get(f.entity_type)
            if expected is not None:
                assert f.confidence == expected

    def test_detector_name(self, detector):
        assert detector.name == "ner:en_core_web_sm"
        findings = detector.detect("John Smith")
        for f in findings:
            assert f.detector == "ner:en_core_web_sm"

    def test_finding_is_frozen(self, detector):
        findings = detector.detect("John Smith")
        if findings:
            with pytest.raises(AttributeError):
                findings[0].text = "modified"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestNerConfiguration:
    def test_custom_entity_map(self):
        custom_map = {"PERSON": "FULL_NAME"}
        det = NerDetector(entity_map=custom_map)
        findings = det.detect("John Smith went to London.")
        person_findings = [f for f in findings if f.entity_type == "FULL_NAME"]
        assert len(person_findings) >= 1
        loc_findings = [f for f in findings if f.entity_type == "LOCATION"]
        assert loc_findings == []

    def test_custom_confidence_map(self):
        det = NerDetector(confidence_map={"PERSON_NAME": 0.99, "LOCATION": 0.60})
        findings = det.detect("John Smith visited London.")
        for f in findings:
            if f.entity_type == "PERSON_NAME":
                assert f.confidence == 0.99
            elif f.entity_type == "LOCATION":
                assert f.confidence == 0.60

    def test_unmapped_spacy_labels_ignored(self, detector):
        findings = detector.detect("The total was $500 million.")
        types = {f.entity_type for f in findings}
        assert "MONEY" not in types


# ---------------------------------------------------------------------------
# ner_detectors() factory
# ---------------------------------------------------------------------------


class TestNerDetectorsFactory:
    def test_returns_list(self):
        result = ner_detectors()
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], NerDetector)

    def test_composable_with_default_detectors(self):
        from veil import default_detectors

        combined = default_detectors() + ner_detectors()
        assert len(combined) > len(default_detectors())

    def test_passes_kwargs(self):
        custom_map = {"PERSON": "NAME"}
        result = ner_detectors(entity_map=custom_map)
        assert result[0]._entity_map == custom_map


# ---------------------------------------------------------------------------
# Integration with Scrubber
# ---------------------------------------------------------------------------


class TestNerWithScrubber:
    def test_scrub_person_name(self):
        from veil import Scrubber, default_detectors

        scrubber = Scrubber(detectors=default_detectors() + ner_detectors())
        result = scrubber.scrub("Please contact John Smith about the project.")
        assert "John Smith" not in result.text
        assert "[PERSON_NAME_" in result.text

    def test_ner_does_not_break_tier1(self):
        from veil import Scrubber, default_detectors

        scrubber = Scrubber(detectors=default_detectors() + ner_detectors())
        result = scrubber.scrub("Email john.smith@acme.com for help.")
        assert "john.smith@acme.com" not in result.text
        assert "[EMAIL_" in result.text

    def test_rehydrate_roundtrip(self):
        from veil import Scrubber, default_detectors

        scrubber = Scrubber(detectors=default_detectors() + ner_detectors())
        original = "John Smith works at Google in London."
        result = scrubber.scrub(original)
        restored = scrubber.rehydrate(result.text, result.session)
        assert restored == original
