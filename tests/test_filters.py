"""Tests for FilteredDetector and Scrubber allowlist integration."""

import re

from veil import Scrubber
from veil.detectors.base import RegexDetector
from veil.detectors.filters import FilteredDetector


def _email_detector():
    return RegexDetector("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", confidence=0.95)


class TestFilteredDetector:
    def test_allowlist_exact_match(self):
        fd = FilteredDetector(_email_detector(), allowlist={"test@example.com"})
        findings = fd.detect("contact test@example.com today")
        assert findings == []

    def test_allowlist_does_not_drop_others(self):
        fd = FilteredDetector(_email_detector(), allowlist={"test@example.com"})
        findings = fd.detect("contact real@company.com today")
        assert len(findings) == 1
        assert findings[0].text == "real@company.com"

    def test_allowlist_pattern(self):
        fd = FilteredDetector(
            _email_detector(),
            allowlist_patterns=[re.compile(r".*@mycompany\.com")],
        )
        findings = fd.detect("user alice@mycompany.com and bob@other.com")
        assert len(findings) == 1
        assert findings[0].text == "bob@other.com"

    def test_name_delegates(self):
        fd = FilteredDetector(_email_detector())
        assert fd.name == "regex:email"

    def test_no_filters_passes_through(self):
        fd = FilteredDetector(_email_detector())
        findings = fd.detect("mail me@here.org")
        assert len(findings) == 1


class TestScrubberAllowlist:
    def test_allowlist_skips_value(self):
        scrubber = Scrubber(allowlist={"test@example.com"})
        result = scrubber.scrub("contact test@example.com and real@company.com")
        assert "test@example.com" in result.text
        assert "real@company.com" not in result.text

    def test_allowlist_pattern_skips_domain(self):
        scrubber = Scrubber(
            allowlist_patterns=[re.compile(r".*@safe\.org")],
        )
        result = scrubber.scrub("info@safe.org and secret@other.com")
        assert "info@safe.org" in result.text
        assert "secret@other.com" not in result.text

    def test_no_allowlist_scrubs_all(self):
        scrubber = Scrubber()
        result = scrubber.scrub("send to admin@example.com")
        assert "admin@example.com" not in result.text
