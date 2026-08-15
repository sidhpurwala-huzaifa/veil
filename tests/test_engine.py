import pytest

from veil import (
    Action,
    PIIBlockedError,
    Policy,
    RegexDetector,
    Rule,
    Scrubber,
    ScrubSession,
)


class TestScrubRehydrate:
    def test_round_trip(self):
        s = Scrubber()
        result = s.scrub("Email jane@acme.com about card 4111 1111 1111 1111.")
        assert "jane@acme.com" not in result.text
        assert "4111" not in result.text
        assert "[EMAIL_1]" in result.text
        assert "[CREDIT_CARD_1]" in result.text
        # model echoes tokens back; rehydrate restores originals
        assert s.rehydrate("I'll contact [EMAIL_1] now.", result.session) == "I'll contact jane@acme.com now."

    def test_deterministic_within_session(self):
        s = Scrubber()
        session = ScrubSession()
        r1 = s.scrub("mail jane@acme.com", session)
        r2 = s.scrub("again: jane@acme.com and bob@acme.com", session)
        assert "[EMAIL_1]" in r1.text
        assert "[EMAIL_1]" in r2.text and "[EMAIL_2]" in r2.text
        assert len(session) == 2

    def test_unknown_token_passthrough(self):
        s = Scrubber()
        session = ScrubSession()
        assert s.rehydrate("see [SECTION_2] below", session) == "see [SECTION_2] below"


class TestPolicy:
    def test_block_raises(self):
        policy = Policy({"CREDIT_CARD": Rule(Action.BLOCK)})
        s = Scrubber(policy=policy)
        with pytest.raises(PIIBlockedError) as exc:
            s.scrub("card 4111 1111 1111 1111")
        assert exc.value.findings[0].entity_type == "CREDIT_CARD"

    def test_mask_is_irreversible(self):
        policy = Policy({"EMAIL": Rule(Action.MASK)})
        s = Scrubber(policy=policy)
        result = s.scrub("mail jane@acme.com")
        assert "[REDACTED_EMAIL]" in result.text
        assert s.rehydrate(result.text, result.session) == result.text

    def test_allow_passthrough(self):
        policy = Policy({"EMAIL": Rule(Action.ALLOW)})
        s = Scrubber(policy=policy)
        result = s.scrub("mail jane@acme.com")
        assert result.text == "mail jane@acme.com"
        assert result.findings == []

    def test_confidence_threshold_filters(self):
        weak = RegexDetector("WEAK_THING", r"foo\d+", confidence=0.3)
        s = Scrubber(detectors=[weak], policy=Policy(default=Rule(Action.TOKENIZE, min_confidence=0.5)))
        assert s.scrub("foo123").text == "foo123"

    def test_overlap_prefers_higher_confidence(self):
        lo = RegexDetector("LO", r"one two three", confidence=0.6)
        hi = RegexDetector("HI", r"two", confidence=0.9)
        s = Scrubber(detectors=[lo, hi])
        result = s.scrub("one two three")
        assert result.text == "one [HI_1] three"


class TestMessages:
    def test_openai_shape(self):
        s = Scrubber()
        msgs = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Email jane@acme.com for me."},
        ]
        result = s.scrub_messages(msgs)
        assert result.messages[1]["content"] == "Email [EMAIL_1] for me."
        assert msgs[1]["content"] == "Email jane@acme.com for me."  # input not mutated
        assert result.findings[0].entity_type == "EMAIL"

    def test_anthropic_block_shape(self):
        s = Scrubber()
        msgs = [
            {"role": "user", "content": [{"type": "text", "text": "ssn is 219-09-9999"}]},
        ]
        result = s.scrub_messages(msgs)
        assert result.messages[0]["content"][0]["text"] == "ssn is [US_SSN_1]"

    def test_shared_session_across_messages(self):
        s = Scrubber()
        msgs = [
            {"role": "user", "content": "jane@acme.com"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "again jane@acme.com"},
        ]
        result = s.scrub_messages(msgs)
        assert result.messages[0]["content"] == "[EMAIL_1]"
        assert result.messages[2]["content"] == "again [EMAIL_1]"


class TestSessionPersistence:
    def test_round_trip(self):
        s = Scrubber()
        result = s.scrub("mail jane@acme.com")
        restored = ScrubSession.from_dict(result.session.to_dict())
        assert restored.rehydrate("hi [EMAIL_1]") == "hi jane@acme.com"
        # determinism survives restore
        r2 = s.scrub("jane@acme.com again", restored)
        assert "[EMAIL_1]" in r2.text
