from veil import Scrubber, ScrubSession


def _session_with(text):
    s = Scrubber()
    return s.scrub(text).session


def _stream(session, chunks):
    from veil import StreamRehydrator

    rh = StreamRehydrator(session)
    out = [rh.feed(c) for c in chunks]
    out.append(rh.flush())
    return "".join(out)


class TestStreamRehydrator:
    def test_token_split_across_chunks(self):
        session = _session_with("mail jane@acme.com")
        assert _stream(session, ["Hello [EMA", "IL_1], welcome"]) == "Hello jane@acme.com, welcome"

    def test_token_split_three_ways(self):
        session = _session_with("mail jane@acme.com")
        assert _stream(session, ["[", "EMAIL", "_1]"]) == "jane@acme.com"

    def test_char_by_char(self):
        session = _session_with("mail jane@acme.com")
        text = "hi [EMAIL_1] bye [EMAIL_1]"
        assert _stream(session, list(text)) == "hi jane@acme.com bye jane@acme.com"

    def test_non_token_brackets_pass_through(self):
        session = _session_with("mail jane@acme.com")
        assert _stream(session, ["see [section 2] and [1]"]) == "see [section 2] and [1]"

    def test_unknown_token_left_intact(self):
        session = ScrubSession()
        assert _stream(session, ["ref [FIGURE_3] here"]) == "ref [FIGURE_3] here"

    def test_unterminated_partial_emitted_on_flush(self):
        session = _session_with("mail jane@acme.com")
        assert _stream(session, ["truncated [EMAIL_"]) == "truncated [EMAIL_"

    def test_oversized_bracket_run_not_held_forever(self):
        session = ScrubSession()
        chunks = ["[" + "A" * 100, " rest"]
        assert _stream(session, chunks) == "[" + "A" * 100 + " rest"

    def test_incremental_emission(self):
        # text before a held-back partial must be emitted immediately
        session = _session_with("mail jane@acme.com")
        from veil import StreamRehydrator

        rh = StreamRehydrator(session)
        first = rh.feed("some prose then [EMA")
        assert first == "some prose then "
        assert rh.feed("IL_1] done") == "jane@acme.com done"
        assert rh.flush() == ""
