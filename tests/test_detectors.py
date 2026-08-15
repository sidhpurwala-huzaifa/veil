from veil.detectors import default_detectors
from veil.detectors.validators import iban_mod97, ipv4_octets, luhn, phone_digit_count


def _detect(text):
    findings = []
    for d in default_detectors():
        findings.extend(d.detect(text))
    return findings


def types_found(text):
    return {f.entity_type for f in _detect(text)}


class TestValidators:
    def test_luhn_valid(self):
        assert luhn("4111111111111111")
        assert luhn("4111 1111 1111 1111")

    def test_luhn_invalid(self):
        assert not luhn("4111111111111112")
        assert not luhn("1234")  # too short

    def test_iban_valid(self):
        assert iban_mod97("GB82WEST12345698765432")

    def test_iban_invalid(self):
        assert not iban_mod97("GB82WEST12345698765431")

    def test_ipv4_octets(self):
        assert ipv4_octets("10.0.255.1")
        assert not ipv4_octets("999.0.0.1")

    def test_phone_digit_count(self):
        assert phone_digit_count("+1 (212) 555-0173")
        assert not phone_digit_count("555-0173")  # 7 digits


class TestBuiltinDetectors:
    def test_email(self):
        assert "EMAIL" in types_found("contact jane.doe+test@sub.example.co.uk today")

    def test_credit_card_luhn_gated(self):
        assert "CREDIT_CARD" in types_found("card: 4111 1111 1111 1111")
        assert "CREDIT_CARD" not in types_found("order id 4111111111111112")

    def test_ssn_dashed_only(self):
        assert "US_SSN" in types_found("ssn 219-09-9999")
        assert "US_SSN" not in types_found("id 219099999")
        assert "US_SSN" not in types_found("ssn 000-12-3456")

    def test_phone(self):
        assert "PHONE" in types_found("call (212) 555-0173 now")
        assert "PHONE" in types_found("intl +442071838750")

    def test_ip(self):
        assert "IP_ADDRESS" in types_found("host 192.168.1.10 is up")
        assert "IP_ADDRESS" not in types_found("version 999.888.777.666")

    def test_iban(self):
        assert "IBAN" in types_found("wire to GB82WEST12345698765432 please")

    def test_aws_key(self):
        assert "AWS_ACCESS_KEY" in types_found("key=AKIAIOSFODNN7EXAMPLE")

    def test_api_keys(self):
        assert "API_KEY" in types_found("token sk-abcdefghijklmnopqrstuvwx")
        assert "API_KEY" in types_found("gh ghp_" + "a" * 36)

    def test_clean_text_no_findings(self):
        assert types_found("The quarterly report looks fine to me.") == set()

    def test_offsets_and_text_agree(self):
        text = "email bob@example.com now"
        (f,) = _detect(text)
        assert text[f.start : f.end] == f.text == "bob@example.com"
