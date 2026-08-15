from veil.detectors import default_detectors
from veil.detectors.validators import (
    iban_mod97,
    ipv4_octets,
    ipv6_structure,
    jwt_structure,
    luhn,
    luhn_9,
    nino_prefix,
    phone_digit_count,
    ssn_not_itin,
    valid_date,
    verhoeff,
)


def _detect(text):
    findings = []
    for d in default_detectors():
        findings.extend(d.detect(text))
    return findings


def types_found(text):
    return {f.entity_type for f in _detect(text)}


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


class TestValidators:
    def test_luhn_valid(self):
        assert luhn("4111111111111111")
        assert luhn("4111 1111 1111 1111")

    def test_luhn_invalid(self):
        assert not luhn("4111111111111112")
        assert not luhn("1234")  # too short

    def test_luhn_9_valid(self):
        assert luhn_9("046 454 286")

    def test_luhn_9_invalid(self):
        assert not luhn_9("046 454 287")
        assert not luhn_9("1234")

    def test_iban_valid(self):
        assert iban_mod97("GB82WEST12345698765432")

    def test_iban_invalid(self):
        assert not iban_mod97("GB82WEST12345698765431")

    def test_ipv4_octets(self):
        assert ipv4_octets("10.0.255.1")
        assert not ipv4_octets("999.0.0.1")

    def test_ipv4_excludes_doc_ranges(self):
        assert not ipv4_octets("192.0.2.1")
        assert not ipv4_octets("198.51.100.5")
        assert not ipv4_octets("203.0.113.10")
        assert not ipv4_octets("0.0.0.0")
        assert not ipv4_octets("255.255.255.255")

    def test_ipv6_full(self):
        assert ipv6_structure("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_ipv6_shorthand(self):
        assert ipv6_structure("::1")
        assert ipv6_structure("fe80::1")
        assert ipv6_structure("::")

    def test_ipv6_invalid(self):
        assert not ipv6_structure("2001:db8:85a3::8a2e::7334")  # double ::
        assert not ipv6_structure("xyz")

    def test_phone_digit_count(self):
        assert phone_digit_count("+1 (212) 555-0173")
        assert not phone_digit_count("555-0173")  # 7 digits

    def test_ssn_not_itin(self):
        assert ssn_not_itin("219-09-9999")
        assert not ssn_not_itin("900-70-1234")  # ITIN range
        assert not ssn_not_itin("999-99-1234")  # ITIN range

    def test_jwt_structure_valid(self):
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234"}).encode()).rstrip(b"=").decode()
        sig = "abcdefghijklmnop"
        assert jwt_structure(f"{header}.{payload}.{sig}")

    def test_jwt_structure_invalid(self):
        assert not jwt_structure("not.a.jwt")
        assert not jwt_structure("one.two")

    def test_valid_date_mmddyyyy(self):
        assert valid_date("01/15/1990")
        assert valid_date("12-25-2000")

    def test_valid_date_yyyymmdd(self):
        assert valid_date("1990/01/15")

    def test_valid_date_invalid(self):
        assert not valid_date("13/32/2000")
        assert not valid_date("00/00/0000")

    def test_verhoeff_valid(self):
        assert verhoeff("496107271198")

    def test_verhoeff_invalid(self):
        assert not verhoeff("496107271199")
        assert not verhoeff("1234")

    def test_nino_prefix_valid(self):
        assert nino_prefix("AB123456C")

    def test_nino_prefix_invalid(self):
        assert not nino_prefix("BG123456C")
        assert not nino_prefix("DA123456C")


# ---------------------------------------------------------------------------
# Built-in detectors (original + hardened)
# ---------------------------------------------------------------------------


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

    def test_ssn_rejects_itin_range(self):
        assert "US_SSN" not in types_found("ssn 900-70-1234")

    def test_phone(self):
        assert "PHONE" in types_found("call (212) 555-0173 now")
        assert "PHONE" in types_found("intl +442071838750")

    def test_ip(self):
        assert "IP_ADDRESS" in types_found("host 192.168.1.10 is up")
        assert "IP_ADDRESS" not in types_found("version 999.888.777.666")

    def test_ip_excludes_doc_ranges(self):
        assert "IP_ADDRESS" not in types_found("docs say use 192.0.2.1")
        assert "IP_ADDRESS" not in types_found("broadcast 255.255.255.255")

    def test_iban(self):
        assert "IBAN" in types_found("wire to GB82WEST12345698765432 please")

    def test_aws_key(self):
        assert "AWS_ACCESS_KEY" in types_found("key=AKIAIOSFODNN7EXAMPLE")

    def test_api_keys(self):
        assert "API_KEY" in types_found("token sk-abcdefghijklmnopqrstuvwx")
        assert "API_KEY" in types_found("gh ghp_" + "a" * 36)

    def test_api_key_stripe(self):
        assert "API_KEY" in types_found("key sk_live_" + "a" * 24)
        assert "API_KEY" in types_found("key sk_test_" + "b" * 24)

    def test_api_key_anthropic(self):
        assert "API_KEY" in types_found("key sk-ant-" + "c" * 20)

    def test_clean_text_no_findings(self):
        assert types_found("The quarterly report looks fine to me.") == set()

    def test_offsets_and_text_agree(self):
        text = "email bob@example.com now"
        (f,) = _detect(text)
        assert text[f.start : f.end] == f.text == "bob@example.com"


# ---------------------------------------------------------------------------
# New detectors: credentials / secrets
# ---------------------------------------------------------------------------


class TestNewSecretDetectors:
    def test_us_itin(self):
        assert "US_ITIN" in types_found("ITIN: 900-78-1234")

    def test_private_key(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBogIBAAJBALRiM...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        assert "PRIVATE_KEY" in types_found(f"here is a key: {pem}")

    def test_private_key_ec(self):
        pem = (
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHQCAQEEIBkg...\n"
            "-----END EC PRIVATE KEY-----"
        )
        assert "PRIVATE_KEY" in types_found(pem)

    def test_jwt(self):
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "Jane"}).encode()).rstrip(b"=").decode()
        sig = "SflKxwRJSMeKKF2QT4fwp"
        token = f"{header}.{payload}.{sig}"
        assert "JWT" in types_found(f"Bearer {token}")

    def test_slack_token(self):
        assert "SLACK_TOKEN" in types_found("token xoxb-123456789-abcdefghij")

    def test_gcp_api_key(self):
        key = "AIza" + "A" * 35
        assert "GCP_API_KEY" in types_found(f"key={key}")

    def test_generic_secret(self):
        assert "GENERIC_SECRET" in types_found('password = "s3cr3t_p@ssword!"')
        assert "GENERIC_SECRET" in types_found("api_key: sk_somevalue_long_enough")


# ---------------------------------------------------------------------------
# New detectors: network / infra
# ---------------------------------------------------------------------------


class TestNewNetworkDetectors:
    def test_mac_address(self):
        assert "MAC_ADDRESS" in types_found("mac 00:1A:2B:3C:4D:5E")
        assert "MAC_ADDRESS" in types_found("mac 00-1A-2B-3C-4D-5E")

    def test_url(self):
        assert "URL" in types_found("visit https://example.com/path?user=bob")
        assert "URL" in types_found("see http://10.0.0.1:8080/api")

    def test_url_not_in_clean_text(self):
        assert "URL" not in types_found("The meeting is at noon.")


# ---------------------------------------------------------------------------
# Context-gated detectors
# ---------------------------------------------------------------------------


class TestContextGatedDetectors:
    def test_dob_with_context(self):
        assert "DATE_OF_BIRTH" in types_found("date of birth: 01/15/1990")
        assert "DATE_OF_BIRTH" in types_found("born on 1990-06-15")
        assert "DATE_OF_BIRTH" in types_found("DOB 12/25/2000")

    def test_dob_without_context_dropped(self):
        assert "DATE_OF_BIRTH" not in types_found("the date is 01/15/1990")

    def test_passport_with_context(self):
        assert "PASSPORT_US" in types_found("passport number 123456789")

    def test_passport_without_context_dropped(self):
        assert "PASSPORT_US" not in types_found("order 123456789 confirmed")


# ---------------------------------------------------------------------------
# False-positive regression tests
# ---------------------------------------------------------------------------


class TestFalsePositiveRegression:
    def test_email_not_in_url(self):
        assert "EMAIL" not in types_found("ftp://admin@fileserver.example.com/data")

    def test_ip_not_doc_range(self):
        assert "IP_ADDRESS" not in types_found("example: 192.0.2.1")
        assert "IP_ADDRESS" not in types_found("reserved: 198.51.100.0")

    def test_ssn_not_itin(self):
        assert "US_SSN" not in types_found("ITIN 900-70-1234")
        assert "US_SSN" not in types_found("ITIN 999-88-7654")

    def test_clean_prose_no_detections(self):
        text = (
            "The quarterly financial results show a 15% increase in revenue. "
            "We should schedule a meeting for next Tuesday at 3pm to discuss "
            "the roadmap and v2.1.0 release milestones."
        )
        assert types_found(text) == set()


# ---------------------------------------------------------------------------
# Codex review regression tests
# ---------------------------------------------------------------------------


class TestCodexReviewFixes:
    def test_ipv6_compressed_full_match(self):
        """IPv6 compressed addresses must be matched in full, not partially."""
        text = "host fe80::1 is up"
        findings = [f for f in _detect(text) if f.entity_type == "IPV6_ADDRESS"]
        assert len(findings) == 1
        assert findings[0].text == "fe80::1"

    def test_ipv6_longer_compressed(self):
        text = "addr 2001:db8::8a2e:370:7334 here"
        findings = [f for f in _detect(text) if f.entity_type == "IPV6_ADDRESS"]
        assert len(findings) == 1
        assert findings[0].text == "2001:db8::8a2e:370:7334"

    def test_dob_single_digit_components(self):
        """Single-digit day/month in DOB must be detected."""
        assert "DATE_OF_BIRTH" in types_found("DOB 1/5/1990")
        assert "DATE_OF_BIRTH" in types_found("birthday 3/9/1985")

    def test_dob_two_digit_year(self):
        """Two-digit year in DOB must be detected."""
        assert "DATE_OF_BIRTH" in types_found("born 01/15/90")

    def test_feb_29_non_leap_rejected(self):
        """Feb 29 in a non-leap year must be rejected by the validator."""
        assert "DATE_OF_BIRTH" not in types_found("DOB 02/29/2023")

    def test_feb_29_leap_accepted(self):
        """Feb 29 in a leap year must be accepted."""
        assert "DATE_OF_BIRTH" in types_found("DOB 02/29/2024")
