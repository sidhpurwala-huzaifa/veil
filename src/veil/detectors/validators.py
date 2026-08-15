"""Checksum and structural validators for the deterministic detection tier."""

from __future__ import annotations

import calendar


def _digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def luhn(value: str) -> bool:
    """Luhn mod-10 check over the digits in `value` (separators ignored)."""
    digits = _digits(value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_9(value: str) -> bool:
    """Luhn mod-10 for exactly 9 digit values (CA SIN)."""
    digits = _digits(value)
    if len(digits) != 9:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_mod97(value: str) -> bool:
    """ISO 13616 IBAN check: rotate first four chars to the end, base-36 mod 97 == 1."""
    v = value.replace(" ", "").upper()
    if not 15 <= len(v) <= 34:
        return False
    rotated = v[4:] + v[:4]
    try:
        numeric = "".join(str(int(ch, 36)) for ch in rotated)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


# RFC 5737 documentation ranges + broadcast/unspecified — never real user IPs.
_IPV4_EXCLUDED = {
    "0.0.0.0",
    "255.255.255.255",
}
_IPV4_DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


def ipv4_octets(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    if value in _IPV4_EXCLUDED:
        return False
    if any(value.startswith(p) for p in _IPV4_DOC_PREFIXES):
        return False
    return True


def ipv6_structure(value: str) -> bool:
    """Validate an IPv6 address: 8 groups of hex quads or valid :: shorthand."""
    v = value.strip()
    if "::" in v:
        parts = v.split("::")
        if len(parts) != 2:
            return False
        left = parts[0].split(":") if parts[0] else []
        right = parts[1].split(":") if parts[1] else []
        if len(left) + len(right) >= 8:
            return False
    else:
        groups = v.split(":")
        if len(groups) != 8:
            return False
        left = groups
    for g in left + (right if "::" in v else []):  # type: ignore[possibly-undefined]
        if not g or len(g) > 4:
            return False
        try:
            int(g, 16)
        except ValueError:
            return False
    return True


def phone_digit_count(value: str) -> bool:
    """Subscriber numbers are 10-15 digits; anything else is likely an ID or a date."""
    return 10 <= len(_digits(value)) <= 15


def ssn_not_itin(value: str) -> bool:
    """Accept SSN-formatted values but reject ITIN ranges (9xx-[7-9]x-xxxx)."""
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    if area >= 900 and 70 <= group <= 99:
        return False
    return True


def jwt_structure(value: str) -> bool:
    """Verify three dot-separated base64url segments with plausible lengths."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    import base64
    for part in parts[:2]:
        padded = part + "=" * (-len(part) % 4)
        try:
            base64.urlsafe_b64decode(padded)
        except Exception:
            return False
    return all(len(p) >= 4 for p in parts)


def valid_date(value: str) -> bool:
    """Check that a date string represents a real calendar date."""
    digits = _digits(value)
    if len(digits) == 8:
        # Try MMDDYYYY and YYYYMMDD
        for m_s, d_s, y_s in [
            (digits[:2], digits[2:4], digits[4:]),
            (digits[4:6], digits[6:], digits[:4]),
        ]:
            m, d, y = int(m_s), int(d_s), int(y_s)
            if 1 <= m <= 12 and 1900 <= y <= 2100:
                max_day = 29 if m == 2 else (30 if m in (4, 6, 9, 11) else 31)
                if m == 2 and calendar.isleap(y):
                    max_day = 29
                if 1 <= d <= max_day:
                    return True
    return False


# Verhoeff checksum tables for Aadhaar validation.
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff(value: str) -> bool:
    """Verhoeff checksum used by India's Aadhaar system."""
    digits = _digits(value)
    if len(digits) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def nino_prefix(value: str) -> bool:
    """UK National Insurance Number prefix validation."""
    v = value.replace(" ", "").upper()
    if len(v) != 9:
        return False
    prefix = v[:2]
    invalid_prefixes = {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}
    if prefix in invalid_prefixes:
        return False
    if prefix[0] in "DFIQUV" or prefix[1] in "DFIQUVO":
        return False
    return True
