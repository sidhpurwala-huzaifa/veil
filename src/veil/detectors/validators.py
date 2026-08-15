"""Checksum and structural validators for the deterministic detection tier."""

from __future__ import annotations


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


def ipv4_octets(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def phone_digit_count(value: str) -> bool:
    """Subscriber numbers are 10-15 digits; anything else is likely an ID or a date."""
    return 10 <= len(_digits(value)) <= 15
