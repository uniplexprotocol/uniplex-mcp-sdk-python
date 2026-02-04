"""
Uniplex MCP Server Transforms

Canonical financial value transforms matching MCP Server Specification v1.0.0 Section 2.3.
All implementations MUST produce identical results.
"""

from __future__ import annotations

import re
from typing import Literal

# Maximum safe integer (same as JavaScript's Number.MAX_SAFE_INTEGER)
MAX_SAFE_INTEGER = 9007199254740991


class TransformError(Exception):
    """Raised when transform fails."""
    pass


def transform_to_canonical(
    value: int | float | str,
    precision: int,
    mode: Literal["strict", "round", "truncate"] = "strict",
) -> int:
    """
    Transform a financial value to its canonical integer representation.
    
    NORMATIVE:
    - Implementations MUST be deterministic across SDKs.
    - Implementations MUST compute using arbitrary precision and
      MUST reject if abs(result) > MAX_SAFE_INTEGER before returning.
    
    Args:
        value: The input value (string strongly recommended for precision)
        precision: Number of decimal places (e.g., 2 for cents, 8 for satoshis)
        mode: 'strict' (default) | 'round' | 'truncate'
            - strict: reject if input has too many decimal places
            - round: round half-up to precision
            - truncate: silently truncate to precision
    
    Returns:
        Integer in smallest unit
    
    Raises:
        TransformError: If value exceeds precision in strict mode, or overflows
    
    Examples:
        >>> transform_to_canonical("4.99", 2)
        499
        >>> transform_to_canonical("1.005", 2, "round")
        101
        >>> transform_to_canonical("1.005", 2, "truncate")
        100
        >>> transform_to_canonical("1.005", 2, "strict")
        TransformError: Value 1.005 has 3 decimal places, max is 2
    """
    # Convert to string and validate format
    str_value = str(value).strip()
    
    if not re.match(r"^[+-]?\d+(\.\d+)?$", str_value):
        raise TransformError(f"Invalid numeric value: {value}")
    
    # Handle sign
    is_negative = str_value.startswith("-")
    str_value = str_value.lstrip("+-")
    
    # Split into whole and decimal parts
    if "." in str_value:
        whole_raw, dec_raw = str_value.split(".")
    else:
        whole_raw, dec_raw = str_value, ""
    
    whole = whole_raw if whole_raw else "0"
    dec = dec_raw
    
    # Compute base (10^precision)
    base = 10 ** precision
    
    def build(dec_digits: str) -> int:
        """Build canonical integer from whole + first N decimal digits."""
        padded = dec_digits.ljust(precision, "0")[:precision]
        whole_contribution = int(whole) * base
        dec_contribution = int(padded) if padded else 0
        return whole_contribution + dec_contribution
    
    # Handle precision modes
    if len(dec) > precision:
        if mode == "strict":
            raise TransformError(
                f"Value {value} has {len(dec)} decimal places, max is {precision}"
            )
        
        truncated = build(dec[:precision])
        
        if mode == "truncate":
            result = truncated
        else:
            # mode == "round": round half-up (away from zero)
            next_digit = int(dec[precision])
            result = truncated + 1 if next_digit >= 5 else truncated
    else:
        result = build(dec)
    
    # Apply sign
    if is_negative:
        result = -result
    
    # Overflow check
    if result > MAX_SAFE_INTEGER or result < -MAX_SAFE_INTEGER:
        raise TransformError(
            f"Transformed value {result} exceeds safe integer range"
        )
    
    return result


def dollars_to_cents(
    value: int | float | str,
    mode: Literal["strict", "round", "truncate"] = "strict",
) -> int:
    """
    Alias for transform_to_canonical(value, 2, mode).
    
    Converts dollar amounts to cents.
    
    Args:
        value: Dollar amount (string recommended)
        mode: Transform mode
    
    Returns:
        Amount in cents
    
    Examples:
        >>> dollars_to_cents("4.99")
        499
        >>> dollars_to_cents("10.00")
        1000
    """
    return transform_to_canonical(value, 2, mode)


def compute_platform_fee(service_cost_cents: int, basis_points: int) -> int:
    """
    Compute platform fee using deterministic ceiling rounding.
    
    fee_cents = ceil(service_cost_cents * basis_points / 10000)
    
    Args:
        service_cost_cents: Service cost in smallest currency unit
        basis_points: Platform fee in basis points (200 = 2%)
    
    Returns:
        Platform fee in smallest currency unit
    
    Examples:
        >>> compute_platform_fee(1000, 200)  # 2% of $10.00
        20
        >>> compute_platform_fee(999, 200)   # ceil(19.98) = 20
        20
        >>> compute_platform_fee(1, 200)     # ceil(0.02) = 1
        1
    """
    if service_cost_cents < 0:
        raise ValueError("Service cost cannot be negative")
    if basis_points < 0:
        raise ValueError("Basis points cannot be negative")
    
    # Use ceiling division: ceil(a/b) = (a + b - 1) // b
    numerator = service_cost_cents * basis_points
    if numerator == 0:
        return 0
    return (numerator + 10000 - 1) // 10000
