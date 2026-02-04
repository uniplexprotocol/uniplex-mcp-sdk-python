"""
Transform Tests

Test vectors from MCP Server Specification v1.0.0 Section 2.3.
All implementations MUST pass these tests exactly.
"""

import pytest

from uniplex_mcp.transforms import (
    compute_platform_fee,
    dollars_to_cents,
    transform_to_canonical,
    TransformError,
)


class TestTransformToCanonicalStrict:
    """Test vectors for strict mode (default)."""
    
    def test_basic_case(self):
        assert transform_to_canonical("1.00", 2) == 100
    
    def test_common_price(self):
        assert transform_to_canonical("4.99", 2) == 499
    
    def test_simple_decimal(self):
        assert transform_to_canonical("0.1", 2) == 10
    
    def test_trailing_zero(self):
        assert transform_to_canonical("0.10", 2) == 10
    
    def test_single_cent(self):
        assert transform_to_canonical("0.01", 2) == 1
    
    def test_micropayment_precision_3(self):
        assert transform_to_canonical("0.001", 3) == 1
    
    def test_negative_value(self):
        assert transform_to_canonical("-4.99", 2) == -499
    
    def test_large_but_safe(self):
        assert transform_to_canonical("1000000.00", 2) == 100000000
    
    def test_exactly_max_safe_integer(self):
        assert transform_to_canonical("90071992547409.91", 2) == 9007199254740991
    
    def test_zero(self):
        assert transform_to_canonical("0", 2) == 0
    
    def test_zero_with_decimals(self):
        assert transform_to_canonical("0.00", 2) == 0
    
    def test_within_precision(self):
        assert transform_to_canonical("1.005", 3) == 1005
    
    # Strict mode rejections
    
    def test_rejects_exceeding_precision(self):
        with pytest.raises(TransformError, match="3 decimal places"):
            transform_to_canonical("1.005", 2)
    
    def test_rejects_micropayment_wrong_precision(self):
        with pytest.raises(TransformError, match="3 decimal places"):
            transform_to_canonical("0.001", 2)
    
    def test_rejects_4_995_precision_2(self):
        with pytest.raises(TransformError, match="3 decimal places"):
            transform_to_canonical("4.995", 2)
    
    def test_rejects_exceeds_max_safe_integer(self):
        with pytest.raises(TransformError, match="exceeds safe integer range"):
            transform_to_canonical("90071992547409.92", 2)


class TestTransformToCanonicalRound:
    """Test vectors for round mode."""
    
    def test_round_half_up(self):
        assert transform_to_canonical("1.005", 2, "round") == 101
    
    def test_round_down(self):
        assert transform_to_canonical("1.004", 2, "round") == 100
    
    def test_round_4_995(self):
        assert transform_to_canonical("4.995", 2, "round") == 500
    
    def test_round_4_994(self):
        assert transform_to_canonical("4.994", 2, "round") == 499
    
    def test_round_to_zero(self):
        assert transform_to_canonical("0.001", 2, "round") == 0
    
    def test_negative_round_half_up(self):
        # Round half-up means away from zero for negatives
        assert transform_to_canonical("-1.005", 2, "round") == -101


class TestTransformToCanonicalTruncate:
    """Test vectors for truncate mode."""
    
    def test_truncate_1_005(self):
        assert transform_to_canonical("1.005", 2, "truncate") == 100
    
    def test_truncate_1_009(self):
        assert transform_to_canonical("1.009", 2, "truncate") == 100
    
    def test_truncate_4_999(self):
        assert transform_to_canonical("4.999", 2, "truncate") == 499


class TestTransformEdgeCases:
    """Edge cases and special handling."""
    
    def test_integer_input(self):
        assert transform_to_canonical(5, 2) == 500
    
    def test_float_input(self):
        # Float input works but string is recommended
        assert transform_to_canonical(4.99, 2) == 499
    
    def test_precision_0(self):
        assert transform_to_canonical("42", 0) == 42
    
    def test_precision_8(self):
        # Satoshi precision
        assert transform_to_canonical("1.00000001", 8) == 100000001
    
    def test_leading_zeros(self):
        assert transform_to_canonical("007.50", 2) == 750
    
    def test_whitespace_trimmed(self):
        assert transform_to_canonical("  4.99  ", 2) == 499
    
    def test_positive_sign(self):
        assert transform_to_canonical("+4.99", 2) == 499
    
    def test_invalid_format(self):
        with pytest.raises(TransformError, match="Invalid numeric value"):
            transform_to_canonical("abc", 2)
    
    def test_empty_string(self):
        with pytest.raises(TransformError, match="Invalid numeric value"):
            transform_to_canonical("", 2)


class TestDollarsToCents:
    """Test the dollars_to_cents alias."""
    
    def test_basic(self):
        assert dollars_to_cents("4.99") == 499
    
    def test_ten_dollars(self):
        assert dollars_to_cents("10.00") == 1000
    
    def test_with_round_mode(self):
        assert dollars_to_cents("1.005", "round") == 101


class TestComputePlatformFee:
    """Test platform fee computation."""
    
    def test_2_percent_of_10_dollars(self):
        assert compute_platform_fee(1000, 200) == 20
    
    def test_ceiling_rounding(self):
        # ceil(19.98) = 20
        assert compute_platform_fee(999, 200) == 20
    
    def test_minimum_fee(self):
        # ceil(0.02) = 1
        assert compute_platform_fee(1, 200) == 1
    
    def test_zero_cost(self):
        assert compute_platform_fee(0, 200) == 0
    
    def test_1_percent(self):
        assert compute_platform_fee(10000, 100) == 100
    
    def test_negative_cost_raises(self):
        with pytest.raises(ValueError, match="cannot be negative"):
            compute_platform_fee(-100, 200)
    
    def test_negative_basis_points_raises(self):
        with pytest.raises(ValueError, match="cannot be negative"):
            compute_platform_fee(100, -200)
