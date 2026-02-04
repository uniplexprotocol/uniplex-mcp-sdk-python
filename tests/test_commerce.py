"""
Commerce Module Tests

Tests for consumption attestations, cost computation, and billing aggregation.
Cross-ref: Patent #26 (Service Advertising), Patent #27 (Bilateral Metering)
"""

import pytest
from datetime import datetime, timezone

from uniplex_mcp.commerce import (
    compute_platform_fee,
    compute_call_cost,
    compute_time_cost,
    extract_pricing_constraints,
    extract_sla_constraints,
    extract_platform_fee_constraints,
    generate_request_nonce,
    issue_consumption_attestation,
    verify_consumption_attestation,
    aggregate_attestations,
    matches_discovery_criteria,
    meets_sla_requirements,
)
from uniplex_mcp.types import (
    PricingConstraints,
    SLAConstraints,
    PlatformFeeConstraints,
    ConsumptionAttestation,
    ConsumptionData,
    ConsumptionAttestationProof,
    EffectiveConstraints,
    PricingModel,
)


# =============================================================================
# PLATFORM FEE COMPUTATION
# =============================================================================

class TestComputePlatformFee:
    def test_computes_2_percent_fee_correctly(self):
        # 2% = 200 basis points
        fee = compute_platform_fee(1000, 200)
        assert fee == 20  # 1000 * 200 / 10000 = 20 cents

    def test_uses_ceiling_rounding(self):
        # 2% of 101 = 2.02, should round up to 3
        fee = compute_platform_fee(101, 200)
        assert fee == 3

    def test_handles_zero_cost(self):
        fee = compute_platform_fee(0, 200)
        assert fee == 0

    def test_handles_zero_basis_points(self):
        fee = compute_platform_fee(1000, 0)
        assert fee == 0

    def test_rejects_negative_cost(self):
        with pytest.raises(ValueError, match="Cost cannot be negative"):
            compute_platform_fee(-100, 200)

    def test_rejects_negative_basis_points(self):
        with pytest.raises(ValueError, match="Basis points cannot be negative"):
            compute_platform_fee(100, -200)


# =============================================================================
# COST COMPUTATION
# =============================================================================

class TestComputeCallCost:
    def test_computes_per_call_cost(self):
        pricing = PricingConstraints(per_call_cents=10, currency="USD")
        assert compute_call_cost(pricing, 1) == 10
        assert compute_call_cost(pricing, 5) == 50

    def test_returns_0_when_no_per_call_cents(self):
        pricing = PricingConstraints(currency="USD")
        assert compute_call_cost(pricing, 1) == 0

    def test_defaults_to_1_unit(self):
        pricing = PricingConstraints(per_call_cents=10)
        assert compute_call_cost(pricing) == 10


class TestComputeTimeCost:
    def test_computes_per_minute_cost(self):
        pricing = PricingConstraints(per_minute_cents=100)
        assert compute_time_cost(pricing, 60000) == 100  # 1 minute
        assert compute_time_cost(pricing, 120000) == 200  # 2 minutes

    def test_rounds_up_partial_minutes(self):
        pricing = PricingConstraints(per_minute_cents=100)
        assert compute_time_cost(pricing, 61000) == 200  # 1.017 min -> 2 min

    def test_returns_0_when_no_per_minute_cents(self):
        pricing = PricingConstraints(per_call_cents=10)
        assert compute_time_cost(pricing, 60000) == 0


# =============================================================================
# CONSTRAINT EXTRACTION
# =============================================================================

class TestExtractPricingConstraints:
    def test_extracts_all_pricing_fields(self):
        constraints = {
            "core:pricing:per_call_cents": 10,
            "core:pricing:currency": "USD",
            "core:pricing:model": "per_call",
            "core:pricing:free_tier_calls": 100,
        }
        
        pricing = extract_pricing_constraints(constraints)
        assert pricing.per_call_cents == 10
        assert pricing.currency == "USD"
        assert pricing.model == PricingModel.PER_CALL
        assert pricing.free_tier_calls == 100

    def test_handles_missing_fields_gracefully(self):
        pricing = extract_pricing_constraints({})
        assert pricing.per_call_cents is None
        assert pricing.currency is None


class TestExtractPlatformFeeConstraints:
    def test_extracts_platform_fee_fields(self):
        constraints = {
            "core:platform_fee:basis_points": 200,
            "core:platform_fee:recipient": "gate_uniplex",
        }
        
        fee = extract_platform_fee_constraints(constraints)
        assert fee.basis_points == 200
        assert fee.recipient == "gate_uniplex"


# =============================================================================
# REQUEST NONCE
# =============================================================================

class TestGenerateRequestNonce:
    def test_generates_unique_nonces(self):
        nonce1 = generate_request_nonce("agent_test")
        nonce2 = generate_request_nonce("agent_test")
        
        assert nonce1.nonce != nonce2.nonce
        assert nonce1.agent_id == "agent_test"

    def test_includes_timestamp(self):
        nonce = generate_request_nonce("agent_test")
        # Should be a valid ISO timestamp
        assert "T" in nonce.timestamp


# =============================================================================
# CONSUMPTION ATTESTATION
# =============================================================================

class TestIssueConsumptionAttestation:
    @pytest.fixture
    def mock_sign(self):
        async def sign(payload: str) -> str:
            return "mock_sig_" + payload[:20].replace("{", "").replace('"', "")
        return sign

    @pytest.mark.asyncio
    async def test_creates_attestation_with_correct_structure(self, mock_sign):
        attestation = await issue_consumption_attestation(
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="weather:forecast",
            catalog_version=1,
            effective_constraints={
                "core:pricing:per_call_cents": 10,
                "core:pricing:currency": "USD",
                "core:platform_fee:basis_points": 200,
            },
            sign=mock_sign,
            signing_key_id="gate_test#key-1",
        )

        assert attestation.attestation_type == "consumption"
        assert attestation.gate_id == "gate_test"
        assert attestation.agent_id == "agent_test"
        assert attestation.permission_key == "weather:forecast"
        assert attestation.consumption.cost_cents == 10
        assert attestation.consumption.platform_fee_cents == 1  # ceil(10 * 200 / 10000)
        assert attestation.proof.type == "JWS"

    @pytest.mark.asyncio
    async def test_includes_request_nonce_when_provided(self, mock_sign):
        attestation = await issue_consumption_attestation(
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="weather:forecast",
            catalog_version=1,
            effective_constraints={},
            request_nonce="nonce_abc123",
            sign=mock_sign,
            signing_key_id="gate_test#key-1",
        )

        assert attestation.request_nonce == "nonce_abc123"

    @pytest.mark.asyncio
    async def test_computes_time_based_cost_when_duration_provided(self, mock_sign):
        attestation = await issue_consumption_attestation(
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="llm:generate",
            catalog_version=1,
            effective_constraints={
                "core:pricing:per_minute_cents": 100,
                "core:pricing:model": "per_minute",
            },
            duration_ms=90000,  # 1.5 minutes -> 2 minutes
            sign=mock_sign,
            signing_key_id="gate_test#key-1",
        )

        assert attestation.consumption.cost_cents == 200
        assert attestation.consumption.duration_ms == 90000


# =============================================================================
# ATTESTATION VERIFICATION
# =============================================================================

class TestVerifyConsumptionAttestation:
    @pytest.fixture
    def mock_verify(self):
        async def verify(payload: str, sig: str, pub_key: str) -> bool:
            # Mock verification - check sig starts with 'mock_sig_'
            return sig.startswith("mock_sig_")
        return verify

    @pytest.mark.asyncio
    async def test_validates_correct_attestation(self, mock_verify):
        attestation = ConsumptionAttestation(
            attestation_id="catt_123",
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="weather:forecast",
            catalog_version=1,
            effective_constraints=EffectiveConstraints(
                pricing=PricingConstraints(per_call_cents=10),
                platform_fee=PlatformFeeConstraints(basis_points=200),
            ),
            consumption=ConsumptionData(
                units=1,
                cost_cents=10,
                platform_fee_cents=1,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
            proof=ConsumptionAttestationProof(
                kid="gate_test#key-1",
                sig="mock_sig_abc123",
            ),
        )

        result = await verify_consumption_attestation(
            attestation=attestation,
            gate_public_key="mock_pubkey",
            verify=mock_verify,
        )

        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_rejects_nonce_mismatch(self, mock_verify):
        attestation = ConsumptionAttestation(
            attestation_id="catt_123",
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="weather:forecast",
            catalog_version=1,
            request_nonce="nonce_wrong",
            effective_constraints=EffectiveConstraints(),
            consumption=ConsumptionData(
                units=1,
                cost_cents=0,
                platform_fee_cents=0,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
            proof=ConsumptionAttestationProof(kid="test", sig="mock_sig_abc"),
        )

        result = await verify_consumption_attestation(
            attestation=attestation,
            expected_nonce="nonce_expected",
            gate_public_key="mock_pubkey",
            verify=mock_verify,
        )

        assert result["valid"] is False
        assert "nonce mismatch" in result["error"]

    @pytest.mark.asyncio
    async def test_rejects_invalid_signature(self, mock_verify):
        attestation = ConsumptionAttestation(
            attestation_id="catt_123",
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="test",
            catalog_version=1,
            effective_constraints=EffectiveConstraints(),
            consumption=ConsumptionData(
                units=1,
                cost_cents=0,
                platform_fee_cents=0,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
            proof=ConsumptionAttestationProof(kid="test", sig="invalid_signature"),
        )

        result = await verify_consumption_attestation(
            attestation=attestation,
            gate_public_key="mock_pubkey",
            verify=mock_verify,
        )

        assert result["valid"] is False
        assert result["error"] == "Invalid signature"


# =============================================================================
# BILLING AGGREGATION
# =============================================================================

class TestAggregateAttestations:
    def _create_attestation(self, units: int, cost: int, fee: int) -> ConsumptionAttestation:
        import secrets
        return ConsumptionAttestation(
            attestation_id=f"catt_{secrets.token_urlsafe(8)}",
            gate_id="gate_test",
            agent_id="agent_test",
            passport_id="passport_123",
            permission_key="weather:forecast",
            catalog_version=1,
            effective_constraints=EffectiveConstraints(),
            consumption=ConsumptionData(
                units=units,
                cost_cents=cost,
                platform_fee_cents=fee,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ),
            proof=ConsumptionAttestationProof(kid="test", sig="mock_sig"),
        )

    def test_aggregates_multiple_attestations(self):
        attestations = [
            self._create_attestation(1, 10, 1),
            self._create_attestation(2, 20, 1),
            self._create_attestation(1, 10, 1),
        ]

        billing = aggregate_attestations(
            attestations,
            "2026-02-01T00:00:00Z",
            "2026-02-28T23:59:59Z",
        )

        assert billing is not None
        assert billing.total_calls == 4
        assert billing.total_cost_cents == 40
        assert billing.total_platform_fee_cents == 3
        assert len(billing.attestation_ids) == 3

    def test_returns_none_for_empty_array(self):
        billing = aggregate_attestations([], "2026-02-01T00:00:00Z", "2026-02-28T23:59:59Z")
        assert billing is None

    def test_throws_on_mixed_agent_gate_pairs(self):
        att1 = self._create_attestation(1, 10, 1)
        att2 = self._create_attestation(1, 10, 1)
        att2.agent_id = "agent_other"

        with pytest.raises(ValueError, match="same agent/gate pair"):
            aggregate_attestations(
                [att1, att2],
                "2026-02-01T00:00:00Z",
                "2026-02-28T23:59:59Z",
            )


# =============================================================================
# DISCOVERY HELPERS
# =============================================================================

class TestMatchesDiscoveryCriteria:
    def test_matches_when_price_is_under_ceiling(self):
        pricing = PricingConstraints(per_call_cents=10, currency="USD")
        assert matches_discovery_criteria(pricing, max_price_cents=20, currency="USD") is True

    def test_rejects_when_price_exceeds_ceiling(self):
        pricing = PricingConstraints(per_call_cents=30, currency="USD")
        assert matches_discovery_criteria(pricing, max_price_cents=20, currency="USD") is False

    def test_rejects_currency_mismatch(self):
        pricing = PricingConstraints(per_call_cents=10, currency="EUR")
        assert matches_discovery_criteria(pricing, max_price_cents=20, currency="USD") is False

    def test_allows_when_no_criteria_specified(self):
        pricing = PricingConstraints(per_call_cents=100, currency="USD")
        assert matches_discovery_criteria(pricing) is True


class TestMeetsSLARequirements:
    def test_passes_when_sla_meets_requirements(self):
        sla = SLAConstraints(uptime_basis_points=9999, response_time_ms=100)
        assert meets_sla_requirements(sla, min_uptime_basis_points=9990, max_response_time_ms=200) is True

    def test_rejects_insufficient_uptime(self):
        sla = SLAConstraints(uptime_basis_points=9900, response_time_ms=100)
        assert meets_sla_requirements(sla, min_uptime_basis_points=9990, max_response_time_ms=200) is False

    def test_rejects_slow_response_time(self):
        sla = SLAConstraints(uptime_basis_points=9999, response_time_ms=500)
        assert meets_sla_requirements(sla, max_response_time_ms=200) is False
