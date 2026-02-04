"""
Uniplex MCP Server - Commerce Module

Implements commerce primitives for agent-to-agent transactions:
- Consumption attestations (receipts)
- Cost computation
- Bilateral verification

Cross-ref: Patent #26 (Service Advertising), Patent #27 (Bilateral Metering)
"""

from __future__ import annotations

import json
import math
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from .types import (
    ConsumptionAttestation,
    ConsumptionAttestationProof,
    ConsumptionData,
    EffectiveConstraints,
    PricingConstraints,
    PlatformFeeConstraints,
    RequestNonce,
    BillingPeriod,
    PricingModel,
    SLAConstraints,
)


# =============================================================================
# PLATFORM FEE COMPUTATION
# =============================================================================

def compute_platform_fee(service_cost_cents: int, basis_points: int) -> int:
    """
    Platform fee computation (Normative).
    fee_cents = ceil(service_cost_cents * basis_points / 10000)
    
    Cross-ref: Patent #27, Section 4.1
    """
    if service_cost_cents < 0:
        raise ValueError("Cost cannot be negative")
    if basis_points < 0:
        raise ValueError("Basis points cannot be negative")
    return math.ceil(service_cost_cents * basis_points / 10000)


def compute_call_cost(pricing: PricingConstraints, units: int = 1) -> int:
    """Compute cost for a single call based on pricing constraints."""
    if pricing.per_call_cents is not None:
        return pricing.per_call_cents * units
    return 0


def compute_time_cost(pricing: PricingConstraints, duration_ms: int) -> int:
    """Compute cost for time-based pricing."""
    if pricing.per_minute_cents is not None:
        minutes = math.ceil(duration_ms / 60000)
        return pricing.per_minute_cents * minutes
    return 0


# =============================================================================
# CONSTRAINT EXTRACTION
# =============================================================================

def extract_pricing_constraints(constraints: dict[str, Any]) -> PricingConstraints:
    """Extract pricing constraints from a constraint record."""
    model_str = constraints.get("core:pricing:model")
    model = PricingModel(model_str) if model_str else None
    
    return PricingConstraints(
        per_call_cents=constraints.get("core:pricing:per_call_cents"),
        per_minute_cents=constraints.get("core:pricing:per_minute_cents"),
        subscription_cents=constraints.get("core:pricing:subscription_cents"),
        model=model,
        currency=constraints.get("core:pricing:currency"),
        free_tier_calls=constraints.get("core:pricing:free_tier_calls"),
    )


def extract_sla_constraints(constraints: dict[str, Any]) -> SLAConstraints:
    """Extract SLA constraints from a constraint record."""
    return SLAConstraints(
        uptime_basis_points=constraints.get("core:sla:uptime_basis_points"),
        response_time_ms=constraints.get("core:sla:response_time_ms"),
        p99_response_ms=constraints.get("core:sla:p99_response_ms"),
        guaranteed_response_ms=constraints.get("core:sla:guaranteed_response_ms"),
    )


def extract_platform_fee_constraints(constraints: dict[str, Any]) -> PlatformFeeConstraints:
    """Extract platform fee constraints from a constraint record."""
    return PlatformFeeConstraints(
        basis_points=constraints.get("core:platform_fee:basis_points"),
        recipient=constraints.get("core:platform_fee:recipient"),
    )


# =============================================================================
# REQUEST NONCE GENERATION
# =============================================================================

def generate_request_nonce(agent_id: str) -> RequestNonce:
    """
    Generate a request nonce for bilateral verification.
    
    Agent generates this before making a tool call and expects
    it to be echoed in the consumption attestation.
    
    Cross-ref: Patent #27, Section 2.1
    """
    nonce = f"nonce_{int(time.time() * 1000)}_{secrets.token_urlsafe(8)}"
    return RequestNonce(
        nonce=nonce,
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
    )


# =============================================================================
# CONSUMPTION ATTESTATION GENERATION
# =============================================================================

async def issue_consumption_attestation(
    *,
    gate_id: str,
    agent_id: str,
    passport_id: str,
    permission_key: str,
    catalog_version: int,
    effective_constraints: dict[str, Any],
    sign: Callable[[str], Awaitable[str]],
    signing_key_id: str,
    catalog_content_hash: str | None = None,
    request_nonce: str | None = None,
    units: int = 1,
    duration_ms: int | None = None,
) -> ConsumptionAttestation:
    """
    Issue a consumption attestation (receipt) after successful tool execution.
    
    The gate issues this to create a bilateral record of the transaction.
    Both gate and agent retain identical signed attestations.
    
    Cross-ref: Patent #27, Section 2.2
    """
    # Extract pricing from constraints
    pricing = extract_pricing_constraints(effective_constraints)
    platform_fee = extract_platform_fee_constraints(effective_constraints)
    
    # Compute costs
    cost_cents = 0
    if pricing.model == PricingModel.PER_MINUTE and duration_ms is not None:
        cost_cents = compute_time_cost(pricing, duration_ms)
    else:
        cost_cents = compute_call_cost(pricing, units)
    
    # Compute platform fee
    platform_fee_cents = (
        compute_platform_fee(cost_cents, platform_fee.basis_points)
        if platform_fee.basis_points
        else 0
    )
    
    # Build consumption data
    consumption = ConsumptionData(
        units=units,
        cost_cents=cost_cents,
        platform_fee_cents=platform_fee_cents,
        timestamp=datetime.now(timezone.utc).isoformat(),
        duration_ms=duration_ms,
    )
    
    # Build attestation ID
    attestation_id = f"catt_{int(time.time() * 1000)}_{secrets.token_urlsafe(8)}"
    
    # Build attestation payload (without signature)
    effective = EffectiveConstraints(
        pricing=pricing,
        platform_fee=platform_fee,
    )
    
    # Create attestation object for JSON serialization
    attestation_payload = {
        "attestation_type": "consumption",
        "attestation_id": attestation_id,
        "gate_id": gate_id,
        "agent_id": agent_id,
        "passport_id": passport_id,
        "permission_key": permission_key,
        "catalog_version": catalog_version,
        "effective_constraints": {
            "pricing": pricing.model_dump(exclude_none=True),
            "platform_fee": platform_fee.model_dump(exclude_none=True),
        },
        "consumption": consumption.model_dump(exclude_none=True),
    }
    
    if catalog_content_hash:
        attestation_payload["catalog_content_hash"] = catalog_content_hash
    if request_nonce:
        attestation_payload["request_nonce"] = request_nonce
    
    # Canonical JSON for signing
    canonical_json = json.dumps(attestation_payload, separators=(",", ":"), sort_keys=True)
    
    # Sign the attestation
    signature = await sign(canonical_json)
    
    return ConsumptionAttestation(
        attestation_id=attestation_id,
        gate_id=gate_id,
        agent_id=agent_id,
        passport_id=passport_id,
        permission_key=permission_key,
        catalog_version=catalog_version,
        catalog_content_hash=catalog_content_hash,
        request_nonce=request_nonce,
        effective_constraints=effective,
        consumption=consumption,
        proof=ConsumptionAttestationProof(
            kid=signing_key_id,
            sig=signature,
        ),
    )


# =============================================================================
# AGENT-SIDE VERIFICATION
# =============================================================================

async def verify_consumption_attestation(
    *,
    attestation: ConsumptionAttestation,
    gate_public_key: str,
    verify: Callable[[str, str, str], Awaitable[bool]],
    expected_nonce: str | None = None,
) -> dict[str, Any]:
    """
    Verify a consumption attestation received from a gate.
    
    Agent-side verification ensures:
    1. Signature is valid (gate actually issued this)
    2. Request nonce matches (prevents fabrication)
    3. Costs are computed correctly from constraints
    
    Cross-ref: Patent #27, Section 2.3
    
    Returns:
        {"valid": True} or {"valid": False, "error": "..."}
    """
    # Check nonce if provided
    if expected_nonce and attestation.request_nonce != expected_nonce:
        return {
            "valid": False,
            "error": "Request nonce mismatch - attestation may be fabricated",
        }
    
    # Reconstruct canonical JSON (without proof)
    attestation_dict = attestation.model_dump(exclude={"proof"}, exclude_none=True)
    
    # Convert nested models to dicts for JSON serialization
    if "effective_constraints" in attestation_dict:
        ec = attestation_dict["effective_constraints"]
        if "pricing" in ec and hasattr(ec["pricing"], "model_dump"):
            ec["pricing"] = ec["pricing"].model_dump(exclude_none=True)
        if "platform_fee" in ec and hasattr(ec["platform_fee"], "model_dump"):
            ec["platform_fee"] = ec["platform_fee"].model_dump(exclude_none=True)
    
    canonical_json = json.dumps(attestation_dict, separators=(",", ":"), sort_keys=True)
    
    # Verify signature
    signature_valid = await verify(canonical_json, attestation.proof.sig, gate_public_key)
    if not signature_valid:
        return {"valid": False, "error": "Invalid signature"}
    
    # Verify cost computation
    pricing = attestation.effective_constraints.pricing or PricingConstraints()
    platform_fee = attestation.effective_constraints.platform_fee or PlatformFeeConstraints()
    
    expected_cost = 0
    if pricing.model == PricingModel.PER_MINUTE and attestation.consumption.duration_ms:
        expected_cost = compute_time_cost(pricing, attestation.consumption.duration_ms)
    else:
        expected_cost = compute_call_cost(pricing, attestation.consumption.units)
    
    if attestation.consumption.cost_cents != expected_cost:
        return {
            "valid": False,
            "error": f"Cost mismatch: expected {expected_cost}, got {attestation.consumption.cost_cents}",
        }
    
    # Verify platform fee computation
    expected_fee = (
        compute_platform_fee(expected_cost, platform_fee.basis_points)
        if platform_fee.basis_points
        else 0
    )
    
    if attestation.consumption.platform_fee_cents != expected_fee:
        return {
            "valid": False,
            "error": f"Platform fee mismatch: expected {expected_fee}, got {attestation.consumption.platform_fee_cents}",
        }
    
    return {"valid": True}


# =============================================================================
# BILLING AGGREGATION
# =============================================================================

def aggregate_attestations(
    attestations: list[ConsumptionAttestation],
    period_start: str,
    period_end: str,
) -> BillingPeriod | None:
    """
    Aggregate consumption attestations into a billing period.
    
    Cross-ref: Patent #27, Section 3.2
    """
    if not attestations:
        return None
    
    # All attestations must be for same agent/gate pair
    first = attestations[0]
    agent_id = first.agent_id
    gate_id = first.gate_id
    
    # Validate all attestations match
    for att in attestations:
        if att.agent_id != agent_id or att.gate_id != gate_id:
            raise ValueError("All attestations must be for the same agent/gate pair")
    
    # Aggregate totals
    total_calls = 0
    total_cost_cents = 0
    total_platform_fee_cents = 0
    attestation_ids: list[str] = []
    
    for att in attestations:
        total_calls += att.consumption.units
        total_cost_cents += att.consumption.cost_cents
        total_platform_fee_cents += att.consumption.platform_fee_cents
        attestation_ids.append(att.attestation_id)
    
    return BillingPeriod(
        period_start=period_start,
        period_end=period_end,
        agent_id=agent_id,
        gate_id=gate_id,
        total_calls=total_calls,
        total_cost_cents=total_cost_cents,
        total_platform_fee_cents=total_platform_fee_cents,
        attestation_ids=attestation_ids,
    )


# =============================================================================
# SERVICE ADVERTISEMENT HELPERS
# =============================================================================

def matches_discovery_criteria(
    pricing: PricingConstraints,
    max_price_cents: int | None = None,
    currency: str | None = None,
) -> bool:
    """Check if a service matches discovery criteria."""
    # Check currency match
    if currency and pricing.currency and pricing.currency != currency:
        return False
    
    # Check price ceiling
    if max_price_cents is not None:
        cost = pricing.per_call_cents or pricing.per_minute_cents or 0
        if cost > max_price_cents:
            return False
    
    return True


def meets_sla_requirements(
    sla: SLAConstraints,
    min_uptime_basis_points: int | None = None,
    max_response_time_ms: int | None = None,
) -> bool:
    """Check if service meets SLA requirements."""
    if min_uptime_basis_points is not None:
        if not sla.uptime_basis_points or sla.uptime_basis_points < min_uptime_basis_points:
            return False
    
    if max_response_time_ms is not None:
        if not sla.response_time_ms or sla.response_time_ms > max_response_time_ms:
            return False
    
    return True


__all__ = [
    # Fee computation
    "compute_platform_fee",
    "compute_call_cost",
    "compute_time_cost",
    # Constraint extraction
    "extract_pricing_constraints",
    "extract_sla_constraints",
    "extract_platform_fee_constraints",
    # Nonce generation
    "generate_request_nonce",
    # Attestations
    "issue_consumption_attestation",
    "verify_consumption_attestation",
    "aggregate_attestations",
    # Discovery helpers
    "matches_discovery_criteria",
    "meets_sla_requirements",
]
