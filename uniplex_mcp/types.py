"""
Uniplex MCP Server Types
Version: 1.2.0

Shared protocol types are imported from the `uniplex` protocol SDK.
MCP-specific types are defined here.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

# =============================================================================
# RE-EXPORTS FROM PROTOCOL SDK
# =============================================================================

from uniplex import DenyReason  # noqa: F401 — 38-member enum

from uniplex.constraints import (  # noqa: F401
    CELResult,
    ConstraintDecision,
    ConstraintEvaluation,
    CONSTRAINT_KEYS,
    CumulativeState,
    CumulativeStateTracker,
    evaluate_constraints,
    OBLIGATION_TOKENS,
)

from uniplex.anonymous import (  # noqa: F401
    AnonymousAccessPolicy,
    AnonymousDecision,
    MemoryAnonymousRateLimiter,
    evaluate_anonymous_access,
)

# =============================================================================
# BACKWARD-COMPATIBLE ALIAS
# =============================================================================

# DenialCode is the legacy name used throughout this SDK.
# It is now an alias for the protocol SDK's DenyReason enum.
DenialCode = DenyReason


# =============================================================================
# TRANSFORM MODE
# =============================================================================

class TransformMode(str, Enum):
    """Transform modes for financial value conversion."""

    STRICT = "strict"      # Reject if decimals exceed precision
    ROUND = "round"        # Round half-up
    TRUNCATE = "truncate"  # Silently truncate


# =============================================================================
# CONSTRAINT TYPES (Section 2.4 Commerce Constraint Namespaces)
# =============================================================================

class ConstraintType(str, Enum):
    """Constraint classification for merge behavior."""

    LIMIT = "limit"  # Access control - min-merge (most restrictive wins)
    TERM = "term"    # Commercial terms - gate-authoritative


# Constraint type registry — defines limit vs term constraints.
#
# - limit: access control constraints (min-merge, passport can restrict)
# - term:  commercial terms (gate-authoritative, credentials bind TO)
#
# Key names align with CONSTRAINT_KEYS from the protocol SDK.
CONSTRAINT_TYPES: dict[str, dict[str, str]] = {
    # Access control constraints (limit type)
    "core:rate:max_per_minute": {"type": "limit", "value_type": "integer"},
    "core:rate:max_per_hour": {"type": "limit", "value_type": "integer"},
    "core:rate:max_per_day": {"type": "limit", "value_type": "integer"},
    "core:cost:max_per_action": {"type": "limit", "value_type": "integer"},
    "core:cost:max_cumulative": {"type": "limit", "value_type": "integer"},

    # Commerce constraints (term type) - forward compatibility
    "core:pricing:per_call_cents": {"type": "term", "value_type": "integer"},
    "core:pricing:per_minute_cents": {"type": "term", "value_type": "integer"},
    "core:pricing:model": {"type": "term", "value_type": "string"},
    "core:pricing:currency": {"type": "term", "value_type": "string"},
    "core:pricing:free_tier_calls": {"type": "term", "value_type": "integer"},
    "core:sla:uptime_basis_points": {"type": "term", "value_type": "integer"},
    "core:sla:response_time_ms": {"type": "term", "value_type": "integer"},
    "core:sla:p99_response_ms": {"type": "term", "value_type": "integer"},
    "core:platform_fee:basis_points": {"type": "term", "value_type": "integer"},
}


# =============================================================================
# RISK LEVEL / TRUST TIER
# =============================================================================

class RiskLevel(str, Enum):
    """Risk levels for permissions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustTier(str, Enum):
    """Trust tiers for passports."""

    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


# =============================================================================
# DENIAL & VERIFY RESULT
# =============================================================================

class Denial(BaseModel):
    """Denial information when verification fails."""

    code: DenyReason
    message: str
    upgrade_template: Optional[str] = None


class VerifyResult(BaseModel):
    """
    Result of local verification.

    Three-tier decision model (§14B.2):
      BLOCK   → wire "deny", no obligations
      SUSPEND → wire "deny", obligations=["require_approval"],
                reason_codes=["approval_required"]
      PERMIT  → wire "permit"

    `allowed` is kept for backward compatibility: True iff decision == "permit".
    """

    # Backward-compatible flag: True when decision is "permit".
    allowed: bool
    # Wire-level decision: "permit" or "deny".
    decision: str = "deny"  # "permit" | "deny"
    # Internal three-tier decision from CEL.
    constraint_decision: Optional[str] = None  # "PERMIT" | "BLOCK" | "SUSPEND"
    # Populated on SUSPEND: ["approval_required"].
    reason_codes: Optional[list[str]] = None
    # Populated on SUSPEND: ["require_approval"].
    obligations: Optional[list[str]] = None
    denial: Optional[Denial] = None
    effective_constraints: Optional[dict[str, Any]] = None
    confident: bool = True  # True if cache was fresh enough


# =============================================================================
# PASSPORT
# =============================================================================

class PermissionClaim(BaseModel):
    """A permission claim within a passport."""

    key: str
    constraints: dict[str, Any] = Field(default_factory=dict)


class Passport(BaseModel):
    """Agent passport with permission claims."""

    passport_id: str
    agent_id: str
    issuer_id: str
    gate_id: str
    trust_tier: TrustTier
    permissions: list[PermissionClaim]
    constraints: dict[str, Any] = Field(default_factory=dict)
    issued_at: str
    expires_at: str
    catalog_version_pin: Optional[dict[str, int]] = None
    signature: str

    # Computed at load time for O(1) lookup
    claims_by_key: dict[str, PermissionClaim] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build claims_by_key index after initialization."""
        if not self.claims_by_key:
            self.claims_by_key = {p.key: p for p in self.permissions}


# =============================================================================
# CATALOG
# =============================================================================

class CatalogPermission(BaseModel):
    """A permission entry in a catalog."""

    key: str
    description: str
    risk_level: RiskLevel
    constraints: dict[str, Any] = Field(default_factory=dict)
    required_constraints: list[str] = Field(default_factory=list)
    default_template: Optional[str] = None


class Catalog(BaseModel):
    """Permission catalog from a gate."""

    gate_id: str
    version: int
    min_compatible_version: int = 1
    permissions: list[CatalogPermission]
    content_hash: str
    signature: str

    # Computed at load time for O(1) lookup
    permissions_by_key: dict[str, CatalogPermission] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build permissions_by_key index after initialization."""
        if not self.permissions_by_key:
            self.permissions_by_key = {p.key: p for p in self.permissions}


class CachedCatalog(BaseModel):
    """Cached catalog with versioned snapshots."""

    gate_id: str
    current: Catalog
    versions: dict[int, Catalog] = Field(default_factory=dict)
    fetched_at: datetime
    max_age_minutes: int = 5


# =============================================================================
# TOOL DEFINITION & CONSTRAINTS
# =============================================================================

class ConstraintConfig(BaseModel):
    """Configuration for constraint extraction from tool input."""

    key: str
    source: Literal["input", "fixed"]
    input_path: str | None = None
    fixed_value: Any = None
    transform: Literal["none", "dollars_to_cents", "custom"] = "none"
    precision: int = 2
    transform_mode: TransformMode = TransformMode.STRICT


class ToolUniplexMetadata(BaseModel):
    """Uniplex metadata for a tool definition."""

    permission_key: str
    risk_level: RiskLevel
    required_constraints: list[str] = Field(default_factory=list)
    constraints: list[ConstraintConfig] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    """MCP tool definition with Uniplex extension."""

    name: str
    description: str
    input_schema: dict[str, Any]
    uniplex: ToolUniplexMetadata | None = None


class SessionState(BaseModel):
    """Session state for a tool."""

    allowed: bool
    reason: str | None = None
    upgrade_template: str | None = None


class VerifyRequest(BaseModel):
    """Request for local verification."""

    passport: Passport
    action: str
    context: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# SERVER CONFIGURATION
# =============================================================================

class ServerConfig(BaseModel):
    """Configuration for the Uniplex MCP Server."""

    gate_id: str
    gate_secret: str | None = None  # Only for server-side operations
    uniplex_api_url: str = "https://api.uniplex.ai"
    signing_key_id: str | None = None  # Key ID for signing attestations

    # Cache settings
    catalog_max_age_minutes: int = 5
    revocation_max_age_minutes: int = 1
    fail_mode: Literal["fail_open", "fail_closed"] = "fail_open"

    # Commerce settings
    commerce_enabled: bool = False
    issue_receipts: bool = False

    # Anonymous access policy (§14A)
    anonymous: Optional[AnonymousAccessPolicy] = None

    # Test mode
    test_mode: bool = False
    skip_signature_verification: bool = False


# =============================================================================
# COMMERCE TYPES (Uni-Commerce Profile)
# Cross-ref: Patent #26 (Service Advertising), Patent #27 (Bilateral Metering)
# =============================================================================

class PricingModel(str, Enum):
    """Pricing model for a permission."""

    PER_CALL = "per_call"
    PER_MINUTE = "per_minute"
    SUBSCRIPTION = "subscription"
    USAGE = "usage"


class PricingConstraints(BaseModel):
    """Pricing constraints extracted from catalog."""

    per_call_cents: int | None = None
    per_minute_cents: int | None = None
    subscription_cents: int | None = None
    model: PricingModel | None = None
    currency: str | None = None  # ISO 4217 (e.g., "USD")
    free_tier_calls: int | None = None


class SLAConstraints(BaseModel):
    """SLA constraints extracted from catalog."""

    uptime_basis_points: int | None = None     # 99.95% = 9995
    response_time_ms: int | None = None
    p99_response_ms: int | None = None
    guaranteed_response_ms: int | None = None


class PlatformFeeConstraints(BaseModel):
    """Platform fee configuration."""

    basis_points: int | None = None  # 2% = 200
    recipient: str | None = None     # Gate ID of fee recipient


class ServiceAdvertisement(BaseModel):
    """
    Service advertisement - extends catalog permission with commerce metadata.
    Cross-ref: Patent #26, Section 2.3
    """

    permission_key: str
    display_name: str
    description: str | None = None
    trust_level_required: int | None = None
    pricing: PricingConstraints
    sla: SLAConstraints | None = None
    platform_fee: PlatformFeeConstraints | None = None


class ConsumptionData(BaseModel):
    """
    Consumption data for a single transaction.
    Cross-ref: Patent #27, Section 2.4
    """

    units: int
    cost_cents: int
    platform_fee_cents: int
    timestamp: str  # RFC3339
    duration_ms: int | None = None  # For per-minute pricing


class RequestNonce(BaseModel):
    """
    Request nonce from agent for bilateral verification.
    Cross-ref: Patent #27, Section 2.1
    """

    nonce: str        # Random string from agent
    timestamp: str    # When agent generated nonce
    agent_id: str


class ConsumptionAttestationProof(BaseModel):
    """Cryptographic proof for consumption attestation."""

    type: Literal["JWS"] = "JWS"
    kid: str  # Key ID (e.g., "gate_weather-pro#key-1")
    sig: str  # BASE64URL signature


class EffectiveConstraints(BaseModel):
    """Commercial terms at time of transaction."""

    pricing: PricingConstraints | None = None
    platform_fee: PlatformFeeConstraints | None = None


class ConsumptionAttestation(BaseModel):
    """
    Consumption attestation - receipt issued by gate after tool execution.
    Cross-ref: Patent #27, Commerce Integration Plan Section 2.4
    """

    attestation_type: Literal["consumption"] = "consumption"
    attestation_id: str
    gate_id: str
    agent_id: str
    passport_id: str
    permission_key: str
    catalog_version: int
    catalog_content_hash: str | None = None

    # Bilateral verification: echo agent's nonce
    request_nonce: str | None = None

    # Commercial terms at time of transaction
    effective_constraints: EffectiveConstraints

    # Consumption details
    consumption: ConsumptionData

    # Cryptographic proof
    proof: ConsumptionAttestationProof


class DiscoveryQuery(BaseModel):
    """
    Discovery query for finding services.
    Cross-ref: Patent #26, Section 2.5
    """

    capability: str | None = None       # Wildcard pattern (e.g., "weather:*")
    max_price_cents: int | None = None
    min_uptime_basis_points: int | None = None
    min_trust_level: int | None = None
    currency: str | None = None
    limit: int = 20
    offset: int = 0


class DiscoveryResult(BaseModel):
    """Discovery result - gate matching query criteria."""

    gate_id: str
    gate_name: str | None = None
    trust_level: int
    services: list[ServiceAdvertisement]
    catalog_version: int
    catalog_content_hash: str | None = None


class BillingPeriod(BaseModel):
    """
    Billing aggregation for settlement.
    Cross-ref: Patent #27, Section 3.2
    """

    period_start: str  # RFC3339
    period_end: str    # RFC3339
    agent_id: str
    gate_id: str

    # Aggregated totals
    total_calls: int
    total_cost_cents: int
    total_platform_fee_cents: int

    # Attestation references for audit
    attestation_ids: list[str]

    # Merkle root for session digest mode
    merkle_root: str | None = None
