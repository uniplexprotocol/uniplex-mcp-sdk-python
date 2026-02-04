"""
Uniplex MCP Server

Permission-aware tool execution for AI agents.
"""

from .cache import CacheManager
from .commerce import (
    aggregate_attestations,
    compute_call_cost,
    compute_time_cost,
    extract_platform_fee_constraints,
    extract_pricing_constraints,
    extract_sla_constraints,
    generate_request_nonce,
    issue_consumption_attestation,
    matches_discovery_criteria,
    meets_sla_requirements,
    verify_consumption_attestation,
)
from .server import UniplexMCPServer, define_tool
from .session import SessionManager, SessionWrapper
from .transforms import (
    compute_platform_fee,
    dollars_to_cents,
    transform_to_canonical,
    TransformError,
)
from .types import (
    BillingPeriod,
    CachedCatalog,
    Catalog,
    CatalogPermission,
    ConstraintConfig,
    ConstraintType,
    CONSTRAINT_TYPES,
    ConsumptionAttestation,
    ConsumptionData,
    Denial,
    DenialCode,
    DiscoveryQuery,
    DiscoveryResult,
    EffectiveConstraints,
    Passport,
    PermissionClaim,
    PlatformFeeConstraints,
    PricingConstraints,
    PricingModel,
    RequestNonce,
    RiskLevel,
    ServerConfig,
    ServiceAdvertisement,
    SessionState,
    SLAConstraints,
    ToolDefinition,
    ToolUniplexMetadata,
    TransformMode,
    TrustTier,
    VerifyRequest,
    VerifyResult,
)
from .verification import (
    build_passport_index,
    merge_constraints,
    RateLimiter,
    validate_constraints,
    verify_locally,
    verify_signature,
)

__version__ = "1.1.1"

__all__ = [
    # Server
    "UniplexMCPServer",
    "define_tool",
    # Cache
    "CacheManager",
    # Session
    "SessionManager",
    "SessionWrapper",
    # Transforms
    "transform_to_canonical",
    "dollars_to_cents",
    "compute_platform_fee",
    "TransformError",
    # Verification
    "verify_locally",
    "verify_signature",
    "validate_constraints",
    "merge_constraints",
    "build_passport_index",
    "RateLimiter",
    # Commerce (Uni-Commerce Profile)
    "issue_consumption_attestation",
    "verify_consumption_attestation",
    "generate_request_nonce",
    "aggregate_attestations",
    "matches_discovery_criteria",
    "meets_sla_requirements",
    "compute_call_cost",
    "compute_time_cost",
    "extract_pricing_constraints",
    "extract_sla_constraints",
    "extract_platform_fee_constraints",
    # Types
    "BillingPeriod",
    "CachedCatalog",
    "Catalog",
    "CatalogPermission",
    "ConstraintConfig",
    "ConstraintType",
    "CONSTRAINT_TYPES",
    "ConsumptionAttestation",
    "ConsumptionData",
    "Denial",
    "DenialCode",
    "DiscoveryQuery",
    "DiscoveryResult",
    "EffectiveConstraints",
    "Passport",
    "PermissionClaim",
    "PlatformFeeConstraints",
    "PricingConstraints",
    "PricingModel",
    "RequestNonce",
    "RiskLevel",
    "ServerConfig",
    "ServiceAdvertisement",
    "SessionState",
    "SLAConstraints",
    "ToolDefinition",
    "ToolUniplexMetadata",
    "TransformMode",
    "TrustTier",
    "VerifyRequest",
    "VerifyResult",
    # Version
    "__version__",
]
