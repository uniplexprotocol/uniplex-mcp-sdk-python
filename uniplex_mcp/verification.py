"""
Uniplex MCP Server - Verification Module
Version: 1.2.0

CRITICAL: This module implements local verification.
verify_locally() MUST NOT make network calls.

Three-tier decision model (§14B.2):
  BLOCK   → wire "deny", no obligations
  SUSPEND → wire "deny" + reason_codes + obligations
  PERMIT  → wire "permit"

Cross-ref: MCP Server Spec Section 1.3 (Hot Path Rules)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from .types import (
    AnonymousAccessPolicy,
    CachedCatalog,
    Catalog,
    CONSTRAINT_TYPES,
    Denial,
    DenyReason,
    Passport,
    VerifyResult,
    OBLIGATION_TOKENS,
    CONSTRAINT_KEYS,
)

from uniplex.constraints import (
    CELResult,
    evaluate_constraints,
)
from uniplex.anonymous import (
    evaluate_anonymous_access,
    MemoryAnonymousRateLimiter,
    AnonymousDecision,
)


# =============================================================================
# RATE LIMITER (LOCAL, IN-MEMORY)
# =============================================================================

class RateLimiter:
    """
    In-memory rate limiter for per-action, per-passport tracking.

    Uses sliding window algorithm.
    """

    def __init__(self) -> None:
        # {(passport_id, action): [timestamps]}
        self._windows: dict[tuple[str, str], list[float]] = defaultdict(list)
        # {action: max_per_hour} from catalog
        self._limits: dict[str, int] = {}

    def set_limit(self, action: str, max_per_hour: int) -> None:
        """Set rate limit for an action."""
        self._limits[action] = max_per_hour

    def check(self, passport_id: str, action: str) -> bool:
        """
        Check if action is within rate limit.

        Returns True if allowed, False if exceeded.
        Does NOT consume a slot - call record() after successful execution.
        """
        limit = self._limits.get(action)
        if limit is None:
            return True  # No limit configured

        key = (passport_id, action)
        now = time.time()
        window_start = now - 3600  # 1 hour window

        # Clean old entries
        self._windows[key] = [t for t in self._windows[key] if t > window_start]

        return len(self._windows[key]) < limit

    def record(self, passport_id: str, action: str) -> None:
        """Record an action execution."""
        key = (passport_id, action)
        self._windows[key].append(time.time())

    def reset(self) -> None:
        """Reset all rate limit state."""
        self._windows.clear()


# =============================================================================
# SIGNATURE VERIFICATION
# =============================================================================

def verify_signature(
    passport: Passport,
    issuer_public_key: str,
    skip_verification: bool = False,
) -> bool:
    """
    Verify passport signature using issuer's Ed25519 public key.

    NORMATIVE: Passports are signed by issuers, verified with issuer keys.
    Gates NEVER use their own keys for passport verification.
    """
    if skip_verification:
        return True

    try:
        # Construct signing input (canonical JSON of passport fields minus signature)
        passport_dict = passport.model_dump(exclude={"signature", "claims_by_key"})
        signing_input = _canonical_json(passport_dict)

        # Verify Ed25519 signature
        verify_key = VerifyKey(bytes.fromhex(issuer_public_key))
        signature_bytes = bytes.fromhex(passport.signature)

        verify_key.verify(signing_input.encode(), signature_bytes)
        return True
    except (BadSignatureError, ValueError):
        return False


def _canonical_json(obj: Any) -> str:
    """
    Canonical JSON serialization (sorted keys, no whitespace).

    This must match the TypeScript canonicalStringify exactly.
    """
    import json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


# =============================================================================
# CATALOG VERSION RESOLUTION
# =============================================================================

def resolve_catalog_version(
    catalog: CachedCatalog,
    passport: Passport,
) -> tuple[Catalog | None, DenyReason | None]:
    """
    Resolve effective catalog version based on passport's version pin.

    Per Permission Catalog Spec Section 16.5.

    Returns:
        (resolved_catalog, error_code) - error_code is None if successful
    """
    pin = None
    if passport.catalog_version_pin:
        pin = passport.catalog_version_pin.get(catalog.gate_id)

    if pin is None:
        # No pin → use current version
        return catalog.current, None

    # Check if pinned version is deprecated
    if pin < catalog.current.min_compatible_version:
        return None, DenyReason.CATALOG_VERSION_DEPRECATED

    # Try to get pinned version from cache
    if pin in catalog.versions:
        return catalog.versions[pin], None

    # Pinned version not in cache - fall back to current
    return catalog.current, None


# =============================================================================
# CONSTRAINT VALIDATION (legacy — used as fallback)
# =============================================================================

def validate_constraints(
    passport_constraints: dict[str, Any],
    catalog_constraints: dict[str, Any],
    context: dict[str, Any],
) -> tuple[bool, str | None]:
    """
    Validate request context against effective constraints.

    Limit constraints use min-merge (most restrictive wins).
    Term constraints are gate-authoritative.

    Returns:
        (valid, error_message)
    """
    # Merge constraints
    effective = merge_constraints(catalog_constraints, passport_constraints)

    # Check core:cost:max_per_action against context.amount_canonical
    if "core:cost:max_per_action" in effective:
        max_cost = effective["core:cost:max_per_action"]
        amount = context.get("amount_canonical")

        if amount is not None and amount > max_cost:
            return False, f"Amount {amount} exceeds max {max_cost}"

    return True, None


def merge_constraints(
    catalog_constraints: dict[str, Any],
    passport_constraints: dict[str, Any],
) -> dict[str, Any]:
    """
    Merge catalog and passport constraints.

    - Limit constraints: min-merge (most restrictive wins)
    - Term constraints: gate-authoritative (catalog value used)
    """
    effective: dict[str, Any] = {}

    # Start with catalog constraints
    effective.update(catalog_constraints)

    # Apply passport constraints based on type
    for key, value in passport_constraints.items():
        constraint_info = CONSTRAINT_TYPES.get(key, {"type": "limit"})

        if constraint_info["type"] == "term":
            # Term constraints are gate-authoritative - don't override
            continue

        # Limit constraints - use minimum (most restrictive)
        if key in effective:
            if isinstance(value, (int, float)) and isinstance(effective[key], (int, float)):
                effective[key] = min(effective[key], value)
            else:
                # Non-numeric - passport value takes precedence
                effective[key] = value
        else:
            effective[key] = value

    return effective


# =============================================================================
# HELPER: build a deny VerifyResult
# =============================================================================

def _deny(
    code: DenyReason,
    message: str,
    *,
    upgrade_template: Optional[str] = None,
    constraint_decision: Optional[str] = None,
    reason_codes: Optional[list[str]] = None,
    obligations: Optional[list[str]] = None,
) -> VerifyResult:
    return VerifyResult(
        allowed=False,
        decision="deny",
        constraint_decision=constraint_decision,
        reason_codes=reason_codes,
        obligations=obligations,
        denial=Denial(
            code=code,
            message=message,
            upgrade_template=upgrade_template,
        ),
        confident=True,
    )


# =============================================================================
# VERIFY LOCALLY — THE HOT PATH
# =============================================================================

def verify_locally(
    passport: Passport | None,
    action: str,
    context: dict[str, Any],
    catalog: CachedCatalog,
    revocation_set: set[str],
    issuer_keys: dict[str, str],
    rate_limiter: RateLimiter,
    skip_signature_verification: bool = False,
    *,
    anonymous_policy: Optional[AnonymousAccessPolicy] = None,
    anonymous_rate_limiter: Optional[MemoryAnonymousRateLimiter] = None,
    source_id: str = "unknown",
) -> VerifyResult:
    """
    LOCAL verification — no network calls.
    This is the hot path that runs on every tool call.

    Three-tier decision model (§14B.2):
      BLOCK   → deny, no obligations
      SUSPEND → deny with reason_codes=["approval_required"],
                obligations=["require_approval"]
      PERMIT  → allow

    Anti-downgrade (§14A.2): invalid/expired/revoked passports are ALWAYS denied.
      They MUST NOT fall back to anonymous access.

    NORMATIVE (RFC 2119):
    - MUST NOT make network calls
    - MUST complete in sub-millisecond time
    - MUST use cached data only

    Implements the 9-step algorithm from Section 1.3 + CEL (§14B).
    """

    # =========================================================================
    # Step 1: Check passport exists — if null, try anonymous policy
    # =========================================================================
    if passport is None:
        # No passport presented — check anonymous access policy
        if anonymous_policy is not None and anonymous_policy.enabled:
            limiter = anonymous_rate_limiter or MemoryAnonymousRateLimiter(
                per_minute=anonymous_policy.rate_limit_per_minute,
                per_hour=anonymous_policy.rate_limit_per_hour,
            )
            anon_result: Optional[AnonymousDecision] = evaluate_anonymous_access(
                passport=None,
                passport_validation_result=None,
                action=action,
                policy=anonymous_policy,
                rate_limiter=limiter,
                source_id=source_id,
            )

            if anon_result is not None and anon_result.allowed:
                return VerifyResult(
                    allowed=True,
                    decision="permit",
                    confident=True,
                )

            # Anonymous access denied — return upgrade info
            upgrade_msg = (
                anonymous_policy.upgrade_message
                or "Get a passport for full access and higher rate limits"
            )
            return _deny(DenyReason.PASSPORT_MISSING, upgrade_msg)

        return _deny(DenyReason.PASSPORT_MISSING, "No passport in session")

    # =========================================================================
    # Step 2: Verify signature using ISSUER's public key
    # Passports are signed by issuers; gate verifies using cached issuer keys
    # =========================================================================
    issuer_key = issuer_keys.get(passport.issuer_id)
    if issuer_key is None:
        # Anti-downgrade: unknown issuer with a passport → deny (NEVER fall to anon)
        return _deny(
            DenyReason.ISSUER_NOT_ALLOWED,
            f"Unknown issuer: {passport.issuer_id}",
            constraint_decision="BLOCK",
        )

    if not verify_signature(passport, issuer_key, skip_signature_verification):
        # Anti-downgrade: invalid signature → deny (NEVER fall to anon)
        return _deny(
            DenyReason.INVALID_SIGNATURE,
            "Passport signature invalid",
            constraint_decision="BLOCK",
        )

    # =========================================================================
    # Step 3: Check expiration (timezone-safe: expires_at is RFC3339)
    # Anti-downgrade: expired passport → deny (NEVER fall to anon)
    # =========================================================================
    try:
        expires_at = datetime.fromisoformat(passport.expires_at.replace("Z", "+00:00"))
        if expires_at < datetime.now(timezone.utc):
            return _deny(
                DenyReason.PASSPORT_EXPIRED,
                "Passport has expired",
                constraint_decision="BLOCK",
            )
    except ValueError:
        return _deny(
            DenyReason.PASSPORT_EXPIRED,
            "Invalid expiration format",
            constraint_decision="BLOCK",
        )

    # =========================================================================
    # Step 4: Check revocation (cached revocation list)
    # Anti-downgrade: revoked passport → deny (NEVER fall to anon)
    # =========================================================================
    if passport.passport_id in revocation_set:
        return _deny(
            DenyReason.PASSPORT_REVOKED,
            "Passport has been revoked",
            constraint_decision="BLOCK",
        )

    # =========================================================================
    # Step 5: Resolve catalog version
    # =========================================================================
    effective_catalog, version_error = resolve_catalog_version(catalog, passport)
    if version_error is not None:
        return _deny(
            version_error,
            f"Catalog version error: {version_error}",
            constraint_decision="BLOCK",
        )

    assert effective_catalog is not None

    # =========================================================================
    # Step 6: Permission lookup in CATALOG (Gate Authority Principle)
    # =========================================================================
    catalog_entry = effective_catalog.permissions_by_key.get(action)
    if catalog_entry is None:
        return _deny(
            DenyReason.PERMISSION_DENIED,
            f"{action} not in gate catalog",
            constraint_decision="BLOCK",
        )

    # =========================================================================
    # Step 7: Permission lookup in PASSPORT
    # O(1) lookup using claims_by_key built at passport load time
    # =========================================================================
    passport_permission = passport.claims_by_key.get(action)
    if passport_permission is None:
        return _deny(
            DenyReason.PERMISSION_DENIED,
            f"Passport lacks {action} permission",
            upgrade_template=catalog_entry.default_template,
            constraint_decision="BLOCK",
        )

    # =========================================================================
    # Step 8: Constraint Enforcement Layer (CEL — §14B)
    #
    # Evaluate constraints in category order:
    #   Temporal → Scope → Rate → Cost → Approval → Data
    # with BLOCK > SUSPEND > PERMIT precedence.
    #
    # Commerce constraints (70+) are pass-through.
    # =========================================================================
    effective_constraints = merge_constraints(
        catalog_entry.constraints,
        passport_permission.constraints,
    )

    # Use protocol SDK's evaluate_constraints for full CEL evaluation
    cost_cents = context.get("amount_canonical")
    if not isinstance(cost_cents, int):
        cost_cents = None

    cel_result: CELResult = evaluate_constraints(
        constraints=effective_constraints,
        action=action,
        cost_cents=cost_cents,
        metadata=context,
    )

    if cel_result.decision == "BLOCK":
        # Find the first BLOCK evaluation for the message
        block_eval = next(
            (e for e in cel_result.evaluations if e.decision == "BLOCK"),
            None,
        )
        return _deny(
            DenyReason.CONSTRAINT_VIOLATED,
            block_eval.reason if block_eval and block_eval.reason else "Constraint violation",
            constraint_decision="BLOCK",
        )

    if cel_result.decision == "SUSPEND":
        return _deny(
            DenyReason.APPROVAL_REQUIRED,
            "Action requires approval before proceeding",
            constraint_decision="SUSPEND",
            reason_codes=cel_result.reason_codes or ["approval_required"],
            obligations=(
                cel_result.obligations
                if cel_result.obligations
                else [OBLIGATION_TOKENS.REQUIRE_APPROVAL]
            ),
        )

    # Also run legacy constraint validation for backward compat with custom keys
    valid, error_msg = validate_constraints(
        passport_permission.constraints,
        catalog_entry.constraints,
        context,
    )
    if not valid:
        return _deny(
            DenyReason.CONSTRAINT_VIOLATED,
            error_msg or "Constraint validation failed",
            constraint_decision="BLOCK",
        )

    # =========================================================================
    # Step 9: Check rate limits (local counters)
    # =========================================================================
    if not rate_limiter.check(passport.passport_id, action):
        return _deny(
            DenyReason.RATE_LIMITED,
            "Rate limit exceeded",
            constraint_decision="BLOCK",
        )

    # All checks passed — record rate limit usage and return success
    rate_limiter.record(passport.passport_id, action)

    return VerifyResult(
        allowed=True,
        decision="permit",
        constraint_decision="PERMIT",
        effective_constraints=effective_constraints,
        confident=True,
    )


# =============================================================================
# PASSPORT UTILITIES
# =============================================================================

def build_passport_index(passport: Passport) -> Passport:
    """
    Build claims_by_key index for O(1) permission lookup.

    Call this when loading a passport from storage/network.
    """
    passport.claims_by_key = {p.key: p for p in passport.permissions}
    return passport
