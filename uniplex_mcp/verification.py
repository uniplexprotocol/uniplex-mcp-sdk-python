"""
Uniplex MCP Server Verification

9-step local verification algorithm from MCP Server Specification v1.0.0 Section 1.3.
MUST NOT make any network calls - all data comes from cache.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from .types import (
    CachedCatalog,
    Catalog,
    CONSTRAINT_TYPES,
    Denial,
    DenialCode,
    Passport,
    VerifyResult,
)


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


def verify_signature(
    passport: Passport,
    issuer_public_key: str,
    skip_verification: bool = False,
) -> bool:
    """
    Verify passport signature using issuer's Ed25519 public key.
    
    Args:
        passport: The passport to verify
        issuer_public_key: Hex-encoded Ed25519 public key
        skip_verification: Skip verification (for testing)
    
    Returns:
        True if signature is valid
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


def resolve_catalog_version(
    catalog: CachedCatalog,
    passport: Passport,
) -> tuple[Catalog | None, DenialCode | None]:
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
        return None, DenialCode.CATALOG_VERSION_DEPRECATED
    
    # Try to get pinned version from cache
    if pin in catalog.versions:
        return catalog.versions[pin], None
    
    # Pinned version not in cache - fall back to current
    # (In production, might want to fetch the specific version)
    return catalog.current, None


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
    
    # Check core:cost:max against context.amount_canonical
    if "core:cost:max" in effective:
        max_cost = effective["core:cost:max"]
        amount = context.get("amount_canonical")
        
        if amount is not None and amount > max_cost:
            return False, f"Amount {amount} exceeds max {max_cost}"
    
    # Check core:rate:max_per_hour (handled by rate limiter, not here)
    # Check core:rate:max_per_day (handled by rate limiter, not here)
    
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


def verify_locally(
    passport: Passport | None,
    action: str,
    context: dict[str, Any],
    catalog: CachedCatalog,
    revocation_set: set[str],
    issuer_keys: dict[str, str],
    rate_limiter: RateLimiter,
    skip_signature_verification: bool = False,
) -> VerifyResult:
    """
    9-step local verification algorithm.
    
    CRITICAL: This function MUST NOT make any network calls.
    All data comes from pre-cached sources.
    
    Args:
        passport: The passport to verify (None if no passport)
        action: Permission key being exercised
        context: Request context including amount_canonical
        catalog: Cached catalog for the gate
        revocation_set: Set of revoked passport IDs
        issuer_keys: Map of issuer_id -> public_key (hex)
        rate_limiter: Rate limiter instance
        skip_signature_verification: Skip signature check (testing only)
    
    Returns:
        VerifyResult with allowed status and effective constraints
    """
    
    # Step 1: Check passport exists
    if passport is None:
        return VerifyResult(
            allowed=False,
            denial=Denial(code=DenialCode.NO_PASSPORT, message="No passport in session"),
        )
    
    # Step 2: Signature verification using ISSUER's public key
    issuer_key = issuer_keys.get(passport.issuer_id)
    if issuer_key is None:
        return VerifyResult(
            allowed=False,
            denial=Denial(
                code=DenialCode.ISSUER_NOT_TRUSTED,
                message=f"Unknown issuer: {passport.issuer_id}",
            ),
        )
    
    if not verify_signature(passport, issuer_key, skip_signature_verification):
        return VerifyResult(
            allowed=False,
            denial=Denial(code=DenialCode.INVALID_SIGNATURE, message="Passport signature invalid"),
        )
    
    # Step 3: Expiration check (timezone-safe)
    try:
        expires_at = datetime.fromisoformat(passport.expires_at.replace("Z", "+00:00"))
        if expires_at < datetime.now(timezone.utc):
            return VerifyResult(
                allowed=False,
                denial=Denial(code=DenialCode.PASSPORT_EXPIRED, message="Passport has expired"),
            )
    except ValueError:
        return VerifyResult(
            allowed=False,
            denial=Denial(code=DenialCode.PASSPORT_EXPIRED, message="Invalid expiration format"),
        )
    
    # Step 4: Revocation check
    if passport.passport_id in revocation_set:
        return VerifyResult(
            allowed=False,
            denial=Denial(code=DenialCode.PASSPORT_REVOKED, message="Passport has been revoked"),
        )
    
    # Step 5: Resolve catalog version
    effective_catalog, version_error = resolve_catalog_version(catalog, passport)
    if version_error is not None:
        return VerifyResult(
            allowed=False,
            denial=Denial(code=version_error, message=f"Catalog version error: {version_error}"),
        )
    
    assert effective_catalog is not None
    
    # Step 6: Permission lookup in CATALOG (Gate Authority Principle)
    catalog_entry = effective_catalog.permissions_by_key.get(action)
    if catalog_entry is None:
        return VerifyResult(
            allowed=False,
            denial=Denial(
                code=DenialCode.PERMISSION_NOT_IN_CATALOG,
                message=f"{action} not in gate catalog",
            ),
        )
    
    # Step 7: Permission lookup in PASSPORT
    passport_permission = passport.claims_by_key.get(action)
    if passport_permission is None:
        return VerifyResult(
            allowed=False,
            denial=Denial(
                code=DenialCode.PERMISSION_NOT_IN_PASSPORT,
                message=f"Passport lacks {action} permission",
            ),
        )
    
    # Step 8: Constraint validation
    valid, error_msg = validate_constraints(
        passport_permission.constraints,
        catalog_entry.constraints,
        context,
    )
    if not valid:
        return VerifyResult(
            allowed=False,
            denial=Denial(
                code=DenialCode.CONSTRAINT_EXCEEDED,
                message=error_msg or "Constraint validation failed",
            ),
        )
    
    # Step 9: Rate limit check
    if not rate_limiter.check(passport.passport_id, action):
        return VerifyResult(
            allowed=False,
            denial=Denial(code=DenialCode.RATE_LIMIT_EXCEEDED, message="Rate limit exceeded"),
        )
    
    # All checks passed
    effective_constraints = merge_constraints(
        catalog_entry.constraints,
        passport_permission.constraints,
    )
    
    return VerifyResult(
        allowed=True,
        effective_constraints=effective_constraints,
        confident=True,
    )


def build_passport_index(passport: Passport) -> Passport:
    """
    Build claims_by_key index for O(1) permission lookup.
    
    Call this when loading a passport from storage/network.
    """
    passport.claims_by_key = {p.key: p for p in passport.permissions}
    return passport
