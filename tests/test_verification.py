"""
Verification Tests

Tests for the 9-step verification algorithm.
"""

from datetime import datetime, timedelta, timezone

import pytest

from uniplex_mcp.types import (
    CachedCatalog,
    Catalog,
    CatalogPermission,
    DenialCode,
    Passport,
    PermissionClaim,
    RiskLevel,
    TrustTier,
)
from uniplex_mcp.verification import (
    merge_constraints,
    RateLimiter,
    validate_constraints,
    verify_locally,
)


def make_passport(
    permissions: list[str] | None = None,
    constraints: dict | None = None,
    expired: bool = False,
    issuer_id: str = "issuer_test",
    passport_id: str = "pp_test_123",
) -> Passport:
    """Helper to create test passports."""
    if permissions is None:
        permissions = ["test:action"]
    
    now = datetime.now(timezone.utc)
    if expired:
        expires = now - timedelta(hours=1)
    else:
        expires = now + timedelta(hours=24)
    
    claims = [
        PermissionClaim(key=p, constraints=constraints or {})
        for p in permissions
    ]
    
    passport = Passport(
        passport_id=passport_id,
        agent_id="agent_test",
        issuer_id=issuer_id,
        gate_id="gate_test",
        trust_tier=TrustTier.L1,
        permissions=claims,
        constraints={},
        issued_at=now.isoformat(),
        expires_at=expires.isoformat(),
        signature="test_signature",
    )
    
    # Build index
    passport.claims_by_key = {p.key: p for p in passport.permissions}
    
    return passport


def make_catalog(
    permissions: list[str] | None = None,
    constraints: dict | None = None,
) -> CachedCatalog:
    """Helper to create test catalogs."""
    if permissions is None:
        permissions = ["test:action"]
    
    catalog_permissions = [
        CatalogPermission(
            key=p,
            description=f"Test {p}",
            risk_level=RiskLevel.LOW,
            constraints=constraints or {"core:rate:max_per_hour": 100},
        )
        for p in permissions
    ]
    
    catalog = Catalog(
        gate_id="gate_test",
        version=1,
        min_compatible_version=1,
        permissions=catalog_permissions,
        content_hash="test_hash",
        signature="test_signature",
    )
    
    # Build index
    catalog.permissions_by_key = {p.key: p for p in catalog.permissions}
    
    return CachedCatalog(
        gate_id="gate_test",
        current=catalog,
        versions={1: catalog},
        fetched_at=datetime.now(timezone.utc),
    )


class TestVerifyLocally:
    """Tests for the 9-step verification algorithm."""
    
    def test_no_passport(self):
        """Step 1: No passport should deny."""
        result = verify_locally(
            passport=None,
            action="test:action",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.NO_PASSPORT
    
    def test_unknown_issuer(self):
        """Step 2: Unknown issuer should deny."""
        result = verify_locally(
            passport=make_passport(issuer_id="unknown_issuer"),
            action="test:action",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},  # different issuer
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.ISSUER_NOT_TRUSTED
    
    def test_expired_passport(self):
        """Step 3: Expired passport should deny."""
        result = verify_locally(
            passport=make_passport(expired=True),
            action="test:action",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.PASSPORT_EXPIRED
    
    def test_revoked_passport(self):
        """Step 4: Revoked passport should deny."""
        result = verify_locally(
            passport=make_passport(passport_id="pp_revoked"),
            action="test:action",
            context={},
            catalog=make_catalog(),
            revocation_set={"pp_revoked"},
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.PASSPORT_REVOKED
    
    def test_permission_not_in_catalog(self):
        """Step 6: Permission not in catalog should deny."""
        result = verify_locally(
            passport=make_passport(permissions=["other:action"]),
            action="other:action",
            context={},
            catalog=make_catalog(permissions=["test:action"]),  # different permission
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.PERMISSION_NOT_IN_CATALOG
    
    def test_permission_not_in_passport(self):
        """Step 7: Permission not in passport should deny."""
        result = verify_locally(
            passport=make_passport(permissions=["other:action"]),
            action="test:action",
            context={},
            catalog=make_catalog(permissions=["test:action"]),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.PERMISSION_NOT_IN_PASSPORT
    
    def test_constraint_exceeded(self):
        """Step 8: Constraint exceeded should deny."""
        result = verify_locally(
            passport=make_passport(
                permissions=["test:action"],
                constraints={"core:cost:max": 100},
            ),
            action="test:action",
            context={"amount_canonical": 500},  # Exceeds max 100
            catalog=make_catalog(
                permissions=["test:action"],
                constraints={"core:cost:max": 1000},
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.CONSTRAINT_EXCEEDED
    
    def test_rate_limit_exceeded(self):
        """Step 9: Rate limit exceeded should deny."""
        rate_limiter = RateLimiter()
        rate_limiter.set_limit("test:action", 2)
        
        passport = make_passport()
        catalog = make_catalog()
        issuer_keys = {"issuer_test": "0" * 64}
        
        # First two calls should pass
        for _ in range(2):
            result = verify_locally(
                passport=passport,
                action="test:action",
                context={},
                catalog=catalog,
                revocation_set=set(),
                issuer_keys=issuer_keys,
                rate_limiter=rate_limiter,
                skip_signature_verification=True,
            )
            assert result.allowed
            rate_limiter.record(passport.passport_id, "test:action")
        
        # Third call should fail
        result = verify_locally(
            passport=passport,
            action="test:action",
            context={},
            catalog=catalog,
            revocation_set=set(),
            issuer_keys=issuer_keys,
            rate_limiter=rate_limiter,
            skip_signature_verification=True,
        )
        
        assert not result.allowed
        assert result.denial.code == DenialCode.RATE_LIMIT_EXCEEDED
    
    def test_successful_verification(self):
        """All steps pass should allow."""
        result = verify_locally(
            passport=make_passport(
                permissions=["test:action"],
                constraints={"core:cost:max": 500},
            ),
            action="test:action",
            context={"amount_canonical": 100},
            catalog=make_catalog(
                permissions=["test:action"],
                constraints={"core:cost:max": 1000, "core:rate:max_per_hour": 100},
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert result.allowed
        assert result.confident
        assert result.effective_constraints is not None
    
    def test_effective_constraints_merged(self):
        """Effective constraints should merge passport and catalog."""
        result = verify_locally(
            passport=make_passport(
                permissions=["test:action"],
                constraints={"core:cost:max": 500},  # Passport is more restrictive
            ),
            action="test:action",
            context={},
            catalog=make_catalog(
                permissions=["test:action"],
                constraints={"core:cost:max": 1000, "core:rate:max_per_hour": 100},
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )
        
        assert result.allowed
        # Limit constraint should use min (500 < 1000)
        assert result.effective_constraints["core:cost:max"] == 500
        # Other constraints should be present
        assert result.effective_constraints["core:rate:max_per_hour"] == 100


class TestMergeConstraints:
    """Tests for constraint merging."""
    
    def test_limit_constraint_uses_min(self):
        """Limit constraints use min-merge (most restrictive wins)."""
        result = merge_constraints(
            {"core:cost:max": 1000},
            {"core:cost:max": 500},
        )
        assert result["core:cost:max"] == 500
    
    def test_term_constraint_gate_authoritative(self):
        """Term constraints are gate-authoritative."""
        result = merge_constraints(
            {"core:pricing:per_call_cents": 100},
            {"core:pricing:per_call_cents": 50},  # Should be ignored
        )
        assert result["core:pricing:per_call_cents"] == 100
    
    def test_mixed_constraints(self):
        """Mix of limit and term constraints."""
        result = merge_constraints(
            {
                "core:cost:max": 1000,
                "core:pricing:per_call_cents": 100,
            },
            {
                "core:cost:max": 500,
                "core:pricing:per_call_cents": 50,
            },
        )
        assert result["core:cost:max"] == 500  # Limit: min-merge
        assert result["core:pricing:per_call_cents"] == 100  # Term: gate wins


class TestValidateConstraints:
    """Tests for constraint validation."""
    
    def test_amount_within_limit(self):
        valid, _ = validate_constraints(
            {"core:cost:max": 500},
            {"core:cost:max": 1000},
            {"amount_canonical": 400},
        )
        assert valid
    
    def test_amount_exceeds_limit(self):
        valid, msg = validate_constraints(
            {"core:cost:max": 500},
            {"core:cost:max": 1000},
            {"amount_canonical": 600},
        )
        assert not valid
        assert "exceeds" in msg.lower()
    
    def test_no_amount_in_context(self):
        """No amount in context should pass."""
        valid, _ = validate_constraints(
            {"core:cost:max": 500},
            {"core:cost:max": 1000},
            {},
        )
        assert valid


class TestRateLimiter:
    """Tests for rate limiter."""
    
    def test_no_limit_configured(self):
        limiter = RateLimiter()
        assert limiter.check("pp_123", "any:action") is True
    
    def test_within_limit(self):
        limiter = RateLimiter()
        limiter.set_limit("test:action", 5)
        
        for i in range(5):
            assert limiter.check("pp_123", "test:action") is True
            limiter.record("pp_123", "test:action")
    
    def test_exceeds_limit(self):
        limiter = RateLimiter()
        limiter.set_limit("test:action", 2)
        
        limiter.record("pp_123", "test:action")
        limiter.record("pp_123", "test:action")
        
        assert limiter.check("pp_123", "test:action") is False
    
    def test_separate_passports(self):
        """Different passports have separate limits."""
        limiter = RateLimiter()
        limiter.set_limit("test:action", 1)
        
        limiter.record("pp_123", "test:action")
        
        # pp_123 should be blocked
        assert limiter.check("pp_123", "test:action") is False
        
        # pp_456 should be allowed
        assert limiter.check("pp_456", "test:action") is True
    
    def test_reset(self):
        limiter = RateLimiter()
        limiter.set_limit("test:action", 1)
        limiter.record("pp_123", "test:action")
        
        assert limiter.check("pp_123", "test:action") is False
        
        limiter.reset()
        
        assert limiter.check("pp_123", "test:action") is True
