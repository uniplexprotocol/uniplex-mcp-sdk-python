"""
Uniplex MCP Server - Verification Tests

Tests for verify_locally 9-step algorithm with three-tier decision model.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from uniplex_mcp.types import (
    AnonymousAccessPolicy,
    CachedCatalog,
    Catalog,
    CatalogPermission,
    CONSTRAINT_KEYS,
    DenialCode,
    DenyReason,
    OBLIGATION_TOKENS,
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


# =========================================================================
# TEST FIXTURES
# =========================================================================

def make_passport(
    permissions: list[str] | None = None,
    constraints: dict | None = None,
    expired: bool = False,
    issuer_id: str = "issuer_test",
    passport_id: str = "pp_test_123",
    catalog_version_pin: dict | None = None,
    per_permission_constraints: dict[str, dict] | None = None,
) -> Passport:
    """Helper to create test passports."""
    if permissions is None:
        permissions = ["flights:search", "flights:book"]

    now = datetime.now(timezone.utc)
    if expired:
        expires = now - timedelta(hours=1)
    else:
        expires = now + timedelta(hours=24)

    if per_permission_constraints is not None:
        claims = [
            PermissionClaim(
                key=p,
                constraints=per_permission_constraints.get(p, {}),
            )
            for p in permissions
        ]
    else:
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
        catalog_version_pin=catalog_version_pin,
        signature="test_signature",
    )

    # Build index
    passport.claims_by_key = {p.key: p for p in passport.permissions}
    return passport


def make_catalog(
    permissions: list[str] | None = None,
    constraints: dict | None = None,
    per_permission_constraints: dict[str, dict] | None = None,
) -> CachedCatalog:
    """Helper to create test catalogs."""
    if permissions is None:
        permissions = [
            "flights:search", "flights:book", "admin:manage", "data:read",
        ]

    catalog_permissions = []
    for p in permissions:
        perm_constraints = {}
        if per_permission_constraints and p in per_permission_constraints:
            perm_constraints = per_permission_constraints[p]
        elif constraints is not None:
            perm_constraints = constraints
        else:
            perm_constraints = {"core:rate:max_per_hour": 100}

        catalog_permissions.append(
            CatalogPermission(
                key=p,
                description=f"Test {p}",
                risk_level=RiskLevel.LOW,
                constraints=perm_constraints,
                default_template="travel-booker" if p == "flights:book" else None,
            )
        )

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


# =========================================================================
# VERIFY LOCALLY TESTS (9-STEP ALGORITHM)
# =========================================================================

class TestVerifyLocally:
    """Tests for the 9-step verification algorithm."""

    # Step 1: Check passport exists

    def test_no_passport(self):
        """Step 1: No passport should deny with PASSPORT_MISSING."""
        result = verify_locally(
            passport=None,
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.PASSPORT_MISSING

    # Step 2: Signature verification (using issuer key)

    def test_unknown_issuer(self):
        """Step 2: Unknown issuer should deny with ISSUER_NOT_ALLOWED."""
        result = verify_locally(
            passport=make_passport(issuer_id="unknown_issuer"),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.ISSUER_NOT_ALLOWED

    # Step 3: Expiration check

    def test_expired_passport(self):
        """Step 3: Expired passport should deny with PASSPORT_EXPIRED."""
        result = verify_locally(
            passport=make_passport(expired=True),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.PASSPORT_EXPIRED

    # Step 4: Revocation check

    def test_revoked_passport(self):
        """Step 4: Revoked passport should deny with PASSPORT_REVOKED."""
        result = verify_locally(
            passport=make_passport(passport_id="pp_revoked"),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set={"pp_revoked"},
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.PASSPORT_REVOKED

    # Step 5: Catalog version resolution

    def test_deprecated_catalog_version(self):
        """Step 5: Deprecated catalog version should deny."""
        result = verify_locally(
            passport=make_passport(catalog_version_pin={"gate_test": 0}),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.CATALOG_VERSION_DEPRECATED

    # Step 6: Permission in catalog

    def test_permission_not_in_catalog(self):
        """Step 6: Permission not in catalog should deny with PERMISSION_DENIED."""
        result = verify_locally(
            passport=make_passport(permissions=["other:action"]),
            action="other:action",
            context={},
            catalog=make_catalog(permissions=["flights:search"]),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.PERMISSION_DENIED

    # Step 7: Permission in passport

    def test_permission_not_in_passport(self):
        """Step 7: Permission not in passport should deny with PERMISSION_DENIED."""
        result = verify_locally(
            passport=make_passport(permissions=["flights:search"]),
            action="admin:manage",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.PERMISSION_DENIED

    def test_upgrade_template_from_catalog(self):
        """Missing passport permission should include upgrade_template from catalog."""
        result = verify_locally(
            passport=make_passport(permissions=["flights:search"]),
            action="flights:book",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.denial.code == DenyReason.PERMISSION_DENIED
        assert result.denial.upgrade_template == "travel-booker"

    # Step 8: Constraint validation

    def test_constraint_exceeded(self):
        """Step 8: Constraint exceeded should deny."""
        result = verify_locally(
            passport=make_passport(
                permissions=["flights:book"],
                constraints={"core:cost:max_per_action": 100000},
            ),
            action="flights:book",
            context={"amount_canonical": 150000},
            catalog=make_catalog(
                per_permission_constraints={
                    "flights:book": {"core:cost:max_per_action": 500000},
                },
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"

    def test_constraint_within_limit(self):
        """Context within passport limit should allow."""
        result = verify_locally(
            passport=make_passport(
                permissions=["flights:book"],
                constraints={"core:cost:max_per_action": 100000},
            ),
            action="flights:book",
            context={"amount_canonical": 50000},
            catalog=make_catalog(
                per_permission_constraints={
                    "flights:book": {"core:cost:max_per_action": 500000},
                },
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert result.decision != "deny" or result.allowed

    # Step 9: Rate limit check

    def test_rate_limit_exceeded(self):
        """Step 9: Rate limit exceeded should deny with RATE_LIMITED."""
        rate_limiter = RateLimiter()
        rate_limiter.set_limit("flights:search", 2)

        passport = make_passport()
        catalog = make_catalog()
        issuer_keys = {"issuer_test": "0" * 64}

        # First two calls should pass (verify_locally auto-records)
        for _ in range(2):
            result = verify_locally(
                passport=passport,
                action="flights:search",
                context={},
                catalog=catalog,
                revocation_set=set(),
                issuer_keys=issuer_keys,
                rate_limiter=rate_limiter,
                skip_signature_verification=True,
            )
            assert result.allowed

        # Third call should fail
        result = verify_locally(
            passport=passport,
            action="flights:search",
            context={},
            catalog=catalog,
            revocation_set=set(),
            issuer_keys=issuer_keys,
            rate_limiter=rate_limiter,
            skip_signature_verification=True,
        )

        assert not result.allowed
        assert result.decision == "deny"
        assert result.denial.code == DenyReason.RATE_LIMITED

    # Successful verification

    def test_successful_verification(self):
        """All steps pass should allow."""
        result = verify_locally(
            passport=make_passport(
                permissions=["flights:book"],
                constraints={"core:cost:max_per_action": 500},
            ),
            action="flights:book",
            context={"amount_canonical": 100},
            catalog=make_catalog(
                per_permission_constraints={
                    "flights:book": {
                        "core:cost:max_per_action": 1000,
                        "core:rate:max_per_hour": 100,
                    },
                },
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert result.allowed
        assert result.decision == "permit"
        assert result.confident
        assert result.effective_constraints is not None

    def test_effective_constraints_merged(self):
        """Effective constraints should merge passport and catalog."""
        result = verify_locally(
            passport=make_passport(
                permissions=["flights:book"],
                constraints={"core:cost:max_per_action": 500},
            ),
            action="flights:book",
            context={},
            catalog=make_catalog(
                per_permission_constraints={
                    "flights:book": {
                        "core:cost:max_per_action": 1000,
                        "core:rate:max_per_hour": 100,
                    },
                },
            ),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert result.allowed
        # Limit constraint should use min (500 < 1000)
        assert result.effective_constraints["core:cost:max_per_action"] == 500
        # Other constraints should be present
        assert result.effective_constraints["core:rate:max_per_hour"] == 100


# =========================================================================
# THREE-TIER DECISION MODEL
# =========================================================================

class TestThreeTierDecisionModel:
    """Tests for three-tier PERMIT/BLOCK/SUSPEND decision model."""

    def test_permit_decision(self):
        """Returns decision 'permit' with constraint_decision PERMIT on success."""
        result = verify_locally(
            passport=make_passport(),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert result.allowed is True
        assert result.decision == "permit"
        assert result.constraint_decision == "PERMIT"
        assert result.reason_codes is None
        assert result.obligations is None

    def test_block_decision(self):
        """Returns BLOCK constraint_decision on hard deny."""
        result = verify_locally(
            passport=make_passport(expired=True),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert result.allowed is False
        assert result.decision == "deny"
        assert result.constraint_decision == "BLOCK"
        assert result.obligations is None

    def test_suspend_decision(self):
        """SUSPEND maps to wire 'deny' with reason_codes and obligations."""
        result = verify_locally(
            passport=make_passport(
                permissions=["flights:search"],
                constraints={"core:approval:required": True},
            ),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        assert result.allowed is False
        assert result.decision == "deny"
        assert result.constraint_decision == "SUSPEND"
        assert "approval_required" in result.reason_codes
        assert OBLIGATION_TOKENS.REQUIRE_APPROVAL in result.obligations
        assert result.denial.code == DenyReason.APPROVAL_REQUIRED


# =========================================================================
# BLOCK > SUSPEND > PERMIT PRECEDENCE
# =========================================================================

class TestPrecedence:
    """BLOCK > SUSPEND > PERMIT precedence tests."""

    def test_block_wins_over_suspend(self):
        """BLOCK wins over SUSPEND — expired passport with approval_required."""
        result = verify_locally(
            passport=make_passport(
                expired=True,
                permissions=["flights:search"],
                constraints={"core:approval:required": True},
            ),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
        )

        # Expiration (BLOCK) should prevent even reaching the CEL layer
        assert result.constraint_decision == "BLOCK"
        assert result.obligations is None


# =========================================================================
# ANTI-DOWNGRADE (§14A.2)
# =========================================================================

class TestAntiDowngrade:
    """Anti-downgrade: invalid passports NEVER fall back to anonymous."""

    ANON_POLICY = AnonymousAccessPolicy(
        enabled=True,
        allowed_actions=["flights:search", "data:read"],
        read_only=True,
        rate_limit_per_minute=5,
        rate_limit_per_hour=50,
    )

    def test_expired_passport_denied_even_with_anonymous(self):
        result = verify_locally(
            passport=make_passport(expired=True),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
            anonymous_policy=self.ANON_POLICY,
        )

        assert not result.allowed
        assert result.denial.code == DenyReason.PASSPORT_EXPIRED

    def test_revoked_passport_denied_even_with_anonymous(self):
        result = verify_locally(
            passport=make_passport(passport_id="pp_test_123"),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set={"pp_test_123"},
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
            anonymous_policy=self.ANON_POLICY,
        )

        assert not result.allowed
        assert result.denial.code == DenyReason.PASSPORT_REVOKED

    def test_unknown_issuer_denied_even_with_anonymous(self):
        result = verify_locally(
            passport=make_passport(issuer_id="unknown_issuer"),
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
            anonymous_policy=self.ANON_POLICY,
        )

        assert not result.allowed
        assert result.denial.code == DenyReason.ISSUER_NOT_ALLOWED


# =========================================================================
# ANONYMOUS ACCESS POLICY (§14A)
# =========================================================================

class TestAnonymousAccess:
    """Anonymous access policy tests."""

    ANON_POLICY = AnonymousAccessPolicy(
        enabled=True,
        allowed_actions=["flights:search", "data:read"],
        read_only=True,
        rate_limit_per_minute=5,
        rate_limit_per_hour=50,
        upgrade_message="Get a passport for full access",
    )

    def test_allows_anonymous_for_listed_actions(self):
        result = verify_locally(
            passport=None,
            action="data:read",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
            anonymous_policy=self.ANON_POLICY,
            source_id="test-client",
        )

        assert result.allowed is True
        assert result.decision == "permit"

    def test_denies_anonymous_for_unlisted_actions(self):
        result = verify_locally(
            passport=None,
            action="admin:manage",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
            anonymous_policy=self.ANON_POLICY,
            source_id="test-client",
        )

        assert result.allowed is False
        assert result.decision == "deny"

    def test_passport_missing_when_anonymous_disabled(self):
        result = verify_locally(
            passport=None,
            action="flights:search",
            context={},
            catalog=make_catalog(),
            revocation_set=set(),
            issuer_keys={"issuer_test": "0" * 64},
            rate_limiter=RateLimiter(),
            skip_signature_verification=True,
            anonymous_policy=AnonymousAccessPolicy(
                enabled=False,
                allowed_actions=[],
            ),
        )

        assert result.allowed is False
        assert result.denial.code == DenyReason.PASSPORT_MISSING


# =========================================================================
# CONSTRAINT MERGE TESTS
# =========================================================================

class TestMergeConstraints:
    """Tests for constraint merging."""

    def test_limit_constraint_uses_min(self):
        """Limit constraints use min-merge (most restrictive wins)."""
        result = merge_constraints(
            {"core:cost:max_per_action": 1000},
            {"core:cost:max_per_action": 500},
        )
        assert result["core:cost:max_per_action"] == 500

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
                "core:cost:max_per_action": 1000,
                "core:pricing:per_call_cents": 100,
            },
            {
                "core:cost:max_per_action": 500,
                "core:pricing:per_call_cents": 50,
            },
        )
        assert result["core:cost:max_per_action"] == 500  # Limit: min-merge
        assert result["core:pricing:per_call_cents"] == 100  # Term: gate wins

    def test_merges_multiple_limit_constraints(self):
        result = merge_constraints(
            {"core:cost:max_per_action": 500000, "core:rate:max_per_hour": 1000},
            {"core:cost:max_per_action": 100000, "core:rate:max_per_hour": 500},
        )
        assert result["core:cost:max_per_action"] == 100000
        assert result["core:rate:max_per_hour"] == 500


# =========================================================================
# CONSTRAINT VALIDATION TESTS
# =========================================================================

class TestValidateConstraints:
    """Tests for constraint validation."""

    def test_amount_within_limit(self):
        valid, _ = validate_constraints(
            {"core:cost:max_per_action": 500},
            {"core:cost:max_per_action": 1000},
            {"amount_canonical": 400},
        )
        assert valid

    def test_amount_exceeds_limit(self):
        valid, msg = validate_constraints(
            {"core:cost:max_per_action": 500},
            {"core:cost:max_per_action": 1000},
            {"amount_canonical": 600},
        )
        assert not valid
        assert "exceeds" in msg.lower()

    def test_no_amount_in_context(self):
        """No amount in context should pass."""
        valid, _ = validate_constraints(
            {"core:cost:max_per_action": 500},
            {"core:cost:max_per_action": 1000},
            {},
        )
        assert valid


# =========================================================================
# RATE LIMITER TESTS
# =========================================================================

class TestRateLimiter:
    """Tests for rate limiter."""

    def test_no_limit_configured(self):
        limiter = RateLimiter()
        assert limiter.check("pp_123", "any:action") is True

    def test_within_limit(self):
        limiter = RateLimiter()
        limiter.set_limit("test:action", 5)

        for _ in range(5):
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


# =========================================================================
# PROTOCOL SDK CONSTANTS TESTS
# =========================================================================

class TestProtocolSDKConstants:
    """Tests for protocol SDK re-exports."""

    def test_obligation_tokens(self):
        assert OBLIGATION_TOKENS.REQUIRE_APPROVAL == "require_approval"
        assert OBLIGATION_TOKENS.LOG_ACTION == "log_action"
        assert OBLIGATION_TOKENS.NOTIFY_OWNER == "notify_owner"

    def test_constraint_keys_has_16_core_keys(self):
        # Temporal
        assert CONSTRAINT_KEYS.TIME_OPERATING_HOURS == "core:time:operating_hours"
        assert CONSTRAINT_KEYS.TIME_BLACKOUT_WINDOWS == "core:time:blackout_windows"
        # Scope
        assert CONSTRAINT_KEYS.DOMAIN_ALLOWLIST == "core:scope:domain_allowlist"
        assert CONSTRAINT_KEYS.DOMAIN_BLOCKLIST == "core:scope:domain_blocklist"
        assert CONSTRAINT_KEYS.ACTION_ALLOWLIST == "core:scope:action_allowlist"
        assert CONSTRAINT_KEYS.ACTION_BLOCKLIST == "core:scope:action_blocklist"
        # Rate
        assert CONSTRAINT_KEYS.MAX_PER_MINUTE == "core:rate:max_per_minute"
        assert CONSTRAINT_KEYS.MAX_PER_HOUR == "core:rate:max_per_hour"
        assert CONSTRAINT_KEYS.MAX_PER_DAY == "core:rate:max_per_day"
        # Cost
        assert CONSTRAINT_KEYS.MAX_PER_ACTION == "core:cost:max_per_action"
        assert CONSTRAINT_KEYS.MAX_CUMULATIVE == "core:cost:max_cumulative"
        assert CONSTRAINT_KEYS.APPROVAL_THRESHOLD == "core:cost:approval_threshold"
        # Approval
        assert CONSTRAINT_KEYS.APPROVAL_REQUIRED == "core:approval:required"
        assert CONSTRAINT_KEYS.APPROVAL_FOR_ACTIONS == "core:approval:for_actions"
        # Data
        assert CONSTRAINT_KEYS.DATA_READ_ONLY == "core:data:read_only"
        assert CONSTRAINT_KEYS.DATA_NO_PII_EXPORT == "core:data:no_pii_export"

    def test_deny_reason_has_all_members(self):
        """DenyReason has all 38 members — spot check across categories."""
        # §8.3 Passport
        assert DenyReason.INVALID_SIGNATURE is not None
        assert DenyReason.PASSPORT_EXPIRED is not None
        assert DenyReason.PASSPORT_MISSING is not None
        # §8.3 Issuer
        assert DenyReason.ISSUER_NOT_ALLOWED is not None
        # §14A
        assert DenyReason.ANTI_DOWNGRADE is not None
        # §14B
        assert DenyReason.CONSTRAINT_VIOLATED is not None
        assert DenyReason.RATE_LIMITED is not None
        assert DenyReason.APPROVAL_REQUIRED is not None
        # §24 Session
        assert DenyReason.SESSION_INVALID is not None
        # §27 Delegation
        assert DenyReason.PARENT_INVALID is not None
        assert DenyReason.CHAIN_TOO_DEEP is not None
        # Commerce
        assert DenyReason.CATALOG_PIN_MISMATCH is not None

    def test_denial_code_is_deny_reason_alias(self):
        """DenialCode is a backward-compatible alias for DenyReason."""
        assert DenialCode is DenyReason
        assert DenialCode.PASSPORT_MISSING == DenyReason.PASSPORT_MISSING
