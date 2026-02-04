"""
Uniplex MCP Server Session Management

Manages passports per session with safe default issuance.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from .types import (
    Passport,
    PermissionClaim,
    ServerConfig,
    TrustTier,
)

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages passport sessions.
    
    Each session can have one active passport.
    Sessions are identified by session_id (typically from MCP client).
    """
    
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self._sessions: dict[str, SessionData] = {}
        self._session_timeout_seconds = 3600  # 1 hour
    
    def get_passport(self, session_id: str) -> Passport | None:
        """Get passport for a session."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        
        # Check session expiry
        if time.time() - session.last_active > self._session_timeout_seconds:
            self._sessions.pop(session_id, None)
            return None
        
        session.last_active = time.time()
        return session.passport
    
    def set_passport(self, session_id: str, passport: Passport) -> None:
        """Set passport for a session."""
        if session_id in self._sessions:
            self._sessions[session_id].passport = passport
            self._sessions[session_id].last_active = time.time()
        else:
            self._sessions[session_id] = SessionData(
                session_id=session_id,
                passport=passport,
                created_at=time.time(),
                last_active=time.time(),
            )
    
    def clear_session(self, session_id: str) -> None:
        """Clear a session."""
        self._sessions.pop(session_id, None)
    
    def cleanup_expired(self) -> int:
        """
        Remove expired sessions.
        
        Returns number of sessions removed.
        """
        now = time.time()
        expired = [
            sid for sid, session in self._sessions.items()
            if now - session.last_active > self._session_timeout_seconds
        ]
        
        for sid in expired:
            self._sessions.pop(sid, None)
        
        return len(expired)
    
    async def issue_safe_default(self, session_id: str) -> Passport:
        """
        Issue a safe default passport for a new session.
        
        This is called during session bootstrap (NOT hot path).
        Network call is acceptable here.
        
        The safe default passport has:
        - L1 trust tier (lowest)
        - Read-only permissions only
        - Tight constraints
        """
        # In production, this would call the Uniplex API
        # For now, create a local safe default
        
        if self.config.test_mode:
            return self._create_test_passport(session_id)
        
        # TODO: Call Uniplex API to issue safe default passport
        # response = await http_client.post(
        #     f"{self.config.uniplex_api_url}/gates/{self.config.gate_id}/passports/safe-default",
        #     json={"session_id": session_id}
        # )
        
        # For now, return a minimal passport
        return self._create_test_passport(session_id)
    
    def _create_test_passport(self, session_id: str) -> Passport:
        """Create a test passport for development/testing."""
        now = datetime.now(timezone.utc)
        expires = now.replace(hour=now.hour + 24)  # 24 hours from now
        
        passport = Passport(
            passport_id=f"pp_test_{session_id[:8]}",
            agent_id=f"agent_{session_id[:8]}",
            issuer_id="issuer_test",
            gate_id=self.config.gate_id,
            trust_tier=TrustTier.L1,
            permissions=[
                PermissionClaim(
                    key="test:action",
                    constraints={"core:rate:max_per_hour": 100},
                ),
            ],
            constraints={},
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            signature="test_signature",
        )
        
        # Build index
        passport.claims_by_key = {p.key: p for p in passport.permissions}
        
        return passport


class SessionData:
    """Data stored for each session."""
    
    def __init__(
        self,
        session_id: str,
        passport: Passport | None = None,
        created_at: float | None = None,
        last_active: float | None = None,
    ) -> None:
        self.session_id = session_id
        self.passport = passport
        self.created_at = created_at or time.time()
        self.last_active = last_active or time.time()


class SessionWrapper:
    """
    Wrapper for session operations with passport context.
    
    Provides convenience methods for permission queries.
    """
    
    def __init__(self, session_manager: SessionManager, session_id: str) -> None:
        self._manager = session_manager
        self._session_id = session_id
    
    @property
    def passport(self) -> Passport | None:
        """Get current passport."""
        return self._manager.get_passport(self._session_id)
    
    def has_permission(self, permission_key: str) -> bool:
        """Check if current passport has a permission."""
        passport = self.passport
        if passport is None:
            return False
        return permission_key in passport.claims_by_key
    
    def get_constraint(self, permission_key: str, constraint_key: str) -> Any:
        """Get a constraint value for a permission."""
        passport = self.passport
        if passport is None:
            return None
        
        claim = passport.claims_by_key.get(permission_key)
        if claim is None:
            return None
        
        return claim.constraints.get(constraint_key)
    
    def get_all_permissions(self) -> list[str]:
        """Get all permission keys in current passport."""
        passport = self.passport
        if passport is None:
            return []
        return list(passport.claims_by_key.keys())
