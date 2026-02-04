"""
Uniplex MCP Server Cache Management

Background cache refresh for catalog, revocation list, and issuer keys.
All verification uses cached data - no network calls in hot path.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from .types import (
    CachedCatalog,
    Catalog,
    CatalogPermission,
    DenialCode,
    RiskLevel,
    ServerConfig,
)

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages cached data for local verification.
    
    Caches:
    - Permission catalog (refresh every 5 min)
    - Revocation list (refresh every 1 min)
    - Issuer public keys (refresh every 5 min)
    
    All data is fetched in background; verification uses cached values only.
    """
    
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self._catalog: CachedCatalog | None = None
        self._revocation_set: set[str] = set()
        self._issuer_keys: dict[str, str] = {}
        self._revocation_fetched_at: datetime | None = None
        self._keys_fetched_at: datetime | None = None
        self._refresh_task: asyncio.Task[None] | None = None
        self._running = False
    
    @property
    def catalog(self) -> CachedCatalog | None:
        """Get cached catalog."""
        return self._catalog
    
    @property
    def revocation_set(self) -> set[str]:
        """Get cached revocation set."""
        return self._revocation_set
    
    @property
    def issuer_keys(self) -> dict[str, str]:
        """Get cached issuer keys."""
        return self._issuer_keys
    
    def is_catalog_fresh(self) -> bool:
        """Check if catalog is within max age."""
        if self._catalog is None:
            return False
        
        age_minutes = (
            datetime.now(timezone.utc) - self._catalog.fetched_at
        ).total_seconds() / 60
        
        return age_minutes <= self.config.catalog_max_age_minutes
    
    def is_revocation_fresh(self) -> bool:
        """Check if revocation list is within max age."""
        if self._revocation_fetched_at is None:
            return False
        
        age_minutes = (
            datetime.now(timezone.utc) - self._revocation_fetched_at
        ).total_seconds() / 60
        
        return age_minutes <= self.config.revocation_max_age_minutes
    
    def check_freshness(self) -> tuple[bool, DenialCode | None]:
        """
        Check cache freshness based on fail mode.
        
        Returns:
            (is_fresh, error_code) - error_code is set in fail_closed mode
        """
        if self.config.fail_mode == "fail_open":
            return True, None
        
        # fail_closed mode
        if not self.is_catalog_fresh():
            return False, DenialCode.CATALOG_STALE
        
        if not self.is_revocation_fresh():
            return False, DenialCode.REVOCATION_STALE
        
        return True, None
    
    async def initialize(self) -> None:
        """
        Initialize cache with initial fetch.
        
        Call this before starting the server.
        """
        await self._fetch_catalog()
        await self._fetch_revocations()
        await self._fetch_issuer_keys()
    
    async def start_background_refresh(self) -> None:
        """Start background refresh task."""
        if self._running:
            return
        
        self._running = True
        self._refresh_task = asyncio.create_task(self._refresh_loop())
    
    async def stop(self) -> None:
        """Stop background refresh."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
    
    async def _refresh_loop(self) -> None:
        """Background refresh loop."""
        catalog_interval = self.config.catalog_max_age_minutes * 60 * 0.8  # 80% of max age
        revocation_interval = self.config.revocation_max_age_minutes * 60 * 0.8
        
        last_catalog_refresh = 0.0
        last_revocation_refresh = 0.0
        
        while self._running:
            try:
                now = asyncio.get_event_loop().time()
                
                if now - last_catalog_refresh >= catalog_interval:
                    await self._fetch_catalog()
                    await self._fetch_issuer_keys()
                    last_catalog_refresh = now
                
                if now - last_revocation_refresh >= revocation_interval:
                    await self._fetch_revocations()
                    last_revocation_refresh = now
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache refresh: {e}")
                await asyncio.sleep(30)  # Back off on error
    
    async def _fetch_catalog(self) -> None:
        """Fetch catalog from Uniplex API."""
        if self.config.test_mode:
            # Use mock catalog in test mode
            self._catalog = self._create_mock_catalog()
            return
        
        try:
            # In production, fetch from self.config.uniplex_api_url
            # For now, create a placeholder
            logger.info(f"Fetching catalog for gate {self.config.gate_id}")
            
            # TODO: Implement actual API call
            # response = await http_client.get(
            #     f"{self.config.uniplex_api_url}/gates/{self.config.gate_id}/catalog"
            # )
            # catalog_data = response.json()
            
            # Placeholder - in production this comes from API
            self._catalog = self._create_mock_catalog()
            
        except Exception as e:
            logger.error(f"Failed to fetch catalog: {e}")
    
    async def _fetch_revocations(self) -> None:
        """Fetch revocation list from Uniplex API."""
        if self.config.test_mode:
            self._revocation_set = set()
            self._revocation_fetched_at = datetime.now(timezone.utc)
            return
        
        try:
            logger.info(f"Fetching revocations for gate {self.config.gate_id}")
            
            # TODO: Implement actual API call
            # response = await http_client.get(
            #     f"{self.config.uniplex_api_url}/gates/{self.config.gate_id}/revocations"
            # )
            # self._revocation_set = set(response.json()["revoked_ids"])
            
            self._revocation_set = set()
            self._revocation_fetched_at = datetime.now(timezone.utc)
            
        except Exception as e:
            logger.error(f"Failed to fetch revocations: {e}")
    
    async def _fetch_issuer_keys(self) -> None:
        """Fetch issuer public keys from Uniplex API."""
        if self.config.test_mode:
            # Use mock keys in test mode
            self._issuer_keys = {
                "issuer_test": "0" * 64,  # Mock key
            }
            self._keys_fetched_at = datetime.now(timezone.utc)
            return
        
        try:
            logger.info("Fetching issuer keys")
            
            # TODO: Implement actual API call
            # response = await http_client.get(
            #     f"{self.config.uniplex_api_url}/issuers/keys"
            # )
            # self._issuer_keys = response.json()["keys"]
            
            self._issuer_keys = {}
            self._keys_fetched_at = datetime.now(timezone.utc)
            
        except Exception as e:
            logger.error(f"Failed to fetch issuer keys: {e}")
    
    def _create_mock_catalog(self) -> CachedCatalog:
        """Create a mock catalog for testing."""
        catalog = Catalog(
            gate_id=self.config.gate_id,
            version=1,
            min_compatible_version=1,
            permissions=[
                CatalogPermission(
                    key="test:action",
                    description="Test action",
                    risk_level=RiskLevel.LOW,
                    constraints={"core:rate:max_per_hour": 100},
                ),
            ],
            content_hash="mock_hash",
            signature="mock_signature",
        )
        
        return CachedCatalog(
            gate_id=self.config.gate_id,
            current=catalog,
            versions={1: catalog},
            fetched_at=datetime.now(timezone.utc),
        )
    
    def set_mock_catalog(self, catalog: CachedCatalog) -> None:
        """Set a mock catalog for testing."""
        self._catalog = catalog
    
    def set_mock_revocations(self, revoked_ids: set[str]) -> None:
        """Set mock revocations for testing."""
        self._revocation_set = revoked_ids
        self._revocation_fetched_at = datetime.now(timezone.utc)
    
    def set_mock_issuer_keys(self, keys: dict[str, str]) -> None:
        """Set mock issuer keys for testing."""
        self._issuer_keys = keys
        self._keys_fetched_at = datetime.now(timezone.utc)
