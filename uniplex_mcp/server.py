"""
Uniplex MCP Server

Permission-aware MCP server for AI agent tool execution.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Awaitable

from .cache import CacheManager
from .session import SessionManager
from .transforms import transform_to_canonical
from .types import (
    ConstraintConfig,
    Denial,
    DenialCode,
    ServerConfig,
    ToolDefinition,
    ToolUniplexMetadata,
    TransformMode,
    VerifyResult,
)
from .verification import RateLimiter, verify_locally

logger = logging.getLogger(__name__)


# Type for tool handlers
ToolHandler = Callable[[dict[str, Any]], Awaitable[Any]]


class UniplexMCPServer:
    """
    Uniplex MCP Server with permission-aware tool execution.
    
    Integrates with the Model Context Protocol to provide:
    - Permission verification on every tool call
    - Passport-based authorization
    - Constraint enforcement
    - Attestation generation
    """
    
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.cache = CacheManager(config)
        self.sessions = SessionManager(config)
        self.rate_limiter = RateLimiter()
        
        self._tools: dict[str, RegisteredTool] = {}
        self._current_session_id: str | None = None
    
    async def initialize(self) -> None:
        """
        Initialize the server.
        
        Call this before handling any requests.
        """
        await self.cache.initialize()
        await self.cache.start_background_refresh()
        logger.info(f"Uniplex MCP Server initialized for gate {self.config.gate_id}")
    
    async def shutdown(self) -> None:
        """Shutdown the server."""
        await self.cache.stop()
        logger.info("Uniplex MCP Server shutdown complete")
    
    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: ToolHandler,
        uniplex: ToolUniplexMetadata | None = None,
    ) -> None:
        """
        Register a tool with the server.
        
        Args:
            name: Tool name
            description: Tool description
            input_schema: JSON Schema for tool input
            handler: Async function to execute the tool
            uniplex: Uniplex metadata (permission_key, constraints, etc.)
        """
        self._tools[name] = RegisteredTool(
            definition=ToolDefinition(
                name=name,
                description=description,
                input_schema=input_schema,
                uniplex=uniplex,
            ),
            handler=handler,
        )
        
        # Set up rate limits from catalog if available
        if uniplex and self.cache.catalog:
            catalog_entry = self.cache.catalog.current.permissions_by_key.get(
                uniplex.permission_key
            )
            if catalog_entry:
                max_per_hour = catalog_entry.constraints.get("core:rate:max_per_hour")
                if max_per_hour:
                    self.rate_limiter.set_limit(uniplex.permission_key, max_per_hour)
    
    def set_session(self, session_id: str) -> None:
        """Set the current session ID."""
        self._current_session_id = session_id
    
    async def handle_list_tools(self) -> list[dict[str, Any]]:
        """
        Handle MCP list_tools request.
        
        Returns tool definitions with session state.
        """
        tools = []
        passport = None
        
        if self._current_session_id:
            passport = self.sessions.get_passport(self._current_session_id)
        
        for tool in self._tools.values():
            tool_dict = {
                "name": tool.definition.name,
                "description": tool.definition.description,
                "inputSchema": tool.definition.input_schema,
            }
            
            if tool.definition.uniplex:
                uniplex_meta = tool.definition.uniplex
                
                # Check if current passport allows this tool
                allowed = False
                reason = "No passport"
                
                if passport:
                    if uniplex_meta.permission_key in passport.claims_by_key:
                        allowed = True
                        reason = None
                    else:
                        reason = f"Missing permission: {uniplex_meta.permission_key}"
                
                tool_dict["uniplex"] = {
                    "permission_key": uniplex_meta.permission_key,
                    "risk_level": uniplex_meta.risk_level.value,
                    "required_constraints": uniplex_meta.required_constraints,
                    "session_state": {
                        "allowed": allowed,
                        "reason": reason,
                    },
                }
            
            tools.append(tool_dict)
        
        return tools
    
    async def handle_call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Handle MCP call_tool request.
        
        This is the HOT PATH - verification must be fully local.
        
        Args:
            name: Tool name
            arguments: Tool arguments
        
        Returns:
            Tool result with Uniplex metadata
        """
        tool = self._tools.get(name)
        if tool is None:
            return self._build_error_response(f"Unknown tool: {name}")
        
        # If tool has no Uniplex metadata, execute without verification
        if tool.definition.uniplex is None:
            result = await tool.handler(arguments)
            return {"content": [{"type": "text", "text": str(result)}]}
        
        # Get passport from session
        passport = None
        if self._current_session_id:
            passport = self.sessions.get_passport(self._current_session_id)
        
        # Check cache freshness
        fresh, stale_error = self.cache.check_freshness()
        if not fresh and stale_error:
            return self._build_denial_response(
                VerifyResult(
                    allowed=False,
                    denial=Denial(code=stale_error, message="Cache data is stale"),
                )
            )
        
        # Build request context from arguments
        context = self._build_request_context(tool.definition.uniplex, arguments)
        
        # LOCAL VERIFICATION - no network calls
        verify_result = verify_locally(
            passport=passport,
            action=tool.definition.uniplex.permission_key,
            context=context,
            catalog=self.cache.catalog,
            revocation_set=self.cache.revocation_set,
            issuer_keys=self.cache.issuer_keys,
            rate_limiter=self.rate_limiter,
            skip_signature_verification=self.config.skip_signature_verification,
        )
        
        if not verify_result.allowed:
            return self._build_denial_response(verify_result)
        
        # Record rate limit usage
        if passport:
            self.rate_limiter.record(
                passport.passport_id,
                tool.definition.uniplex.permission_key,
            )
        
        # Execute tool
        try:
            result = await tool.handler(arguments)
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return self._build_error_response(str(e))
        
        # Build successful response with attestation
        response = {
            "content": [{"type": "text", "text": str(result)}],
            "_meta": {
                "uniplex": {
                    "verified": True,
                    "permission_key": tool.definition.uniplex.permission_key,
                    "effective_constraints": verify_result.effective_constraints,
                },
            },
        }
        
        return response
    
    def _build_request_context(
        self,
        uniplex: ToolUniplexMetadata,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build request context from tool arguments.
        
        Applies transforms and extracts constraint values.
        """
        context: dict[str, Any] = {}
        
        for constraint in uniplex.constraints:
            value = self._extract_constraint_value(constraint, arguments)
            if value is not None:
                # Apply transform
                if constraint.transform in ("dollars_to_cents", "custom"):
                    precision = constraint.precision
                    mode = TransformMode(constraint.transform_mode.value)
                    value = transform_to_canonical(value, precision, mode.value)
                
                # Map to context field
                if constraint.key == "core:cost:max":
                    context["amount_canonical"] = value
                else:
                    context[constraint.key] = value
        
        return context
    
    def _extract_constraint_value(
        self,
        constraint: ConstraintConfig,
        arguments: dict[str, Any],
    ) -> Any:
        """Extract constraint value from arguments or fixed value."""
        if constraint.source == "fixed":
            return constraint.fixed_value
        
        if constraint.input_path is None:
            return None
        
        # Simple JSONPath extraction ($.field or $.nested.field)
        path = constraint.input_path
        if path.startswith("$."):
            path = path[2:]
        
        parts = path.split(".")
        value = arguments
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value
    
    def _build_denial_response(self, result: VerifyResult) -> dict[str, Any]:
        """Build MCP error response for denial."""
        denial = result.denial or Denial(
            code=DenialCode.INTERNAL_ERROR,
            message="Unknown error",
        )
        
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"Permission denied: {denial.message}",
                }
            ],
            "_meta": {
                "uniplex": {
                    "denial_code": denial.code.value,
                    "denial_message": denial.message,
                },
            },
        }
    
    def _build_error_response(self, message: str) -> dict[str, Any]:
        """Build MCP error response for execution error."""
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error: {message}"}],
        }
    
    # Custom Uniplex methods
    
    async def handle_catalog(self) -> dict[str, Any]:
        """Handle uniplex/catalog custom method."""
        if self.cache.catalog is None:
            return {"error": "Catalog not loaded"}
        
        catalog = self.cache.catalog.current
        return {
            "gate_id": catalog.gate_id,
            "version": catalog.version,
            "permissions": [
                {
                    "key": p.key,
                    "description": p.description,
                    "risk_level": p.risk_level.value,
                    "constraints": p.constraints,
                }
                for p in catalog.permissions
            ],
        }
    
    async def handle_session(self) -> dict[str, Any]:
        """Handle uniplex/session custom method."""
        if self._current_session_id is None:
            return {"error": "No active session"}
        
        passport = self.sessions.get_passport(self._current_session_id)
        if passport is None:
            return {"session_id": self._current_session_id, "passport": None}
        
        return {
            "session_id": self._current_session_id,
            "passport": {
                "passport_id": passport.passport_id,
                "agent_id": passport.agent_id,
                "trust_tier": passport.trust_tier.value,
                "permissions": [p.key for p in passport.permissions],
                "expires_at": passport.expires_at,
            },
        }
    
    async def handle_request_passport(
        self,
        permissions: list[str],
        constraints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Handle uniplex/request-passport custom method.
        
        Requests a new passport with specified permissions.
        """
        # In production, this would call the Uniplex API
        # For now, return a template
        return {
            "status": "pending",
            "request_id": f"req_{self._current_session_id}",
            "requested_permissions": permissions,
            "requested_constraints": constraints,
            "message": "Passport request submitted for approval",
        }


class RegisteredTool:
    """A tool registered with the server."""
    
    def __init__(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        self.definition = definition
        self.handler = handler


def define_tool(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    permission_key: str | None = None,
    **uniplex_kwargs: Any,
) -> Callable[[ToolHandler], tuple[ToolDefinition, ToolHandler]]:
    """
    Decorator for defining tools.
    
    Example:
        @define_tool(
            name="search_flights",
            description="Search for flights",
            input_schema={"type": "object", "properties": {...}},
            permission_key="flights:search",
            risk_level="low",
        )
        async def search_flights(args):
            ...
    """
    def decorator(handler: ToolHandler) -> tuple[ToolDefinition, ToolHandler]:
        uniplex = None
        if permission_key:
            from .types import RiskLevel
            uniplex = ToolUniplexMetadata(
                permission_key=permission_key,
                risk_level=RiskLevel(uniplex_kwargs.get("risk_level", "low")),
                required_constraints=uniplex_kwargs.get("required_constraints", []),
                constraints=[
                    ConstraintConfig(**c)
                    for c in uniplex_kwargs.get("constraints", [])
                ],
            )
        
        definition = ToolDefinition(
            name=name,
            description=description,
            input_schema=input_schema,
            uniplex=uniplex,
        )
        
        return definition, handler
    
    return decorator
