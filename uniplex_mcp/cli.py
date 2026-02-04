"""
Uniplex MCP Server CLI

Command-line interface for running the Uniplex MCP Server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

from .server import UniplexMCPServer
from .types import ServerConfig


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def load_config(config_path: str | None) -> ServerConfig:
    """Load configuration from file or environment."""
    config_dict: dict = {}
    
    # Load from file if provided
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                config_dict = json.load(f)
    
    # Override with environment variables
    if "UNIPLEX_GATE_ID" in os.environ:
        config_dict["gate_id"] = os.environ["UNIPLEX_GATE_ID"]
    
    if "UNIPLEX_GATE_SECRET" in os.environ:
        config_dict["gate_secret"] = os.environ["UNIPLEX_GATE_SECRET"]
    
    if "UNIPLEX_API_URL" in os.environ:
        config_dict["uniplex_api_url"] = os.environ["UNIPLEX_API_URL"]
    
    if "UNIPLEX_TEST_MODE" in os.environ:
        config_dict["test_mode"] = os.environ["UNIPLEX_TEST_MODE"].lower() == "true"
    
    # Validate required fields
    if "gate_id" not in config_dict:
        raise ValueError("gate_id is required (set UNIPLEX_GATE_ID or provide config file)")
    
    return ServerConfig(**config_dict)


async def run_server(config: ServerConfig) -> None:
    """Run the MCP server."""
    server = UniplexMCPServer(config)
    
    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()
    
    def handle_signal() -> None:
        shutdown_event.set()
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)
    
    try:
        await server.initialize()
        
        # In production, this would connect to MCP transport (stdio)
        # For now, just wait for shutdown
        logging.info("Uniplex MCP Server running. Press Ctrl+C to stop.")
        
        await shutdown_event.wait()
        
    finally:
        await server.shutdown()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Uniplex MCP Server - Permission-aware tool execution for AI agents",
    )
    
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file",
        default=None,
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="uniplex-mcp-sdk 1.0.0",
    )
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    try:
        config = load_config(args.config)
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)
    
    asyncio.run(run_server(config))


if __name__ == "__main__":
    main()
