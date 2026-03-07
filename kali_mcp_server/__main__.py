"""
Entry point for the Kali MCP Server.

This module allows the package to be executed directly using 'python -m kali_mcp_server'.
"""

import sys

from .server import main

if __name__ == "__main__":
    # Pass the exit code from main() to the system
    sys.exit(main())
