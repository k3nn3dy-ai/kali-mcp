#!/usr/bin/env python3
"""
Simple script to verify that the package can be imported correctly.
"""

try:
    # Only import to verify they exist, but don't need to use them
    import importlib.util

    import kali_mcp_server
    from kali_mcp_server.server import kali_server

    assert importlib.util.find_spec("kali_mcp_server.tools")

    print(f"✅ Successfully imported kali_mcp_server v{kali_mcp_server.__version__}")
    print(f"✅ Server name: {kali_server.name}")
    print("✅ All required modules imported successfully")

except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please ensure the package is installed with 'pip install -e .'")
    exit(1)

print("\nPackage installation is valid! 🎉")
