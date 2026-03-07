"""
Tests for the server module functionality.
"""

from unittest.mock import patch

import mcp.types as types
import pytest

from kali_mcp_server.server import handle_tool_request


@pytest.mark.asyncio
async def test_handle_tool_request_unknown_tool():
    """Test handling of unknown tool calls."""
    with pytest.raises(ValueError, match="Unknown tool"):
        await handle_tool_request("unknown_tool", {})


@pytest.mark.asyncio
async def test_handle_tool_request_missing_arguments():
    """Test handling of tool calls with missing arguments."""
    with pytest.raises(ValueError, match="Missing required argument"):
        await handle_tool_request("fetch", {})  # Missing url

    with pytest.raises(ValueError, match="Missing required argument"):
        await handle_tool_request("run", {})  # Missing command


@pytest.mark.asyncio
async def test_handle_fetch_tool():
    """Test handling of fetch tool calls."""

    # Create a mock function directly
    async def mock_fetch(url):
        return [types.TextContent(type="text", text="Test content")]

    # Create a patch context
    with patch("kali_mcp_server.server.fetch_website", mock_fetch):
        # Call function
        result = await handle_tool_request("fetch", {"url": "https://example.com"})

        # Verify results
        assert len(result) == 1
        assert result[0].type == "text"
        assert result[0].text == "Test content"


@pytest.mark.asyncio
async def test_handle_run_tool():
    """Test handling of run tool calls."""

    # Create a mock function directly
    async def mock_run(command):
        return [types.TextContent(type="text", text="Command output")]

    # Create a patch context
    with patch("kali_mcp_server.server.run_command", mock_run):
        # Call function
        result = await handle_tool_request("run", {"command": "uname -a"})

        # Verify results
        assert len(result) == 1
        assert result[0].type == "text"
        assert result[0].text == "Command output"


@pytest.mark.asyncio
async def test_handle_resources_tool():
    """Test handling of resources tool calls."""

    # Create a mock function directly
    async def mock_resources():
        return [types.TextContent(type="text", text="Resources info")]

    # Create a patch context
    with patch("kali_mcp_server.server.list_system_resources", mock_resources):
        # Call function
        result = await handle_tool_request("resources", {})

        # Verify results
        assert len(result) == 1
        assert result[0].type == "text"
        assert result[0].text == "Resources info"


# --- Dispatch tests for 12 new tools ---


@pytest.mark.asyncio
async def test_handle_encode_decode():
    """Test dispatch for encode_decode tool."""

    async def mock_fn(data, operation, fmt):
        return [types.TextContent(type="text", text=f"encoded {data}")]

    with patch("kali_mcp_server.server.encode_decode", mock_fn):
        result = await handle_tool_request(
            "encode_decode",
            {"data": "hello", "operation": "encode", "format": "base64"},
        )
        assert result[0].text == "encoded hello"


@pytest.mark.asyncio
async def test_handle_encode_decode_missing_arg():
    """Test encode_decode dispatch with missing data."""
    with pytest.raises(ValueError, match="Missing required argument 'data'"):
        await handle_tool_request("encode_decode", {})


@pytest.mark.asyncio
async def test_handle_reverse_shell():
    """Test dispatch for reverse_shell tool."""

    async def mock_fn(lhost, shell_type, lport):
        return [types.TextContent(type="text", text=f"shell {lhost}:{lport}")]

    with patch("kali_mcp_server.server.reverse_shell", mock_fn):
        result = await handle_tool_request("reverse_shell", {"lhost": "10.0.0.1"})
        assert "10.0.0.1" in result[0].text


@pytest.mark.asyncio
async def test_handle_reverse_shell_missing_arg():
    """Test reverse_shell dispatch with missing lhost."""
    with pytest.raises(ValueError, match="Missing required argument 'lhost'"):
        await handle_tool_request("reverse_shell", {})


@pytest.mark.asyncio
async def test_handle_hash_identify():
    """Test dispatch for hash_identify tool."""

    async def mock_fn(hash_value):
        return [types.TextContent(type="text", text=f"identified {hash_value}")]

    with patch("kali_mcp_server.server.hash_identify", mock_fn):
        result = await handle_tool_request("hash_identify", {"hash_value": "abc123"})
        assert "abc123" in result[0].text


@pytest.mark.asyncio
async def test_handle_hash_identify_missing_arg():
    """Test hash_identify dispatch with missing hash_value."""
    with pytest.raises(ValueError, match="Missing required argument 'hash_value'"):
        await handle_tool_request("hash_identify", {})


@pytest.mark.asyncio
async def test_handle_credential_store():
    """Test dispatch for credential_store tool."""

    async def mock_fn(**kwargs):
        return [types.TextContent(type="text", text=f"creds {kwargs.get('action')}")]

    with patch("kali_mcp_server.server.credential_store", mock_fn):
        result = await handle_tool_request("credential_store", {"action": "list"})
        assert "creds list" in result[0].text


@pytest.mark.asyncio
async def test_handle_hydra_attack():
    """Test dispatch for hydra_attack tool."""

    async def mock_fn(**kwargs):
        return [types.TextContent(type="text", text=f"hydra {kwargs.get('target')}")]

    with patch("kali_mcp_server.server.hydra_attack", mock_fn):
        result = await handle_tool_request(
            "hydra_attack",
            {"target": "10.0.0.1", "username": "admin", "password": "pass"},
        )
        assert "10.0.0.1" in result[0].text


@pytest.mark.asyncio
async def test_handle_hydra_attack_missing_arg():
    """Test hydra_attack dispatch with missing target."""
    with pytest.raises(ValueError, match="Missing required argument 'target'"):
        await handle_tool_request("hydra_attack", {})


@pytest.mark.asyncio
async def test_handle_payload_generate():
    """Test dispatch for payload_generate tool."""

    async def mock_fn(**kwargs):
        return [types.TextContent(type="text", text=f"payload {kwargs.get('lhost')}")]

    with patch("kali_mcp_server.server.payload_generate", mock_fn):
        result = await handle_tool_request(
            "payload_generate",
            {"payload_type": "reverse_shell", "platform": "linux", "lhost": "10.0.0.1"},
        )
        assert "10.0.0.1" in result[0].text


@pytest.mark.asyncio
async def test_handle_payload_generate_missing_args():
    """Test payload_generate dispatch with missing args."""
    with pytest.raises(ValueError, match="Missing required argument 'payload_type'"):
        await handle_tool_request("payload_generate", {})
    with pytest.raises(ValueError, match="Missing required argument 'platform'"):
        await handle_tool_request("payload_generate", {"payload_type": "reverse_shell"})
    with pytest.raises(ValueError, match="Missing required argument 'lhost'"):
        await handle_tool_request(
            "payload_generate", {"payload_type": "reverse_shell", "platform": "linux"}
        )


@pytest.mark.asyncio
async def test_handle_port_scan():
    """Test dispatch for port_scan tool."""

    async def mock_fn(target, scan_type, ports):
        return [types.TextContent(type="text", text=f"scan {target}")]

    with patch("kali_mcp_server.server.port_scan", mock_fn):
        result = await handle_tool_request("port_scan", {"target": "10.0.0.1"})
        assert "10.0.0.1" in result[0].text


@pytest.mark.asyncio
async def test_handle_port_scan_missing_arg():
    """Test port_scan dispatch with missing target."""
    with pytest.raises(ValueError, match="Missing required argument 'target'"):
        await handle_tool_request("port_scan", {})


@pytest.mark.asyncio
async def test_handle_dns_enum():
    """Test dispatch for dns_enum tool."""

    async def mock_fn(domain, record_types):
        return [types.TextContent(type="text", text=f"dns {domain}")]

    with patch("kali_mcp_server.server.dns_enum", mock_fn):
        result = await handle_tool_request("dns_enum", {"domain": "example.com"})
        assert "example.com" in result[0].text


@pytest.mark.asyncio
async def test_handle_dns_enum_missing_arg():
    """Test dns_enum dispatch with missing domain."""
    with pytest.raises(ValueError, match="Missing required argument 'domain'"):
        await handle_tool_request("dns_enum", {})


@pytest.mark.asyncio
async def test_handle_enum_shares():
    """Test dispatch for enum_shares tool."""

    async def mock_fn(**kwargs):
        return [types.TextContent(type="text", text=f"shares {kwargs.get('target')}")]

    with patch("kali_mcp_server.server.enum_shares", mock_fn):
        result = await handle_tool_request("enum_shares", {"target": "10.0.0.1"})
        assert "10.0.0.1" in result[0].text


@pytest.mark.asyncio
async def test_handle_enum_shares_missing_arg():
    """Test enum_shares dispatch with missing target."""
    with pytest.raises(ValueError, match="Missing required argument 'target'"):
        await handle_tool_request("enum_shares", {})


@pytest.mark.asyncio
async def test_handle_parse_nmap():
    """Test dispatch for parse_nmap tool."""

    async def mock_fn(filepath):
        return [types.TextContent(type="text", text=f"parsed {filepath}")]

    with patch("kali_mcp_server.server.parse_nmap", mock_fn):
        result = await handle_tool_request("parse_nmap", {"filepath": "/tmp/nmap.txt"})
        assert "/tmp/nmap.txt" in result[0].text


@pytest.mark.asyncio
async def test_handle_parse_nmap_missing_arg():
    """Test parse_nmap dispatch with missing filepath."""
    with pytest.raises(ValueError, match="Missing required argument 'filepath'"):
        await handle_tool_request("parse_nmap", {})


@pytest.mark.asyncio
async def test_handle_parse_tool_output():
    """Test dispatch for parse_tool_output tool."""

    async def mock_fn(filepath, tool_type):
        return [
            types.TextContent(type="text", text=f"parsed {filepath} as {tool_type}")
        ]

    with patch("kali_mcp_server.server.parse_tool_output", mock_fn):
        result = await handle_tool_request(
            "parse_tool_output", {"filepath": "/tmp/nikto.txt"}
        )
        assert "/tmp/nikto.txt" in result[0].text


@pytest.mark.asyncio
async def test_handle_parse_tool_output_missing_arg():
    """Test parse_tool_output dispatch with missing filepath."""
    with pytest.raises(ValueError, match="Missing required argument 'filepath'"):
        await handle_tool_request("parse_tool_output", {})


@pytest.mark.asyncio
async def test_handle_recon_auto():
    """Test dispatch for recon_auto tool."""

    async def mock_fn(target, depth):
        return [types.TextContent(type="text", text=f"recon {target} {depth}")]

    with patch("kali_mcp_server.server.recon_auto", mock_fn):
        result = await handle_tool_request("recon_auto", {"target": "example.com"})
        assert "example.com" in result[0].text


@pytest.mark.asyncio
async def test_handle_recon_auto_missing_arg():
    """Test recon_auto dispatch with missing target."""
    with pytest.raises(ValueError, match="Missing required argument 'target'"):
        await handle_tool_request("recon_auto", {})


@pytest.mark.asyncio
async def test_handle_session_results():
    """Test dispatch for session_results tool."""

    async def mock_fn(limit, lines):
        return [types.TextContent(type="text", text=f"results {limit}/{lines}")]

    with patch("kali_mcp_server.server.session_results", mock_fn):
        result = await handle_tool_request("session_results", {"limit": 2, "lines": 40})
        assert "results 2/40" in result[0].text
