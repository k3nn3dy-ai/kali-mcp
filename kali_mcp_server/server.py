"""
MCP Server implementation for Kali Linux security tools.

This module provides the main server functionality for the Kali MCP Server,
including tool registration, transport configuration, and server initialization.
"""

from typing import Any, Dict, List, Sequence, Union

import anyio
import click
import mcp.types as types
from mcp.server.lowlevel import Server

from kali_mcp_server.tools import (
    create_report,
    credential_store,
    dns_enum,
    download_file,
    encode_decode,
    enum_shares,
    exploit_search,
    fetch_website,
    file_analysis,
    form_analysis,
    hash_identify,
    header_analysis,
    hydra_attack,
    list_system_resources,
    network_discovery,
    parse_nmap,
    parse_tool_output,
    payload_generate,
    port_scan,
    recon_auto,
    reverse_shell,
    run_command,
    save_output,
    session_create,
    session_delete,
    session_history,
    session_list,
    session_results,
    session_status,
    session_switch,
    spider_website,
    ssl_analysis,
    subdomain_enum,
    vulnerability_scan,
    web_audit,
    web_enumeration,
)

# Create server instance with descriptive name
kali_server = Server("kali-mcp-server")


@kali_server.call_tool()
async def handle_tool_request(
    name: str, arguments: Dict[str, Any]
) -> Sequence[Union[types.TextContent, types.ImageContent, types.EmbeddedResource]]:
    """
    Handle MCP tool requests by routing to the appropriate handler.

    Args:
        name: The name of the tool being called
        arguments: Dictionary of arguments for the tool

    Returns:
        Sequence of content items returned by the tool

    Raises:
        ValueError: If the tool name is unknown or required arguments are missing
    """
    if name == "fetch":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        return await fetch_website(arguments["url"])

    elif name == "run":
        if "command" not in arguments:
            raise ValueError("Missing required argument 'command'")
        return await run_command(arguments["command"])

    elif name == "resources":
        return await list_system_resources()

    elif name == "vulnerability_scan":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        scan_type = arguments.get("scan_type", "comprehensive")
        return await vulnerability_scan(arguments["target"], scan_type)

    elif name == "web_enumeration":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        enum_type = arguments.get("enumeration_type", "full")
        return await web_enumeration(arguments["target"], enum_type)

    elif name == "network_discovery":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        discovery_type = arguments.get("discovery_type", "comprehensive")
        return await network_discovery(arguments["target"], discovery_type)

    elif name == "exploit_search":
        if "search_term" not in arguments:
            raise ValueError("Missing required argument 'search_term'")
        search_type = arguments.get("search_type", "all")
        return await exploit_search(arguments["search_term"], search_type)

    elif name == "save_output":
        if "content" not in arguments:
            raise ValueError("Missing required argument 'content'")
        filename = arguments.get("filename")
        category = arguments.get("category", "general")
        return await save_output(
            arguments["content"], filename if filename else None, category
        )

    elif name == "create_report":
        if "title" not in arguments:
            raise ValueError("Missing required argument 'title'")
        if "findings" not in arguments:
            raise ValueError("Missing required argument 'findings'")
        report_type = arguments.get("report_type", "markdown")
        return await create_report(
            arguments["title"], arguments["findings"], report_type
        )

    elif name == "file_analysis":
        if "filepath" not in arguments:
            raise ValueError("Missing required argument 'filepath'")
        return await file_analysis(arguments["filepath"])

    elif name == "download_file":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        filename = arguments.get("filename")
        return await download_file(arguments["url"], filename if filename else None)

    elif name == "session_create":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        description = arguments.get("description", "")
        target = arguments.get("target", "")
        return await session_create(arguments["session_name"], description, target)

    elif name == "session_list":
        return await session_list()

    elif name == "session_switch":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        return await session_switch(arguments["session_name"])

    elif name == "session_status":
        return await session_status()

    elif name == "session_delete":
        if "session_name" not in arguments:
            raise ValueError("Missing required argument 'session_name'")
        return await session_delete(arguments["session_name"])

    elif name == "session_history":
        return await session_history()

    elif name == "session_results":
        limit = arguments.get("limit", 3)
        lines = arguments.get("lines", 80)
        return await session_results(limit, lines)

    elif name == "spider_website":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        depth = arguments.get("depth", 2)
        threads = arguments.get("threads", 10)
        return await spider_website(arguments["url"], depth, threads)

    elif name == "form_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        scan_type = arguments.get("scan_type", "comprehensive")
        return await form_analysis(arguments["url"], scan_type)

    elif name == "header_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        include_security = arguments.get("include_security", True)
        return await header_analysis(arguments["url"], include_security)

    elif name == "ssl_analysis":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        port = arguments.get("port", 443)
        return await ssl_analysis(arguments["url"], port)

    elif name == "subdomain_enum":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        enum_type = arguments.get("enum_type", "comprehensive")
        return await subdomain_enum(arguments["url"], enum_type)

    elif name == "web_audit":
        if "url" not in arguments:
            raise ValueError("Missing required argument 'url'")
        audit_type = arguments.get("audit_type", "comprehensive")
        return await web_audit(arguments["url"], audit_type)

    elif name == "encode_decode":
        if "data" not in arguments:
            raise ValueError("Missing required argument 'data'")
        operation = arguments.get("operation", "encode")
        fmt = arguments.get("format", "base64")
        return await encode_decode(arguments["data"], operation, fmt)

    elif name == "reverse_shell":
        if "lhost" not in arguments:
            raise ValueError("Missing required argument 'lhost'")
        shell_type = arguments.get("shell_type", "bash")
        lport = arguments.get("lport", 4444)
        return await reverse_shell(arguments["lhost"], shell_type, lport)

    elif name == "hash_identify":
        if "hash_value" not in arguments:
            raise ValueError("Missing required argument 'hash_value'")
        return await hash_identify(arguments["hash_value"])

    elif name == "credential_store":
        action = arguments.get("action", "list")
        return await credential_store(
            action=action,
            username=arguments.get("username"),
            password=arguments.get("password"),
            service=arguments.get("service"),
            target=arguments.get("target"),
            notes=arguments.get("notes"),
        )

    elif name == "hydra_attack":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        return await hydra_attack(
            target=arguments["target"],
            service=arguments.get("service", "ssh"),
            username=arguments.get("username"),
            userlist=arguments.get("userlist"),
            password=arguments.get("password"),
            passlist=arguments.get("passlist"),
            threads=arguments.get("threads", 16),
            extra_opts=arguments.get("extra_opts", ""),
        )

    elif name == "payload_generate":
        if "payload_type" not in arguments:
            raise ValueError("Missing required argument 'payload_type'")
        if "platform" not in arguments:
            raise ValueError("Missing required argument 'platform'")
        if "lhost" not in arguments:
            raise ValueError("Missing required argument 'lhost'")
        return await payload_generate(
            payload_type=arguments["payload_type"],
            platform=arguments["platform"],
            lhost=arguments["lhost"],
            lport=arguments.get("lport", 4444),
            format=arguments.get("format", "raw"),
            encoder=arguments.get("encoder"),
        )

    elif name == "port_scan":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        scan_type = arguments.get("scan_type", "quick")
        ports = arguments.get("ports")
        return await port_scan(arguments["target"], scan_type, ports)

    elif name == "dns_enum":
        if "domain" not in arguments:
            raise ValueError("Missing required argument 'domain'")
        record_types = arguments.get("record_types", "all")
        return await dns_enum(arguments["domain"], record_types)

    elif name == "enum_shares":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        return await enum_shares(
            target=arguments["target"],
            enum_type=arguments.get("enum_type", "all"),
            username=arguments.get("username"),
            password=arguments.get("password"),
        )

    elif name == "parse_nmap":
        if "filepath" not in arguments:
            raise ValueError("Missing required argument 'filepath'")
        return await parse_nmap(arguments["filepath"])

    elif name == "parse_tool_output":
        if "filepath" not in arguments:
            raise ValueError("Missing required argument 'filepath'")
        tool_type = arguments.get("tool_type", "auto")
        return await parse_tool_output(arguments["filepath"], tool_type)

    elif name == "recon_auto":
        if "target" not in arguments:
            raise ValueError("Missing required argument 'target'")
        depth = arguments.get("depth", "quick")
        return await recon_auto(arguments["target"], depth)

    else:
        raise ValueError(f"Unknown tool: {name}")


@kali_server.list_tools()
async def list_available_tools() -> List[types.Tool]:
    """
    Register and list all available MCP tools.

    Returns:
        List of available Tool objects
    """
    return [
        types.Tool(
            name="fetch",
            description="Fetches a website and returns its content",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    }
                },
            },
        ),
        types.Tool(
            name="run",
            description="Runs a shell command on the Kali Linux system",
            inputSchema={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    }
                },
            },
        ),
        types.Tool(
            name="resources",
            description="Lists available system resources and command examples",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="vulnerability_scan",
            description="Perform automated vulnerability assessment with multiple tools",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Type of scan (quick, comprehensive, web, network)",
                        "enum": ["quick", "comprehensive", "web", "network"],
                        "default": "comprehensive",
                    },
                },
            },
        ),
        types.Tool(
            name="web_enumeration",
            description="Perform comprehensive web application discovery and enumeration",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL (e.g., http://example.com)",
                    },
                    "enumeration_type": {
                        "type": "string",
                        "description": "Type of enumeration (basic, full, aggressive)",
                        "enum": ["basic", "full", "aggressive"],
                        "default": "full",
                    },
                },
            },
        ),
        types.Tool(
            name="network_discovery",
            description="Perform multi-stage network reconnaissance and discovery",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target network (e.g., 192.168.1.0/24) or host",
                    },
                    "discovery_type": {
                        "type": "string",
                        "description": "Type of discovery (quick, comprehensive, stealth)",
                        "enum": ["quick", "comprehensive", "stealth"],
                        "default": "comprehensive",
                    },
                },
            },
        ),
        types.Tool(
            name="exploit_search",
            description="Search for exploits using searchsploit and other exploit databases",
            inputSchema={
                "type": "object",
                "required": ["search_term"],
                "properties": {
                    "search_term": {
                        "type": "string",
                        "description": "Term to search for (e.g., 'apache', 'ssh', 'CVE-2021-44228')",
                    },
                    "search_type": {
                        "type": "string",
                        "description": "Type of search (all, web, remote, local, dos)",
                        "enum": ["all", "web", "remote", "local", "dos"],
                        "default": "all",
                    },
                },
            },
        ),
        types.Tool(
            name="save_output",
            description="Save content to a timestamped file for evidence collection",
            inputSchema={
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Content to save",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional custom filename (without extension)",
                    },
                    "category": {
                        "type": "string",
                        "description": "Category for organizing files (e.g., 'scan', 'enum', 'evidence')",
                        "default": "general",
                    },
                },
            },
        ),
        types.Tool(
            name="create_report",
            description="Generate a structured report from findings",
            inputSchema={
                "type": "object",
                "required": ["title", "findings"],
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Report title",
                    },
                    "findings": {
                        "type": "string",
                        "description": "Findings content",
                    },
                    "report_type": {
                        "type": "string",
                        "description": "Type of report (markdown, text, json)",
                        "enum": ["markdown", "text", "json"],
                        "default": "markdown",
                    },
                },
            },
        ),
        types.Tool(
            name="file_analysis",
            description="Analyze a file using various tools (file type, strings, hash)",
            inputSchema={
                "type": "object",
                "required": ["filepath"],
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the file to analyze",
                    }
                },
            },
        ),
        types.Tool(
            name="download_file",
            description="Download a file from a URL and save it locally",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to download from",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional custom filename",
                    },
                },
            },
        ),
        types.Tool(
            name="session_create",
            description="Create a new pentest session (name, description, target)",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {
                        "type": "string",
                        "description": "Name of the session",
                    },
                    "description": {
                        "type": "string",
                        "description": "Description of the session",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target for the session",
                    },
                },
            },
        ),
        types.Tool(
            name="session_list",
            description="List all pentest sessions with metadata",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="session_switch",
            description="Switch to a different pentest session",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {
                        "type": "string",
                        "description": "Name of the session to switch to",
                    }
                },
            },
        ),
        types.Tool(
            name="session_status",
            description="Show current session status and summary",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="session_delete",
            description="Delete a pentest session and all its evidence",
            inputSchema={
                "type": "object",
                "required": ["session_name"],
                "properties": {
                    "session_name": {
                        "type": "string",
                        "description": "Name of the session to delete",
                    }
                },
            },
        ),
        types.Tool(
            name="session_history",
            description="Show command/evidence history for the current session",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="session_results",
            description="Read recent output files for the active session",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max number of recent files to preview",
                        "default": 3,
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Trailing lines per file to include",
                        "default": 80,
                    },
                },
            },
        ),
        types.Tool(
            name="spider_website",
            description="Spider a website to find all links and resources",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to spider",
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum depth of the spider",
                        "default": 2,
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 10,
                    },
                },
            },
        ),
        types.Tool(
            name="form_analysis",
            description="Analyze a web form for vulnerabilities",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the web form to analyze",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Type of scan (comprehensive, quick)",
                        "enum": ["comprehensive", "quick"],
                        "default": "comprehensive",
                    },
                },
            },
        ),
        types.Tool(
            name="header_analysis",
            description="Analyze HTTP headers for security issues",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to analyze",
                    },
                    "include_security": {
                        "type": "boolean",
                        "description": "Include security-related headers",
                        "default": True,
                    },
                },
            },
        ),
        types.Tool(
            name="ssl_analysis",
            description="Analyze SSL/TLS configuration of a website",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to analyze",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port to connect to",
                        "default": 443,
                    },
                },
            },
        ),
        types.Tool(
            name="subdomain_enum",
            description="Enumerate subdomains of a target website",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the target website",
                    },
                    "enum_type": {
                        "type": "string",
                        "description": "Type of enumeration (comprehensive, quick)",
                        "enum": ["comprehensive", "quick"],
                        "default": "comprehensive",
                    },
                },
            },
        ),
        types.Tool(
            name="web_audit",
            description="Perform a comprehensive web application audit",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the website to audit",
                    },
                    "audit_type": {
                        "type": "string",
                        "description": "Type of audit (comprehensive, quick)",
                        "enum": ["comprehensive", "quick"],
                        "default": "comprehensive",
                    },
                },
            },
        ),
        types.Tool(
            name="encode_decode",
            description="Multi-format encoding/decoding (base64, URL, hex, HTML, ROT13)",
            inputSchema={
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "The data to encode or decode",
                    },
                    "operation": {
                        "type": "string",
                        "description": "Operation to perform",
                        "enum": ["encode", "decode"],
                        "default": "encode",
                    },
                    "format": {
                        "type": "string",
                        "description": "Encoding format",
                        "enum": ["base64", "url", "hex", "html", "rot13"],
                        "default": "base64",
                    },
                },
            },
        ),
        types.Tool(
            name="reverse_shell",
            description="Generate reverse shell one-liners for various languages",
            inputSchema={
                "type": "object",
                "required": ["lhost"],
                "properties": {
                    "lhost": {
                        "type": "string",
                        "description": "Listener IP address",
                    },
                    "shell_type": {
                        "type": "string",
                        "description": "Shell language/type",
                        "enum": [
                            "bash",
                            "python",
                            "php",
                            "perl",
                            "powershell",
                            "nc",
                            "ruby",
                            "java",
                        ],
                        "default": "bash",
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Listener port",
                        "default": 4444,
                    },
                },
            },
        ),
        types.Tool(
            name="hash_identify",
            description="Identify hash types from hash strings (MD5, SHA, bcrypt, NTLM, etc.)",
            inputSchema={
                "type": "object",
                "required": ["hash_value"],
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash string to identify",
                    }
                },
            },
        ),
        types.Tool(
            name="credential_store",
            description="Store/retrieve discovered credentials tied to sessions",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Action to perform",
                        "enum": ["add", "list", "search"],
                        "default": "list",
                    },
                    "username": {
                        "type": "string",
                        "description": "Username credential",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password credential",
                    },
                    "service": {
                        "type": "string",
                        "description": "Service type (ssh, ftp, http, etc.)",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target host/IP",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Additional notes",
                    },
                },
            },
        ),
        types.Tool(
            name="hydra_attack",
            description="Brute-force credential testing via hydra",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host",
                    },
                    "service": {
                        "type": "string",
                        "description": "Service to attack",
                        "enum": [
                            "ssh",
                            "ftp",
                            "http-get",
                            "http-post-form",
                            "smb",
                            "mysql",
                            "rdp",
                            "telnet",
                            "vnc",
                            "pop3",
                            "imap",
                            "smtp",
                        ],
                        "default": "ssh",
                    },
                    "username": {
                        "type": "string",
                        "description": "Single username to try",
                    },
                    "userlist": {
                        "type": "string",
                        "description": "Path to username wordlist",
                    },
                    "password": {
                        "type": "string",
                        "description": "Single password to try",
                    },
                    "passlist": {
                        "type": "string",
                        "description": "Path to password wordlist",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of threads",
                        "default": 16,
                    },
                    "extra_opts": {
                        "type": "string",
                        "description": "Additional hydra options",
                    },
                },
            },
        ),
        types.Tool(
            name="payload_generate",
            description="Generate payloads using msfvenom (reverse shell, bind shell, meterpreter)",
            inputSchema={
                "type": "object",
                "required": ["payload_type", "platform", "lhost"],
                "properties": {
                    "payload_type": {
                        "type": "string",
                        "description": "Type of payload",
                        "enum": ["reverse_shell", "bind_shell", "meterpreter"],
                    },
                    "platform": {
                        "type": "string",
                        "description": "Target platform",
                        "enum": ["linux", "windows", "osx", "php", "python"],
                    },
                    "lhost": {
                        "type": "string",
                        "description": "Listener IP address",
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Listener port",
                        "default": 4444,
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format",
                        "enum": ["elf", "exe", "raw", "python", "php", "war"],
                        "default": "raw",
                    },
                    "encoder": {
                        "type": "string",
                        "description": "Optional encoder (e.g., x86/shikata_ga_nai)",
                    },
                },
            },
        ),
        types.Tool(
            name="port_scan",
            description="Smart nmap wrapper with scan presets (quick, full, stealth, udp, service, aggressive)",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "scan_type": {
                        "type": "string",
                        "description": "Scan preset",
                        "enum": [
                            "quick",
                            "full",
                            "stealth",
                            "udp",
                            "service",
                            "aggressive",
                        ],
                        "default": "quick",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Custom port specification (e.g., '80,443,8080' or '1-1024')",
                    },
                },
            },
        ),
        types.Tool(
            name="dns_enum",
            description="Comprehensive DNS enumeration with zone transfer attempts",
            inputSchema={
                "type": "object",
                "required": ["domain"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain to enumerate",
                    },
                    "record_types": {
                        "type": "string",
                        "description": "Record types to query (all, or comma-separated: a,mx,ns,txt,etc.)",
                        "default": "all",
                    },
                },
            },
        ),
        types.Tool(
            name="enum_shares",
            description="SMB/NFS share enumeration (smbclient, enum4linux, showmount)",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host",
                    },
                    "enum_type": {
                        "type": "string",
                        "description": "Enumeration type",
                        "enum": ["smb", "nfs", "all"],
                        "default": "all",
                    },
                    "username": {
                        "type": "string",
                        "description": "Optional SMB username",
                    },
                    "password": {
                        "type": "string",
                        "description": "Optional SMB password",
                    },
                },
            },
        ),
        types.Tool(
            name="parse_nmap",
            description="Parse nmap output (text or XML) into structured findings",
            inputSchema={
                "type": "object",
                "required": ["filepath"],
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to nmap output file",
                    }
                },
            },
        ),
        types.Tool(
            name="parse_tool_output",
            description="Parse output from nikto/gobuster/dirb/hydra/sqlmap into structured findings",
            inputSchema={
                "type": "object",
                "required": ["filepath"],
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to tool output file",
                    },
                    "tool_type": {
                        "type": "string",
                        "description": "Tool that generated the output (auto-detects if not specified)",
                        "enum": [
                            "auto",
                            "nikto",
                            "gobuster",
                            "dirb",
                            "hydra",
                            "sqlmap",
                        ],
                        "default": "auto",
                    },
                },
            },
        ),
        types.Tool(
            name="recon_auto",
            description="Automated multi-stage reconnaissance pipeline (DNS, ports, headers, SSL, exploits)",
            inputSchema={
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain or IP",
                    },
                    "depth": {
                        "type": "string",
                        "description": "Recon depth (quick=DNS+ports+headers, standard=+SSL+exploits, deep=+subdomains+web+vulns)",
                        "enum": ["quick", "standard", "deep"],
                        "default": "quick",
                    },
                },
            },
        ),
    ]


@click.command()
@click.option("--port", default=8000, help="Port to listen on for HTTP/SSE connections")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="sse",
    help="Transport type (stdio for command line, sse for Claude Desktop)",
)
@click.option("--debug", is_flag=True, default=False, help="Enable debug mode")
def main(port: int, transport: str, debug: bool) -> int:
    """
    Start the Kali MCP Server with the specified transport.

    Args:
        port: Port number to listen on when using SSE transport
        transport: Transport type (stdio or SSE)
        debug: Enable debug mode

    Returns:
        Exit code (0 for success)
    """
    if transport == "sse":
        return start_sse_server(port, debug)
    else:
        return start_stdio_server(debug)


def start_sse_server(port: int, debug: bool) -> int:
    """
    Start the server with SSE transport for web/Claude Desktop usage.

    Args:
        port: Port number to listen on
        debug: Enable debug mode

    Returns:
        Exit code (0 for success)
    """
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    # Create SSE transport handler
    sse_transport = SseServerTransport("/messages/")

    async def handle_sse_connection(request):
        """Handle incoming SSE connections."""
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await kali_server.run(
                streams[0], streams[1], kali_server.create_initialization_options()
            )

    # Configure Starlette routes
    starlette_app = Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse_connection),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

    # Run the server
    print(f"Starting Kali MCP Server with SSE transport on port {port}")
    print(f"Connect to this server using: http://localhost:{port}/sse")
    uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    return 0


def start_stdio_server(debug: bool) -> int:
    """
    Start the server with stdio transport for command-line usage.

    Args:
        debug: Enable debug mode

    Returns:
        Exit code (0 for success)
    """
    from mcp.server.stdio import stdio_server

    async def start_stdio_connection():
        """Initialize and run the stdio server."""
        print("Starting Kali MCP Server with stdio transport")
        async with stdio_server() as streams:
            await kali_server.run(
                streams[0], streams[1], kali_server.create_initialization_options()
            )

    # Run the server
    anyio.run(start_stdio_connection)
    return 0


if __name__ == "__main__":
    main()
