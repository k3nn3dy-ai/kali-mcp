[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/k3nn3dy-ai-kali-mcp-badge.png)](https://mseep.ai/app/k3nn3dy-ai-kali-mcp)

# Kali MCP Server

A production-ready MCP (Model Context Protocol) server running in a Kali Linux Docker container, providing AI assistants with access to 35 security tools covering the full offensive security lifecycle.

[![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

## Overview

This project provides a Docker containerized MCP server that runs on Kali Linux, giving AI assistants (like Claude) access to a full suite of security and penetration testing tools. The server communicates via Server-Sent Events (SSE) or stdio and allows AI to execute commands in a controlled environment.

## Quick Start

### Building and Running the Container

```bash
# Quick start with the helper script
./run_docker.sh

# Or with Docker Compose
docker compose up --build -d

# Or manually:
docker build -t kali-mcp-server .
docker run -p 8000:8000 kali-mcp-server
```

### Development Checks

```bash
# install dev dependencies
./run_tests.sh install

# individual checks
./run_tests.sh typecheck     # pyright
./run_tests.sh lint          # ruff check .
./run_tests.sh format        # ruff format .
./run_tests.sh test          # pytest
./run_tests.sh test-tools    # pytest tests/test_tools.py
./run_tests.sh test-session  # pytest -k "session"

# run install + typecheck + lint + tests
./run_tests.sh all
```

### Connecting to Claude Desktop

1. Edit your Claude Desktop config file at `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "transport": "sse",
      "url": "http://localhost:8000/sse",
      "command": "docker compose up -d"
    }
  }
}
```

2. Restart Claude Desktop
3. Test with: `/run nmap -F localhost`

## Available MCP Tools (35)

### Core Tools

| Tool | Description |
|------|-------------|
| `run` | Execute shell commands in the Kali Linux environment |
| `fetch` | Fetch and analyze web content from URLs |
| `resources` | List available system resources and command examples |

### Reconnaissance & Scanning

| Tool | Description |
|------|-------------|
| `port_scan` | Smart nmap wrapper with scan presets (quick, full, stealth, udp, service, aggressive) |
| `dns_enum` | Comprehensive DNS enumeration with zone transfer attempts |
| `network_discovery` | Multi-stage network reconnaissance and discovery |
| `subdomain_enum` | Subdomain enumeration using subfinder, amass, waybackurls |
| `recon_auto` | Automated multi-stage reconnaissance pipeline |

### Web Application Testing

| Tool | Description |
|------|-------------|
| `vulnerability_scan` | Automated vulnerability assessment with multiple tools |
| `web_enumeration` | Web application discovery and enumeration |
| `web_audit` | Comprehensive web application security audit |
| `spider_website` | Web crawling and spidering using gospider |
| `form_analysis` | Discover and analyze web forms |
| `header_analysis` | HTTP header security analysis |
| `ssl_analysis` | SSL/TLS security assessment using testssl.sh |

### Credential & Brute-Force Attacks

| Tool | Description |
|------|-------------|
| `hydra_attack` | Brute-force credential testing via hydra (SSH, FTP, HTTP, SMB, MySQL, RDP, etc.) |
| `credential_store` | Store/retrieve discovered credentials tied to sessions |

### Payload & Exploit Tools

| Tool | Description |
|------|-------------|
| `payload_generate` | Generate payloads using msfvenom (reverse shell, bind shell, meterpreter) |
| `reverse_shell` | Generate reverse shell one-liners for bash, python, php, perl, powershell, nc, ruby, java |
| `exploit_search` | Search for exploits using searchsploit |

### Encoding & Hash Tools

| Tool | Description |
|------|-------------|
| `encode_decode` | Multi-format encoding/decoding (base64, URL, hex, HTML, ROT13) |
| `hash_identify` | Identify hash types with Hashcat mode and John format lookup |

### Share Enumeration

| Tool | Description |
|------|-------------|
| `enum_shares` | SMB/NFS share enumeration (smbclient, enum4linux, showmount) |

### Output Parsing

| Tool | Description |
|------|-------------|
| `parse_nmap` | Parse nmap text/XML output into structured JSON findings |
| `parse_tool_output` | Parse output from nikto, gobuster, dirb, hydra, or sqlmap |

### Evidence & Reporting

| Tool | Description |
|------|-------------|
| `save_output` | Save content to timestamped files for evidence collection |
| `create_report` | Generate structured reports (markdown, text, JSON) |
| `file_analysis` | Analyze files (type detection, strings, hashes, metadata) |
| `download_file` | Download files from URLs with hash verification |

### Session Management

| Tool | Description |
|------|-------------|
| `session_create` | Create a new pentest session |
| `session_list` | List all sessions with metadata |
| `session_switch` | Switch between sessions |
| `session_status` | Show current session status |
| `session_delete` | Delete a session and its evidence |
| `session_history` | Show command history for current session |

---

## Tool Details

### `port_scan` - Smart Nmap Wrapper

Runs nmap with predefined scan presets, generating both text and XML output.

```
/port_scan target=192.168.1.1 scan_type=quick
/port_scan target=10.0.0.0/24 scan_type=aggressive ports=80,443,8080
```

**Scan Presets:**
| Preset | Nmap Flags |
|--------|-----------|
| `quick` | `-F -sV` |
| `full` | `-sS -sV -p-` |
| `stealth` | `-sS -T2 --max-retries 1` |
| `udp` | `-sU --top-ports 100` |
| `service` | `-sV --version-intensity 5 -sC` |
| `aggressive` | `-A -T4` |

### `dns_enum` - DNS Enumeration

Queries all DNS record types and attempts zone transfers.

```
/dns_enum domain=example.com
/dns_enum domain=target.com record_types=a,mx,ns,txt
```

### `recon_auto` - Automated Recon Pipeline

Runs a multi-stage reconnaissance pipeline with configurable depth.

```
/recon_auto target=example.com depth=quick
/recon_auto target=10.0.0.1 depth=standard
/recon_auto target=target.com depth=deep
```

**Depth Levels:**
| Depth | Phases |
|-------|--------|
| `quick` | DNS enumeration, quick port scan, header analysis |
| `standard` | + service scan, SSL analysis, exploit search |
| `deep` | + subdomain enumeration, web enumeration, vulnerability scan |

### `hydra_attack` - Brute-Force Testing

```
/hydra_attack target=192.168.1.1 service=ssh username=admin passlist=/usr/share/wordlists/rockyou.txt
/hydra_attack target=10.0.0.1 service=ftp userlist=users.txt passlist=passwords.txt threads=32
```

**Supported Services:** ssh, ftp, http-get, http-post-form, smb, mysql, rdp, telnet, vnc, pop3, imap, smtp

### `payload_generate` - Msfvenom Payloads

```
/payload_generate payload_type=reverse_shell platform=linux lhost=10.0.0.1 lport=4444 format=elf
/payload_generate payload_type=meterpreter platform=windows lhost=10.0.0.1 format=exe
```

**Payload Types:** reverse_shell, bind_shell, meterpreter
**Platforms:** linux, windows, osx, php, python
**Formats:** elf, exe, raw, python, php, war

### `reverse_shell` - Shell One-Liners

Generates ready-to-use reverse shell commands with listener hints.

```
/reverse_shell lhost=10.0.0.1 shell_type=bash lport=4444
/reverse_shell lhost=10.0.0.1 shell_type=python lport=9999
```

**Shell Types:** bash, python, php, perl, powershell, nc, ruby, java

### `encode_decode` - Encoding Utility

```
/encode_decode data="hello world" operation=encode format=base64
/encode_decode data="aGVsbG8gd29ybGQ=" operation=decode format=base64
/encode_decode data="<script>alert(1)</script>" operation=encode format=html
```

**Formats:** base64, url, hex, html, rot13

### `hash_identify` - Hash Identification

Identifies hash types by regex and returns Hashcat mode numbers and John format names.

```
/hash_identify hash_value=5d41402abc4b2a76b9719d911017c592
/hash_identify hash_value=$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345
```

**Supported Types:** MD5, SHA-1, SHA-256, SHA-512, bcrypt, SHA-512/256/MD5 Crypt, NTLM, Apache APR1, MySQL, Django

### `enum_shares` - Share Enumeration

```
/enum_shares target=192.168.1.1 enum_type=all
/enum_shares target=10.0.0.1 enum_type=smb username=admin password=pass
```

**Enum Types:** smb (smbclient + enum4linux), nfs (showmount), all

### `credential_store` - Credential Management

Stores discovered credentials as JSON tied to the active session.

```
/credential_store action=add username=admin password=pass123 service=ssh target=10.0.0.1
/credential_store action=list
/credential_store action=search username=admin
```

### `parse_nmap` - Nmap Output Parser

Parses both text and XML nmap output into structured JSON with hosts, open ports, services, OS detection, and script output.

```
/parse_nmap filepath=port_scan_10_0_0_1_quick_20240101_120000.txt
/parse_nmap filepath=scan_results.xml
```

### `parse_tool_output` - Generic Output Parser

Auto-detects and parses output from nikto, gobuster, dirb, hydra, or sqlmap.

```
/parse_tool_output filepath=nikto_results.txt
/parse_tool_output filepath=gobuster_output.txt tool_type=gobuster
```

### `vulnerability_scan`

```
/vulnerability_scan target=127.0.0.1 scan_type=quick
/vulnerability_scan target=example.com scan_type=comprehensive
```

**Scan Types:** quick, comprehensive, web, network

### `web_enumeration`

```
/web_enumeration target=http://example.com enumeration_type=full
```

**Types:** basic, full, aggressive

### `network_discovery`

```
/network_discovery target=192.168.1.0/24 discovery_type=comprehensive
```

**Types:** quick, comprehensive, stealth

---

## Pre-installed Tools

The Docker container includes the following tools, all enabled for use through the `run` command:

| Category | Tools |
|----------|-------|
| **Network Scanning** | nmap, masscan, netcat, tcpdump, tshark |
| **Web Testing** | nikto, gobuster, dirb, sqlmap, wfuzz, ffuf, feroxbuster, whatweb, wafw00f |
| **Exploitation** | metasploit-framework (msfconsole, msfvenom), searchsploit |
| **Credential Attacks** | hydra, hashcat, john |
| **Information Gathering** | whois, dig, nslookup, amass, subfinder, theharvester, recon-ng, fierce, dnsenum, dnsrecon |
| **Web Crawling** | gospider, waybackurls |
| **Share Enumeration** | smbclient, enum4linux, showmount (nfs-common) |
| **SSL/TLS** | testssl.sh, openssl |
| **HTTP Probing** | httpx-toolkit, curl, wget |
| **File Analysis** | file, strings, binwalk, exiftool, xxd, hexdump |
| **Utilities** | python3, perl, ruby, php, git, base64, jq |

All commands are allowed by default inside the container. The container itself is the security boundary.

## Security Considerations

- **Container isolation**: The server runs inside an isolated Docker container. Root is used inside the container because many security tools (nmap SYN scans, tcpdump, etc.) require raw socket access
- **Input sanitization**: Shell metacharacters (`;`, `&`, `|`) are stripped from all command input
- **No host access**: The container has no access to the host filesystem or network stack (unless volumes are explicitly mounted)
- **Authorization required**: Only use for legitimate security testing with proper authorization
- **Local only**: The container should not be exposed to the internet

## Requirements

- Docker
- Claude Desktop or other MCP client (SSE or stdio)
- Port 8000 available on your host machine

## Development

### Setup

```bash
git clone https://github.com/yourusername/kali-mcp-server.git
cd kali-mcp-server

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Checks

```bash
# All checks
./run_tests.sh

# Individual
pyright                          # Type checking
ruff check .                     # Linting
ruff format .                    # Formatting
pytest                           # All tests
pytest tests/test_tools.py       # Single file
pytest -k "session"              # Pattern match
```

### Architecture

Adding a new tool requires changes in three places:

1. **`kali_mcp_server/tools.py`** - Implement the async function
2. **`kali_mcp_server/server.py`** - Add dispatch in `handle_tool_request()` and schema in `list_available_tools()`
3. **`tests/`** - Add tests in both `test_tools.py` and `test_server.py`

## Acknowledgements

- Kali Linux for their security-focused distribution
- Anthropic for Claude and the MCP protocol
- The open-source security tools community

---

<p align="center">
  <sub>Built for security professionals and AI assistants</sub>
</p>
