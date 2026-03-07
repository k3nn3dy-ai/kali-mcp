# Contributing to Kali MCP Server

## Development Setup

```bash
# Clone the repo
git clone https://github.com/k3nn3dy-ai/kali-mcp.git
cd kali-mcp

# Install dependencies (using uv)
uv sync --dev

# Or using pip
pip install -e ".[dev]"
```

## Running Checks Locally

```bash
# All checks at once
./run_tests.sh all

# Individual checks
./run_tests.sh lint       # Ruff linting
./run_tests.sh format     # Ruff formatting
./run_tests.sh typecheck  # Pyright type checking
./run_tests.sh test       # Pytest
```

## Pull Request Workflow

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Run `./run_tests.sh all` to verify everything passes
4. Open a pull request targeting `main`

### Requirements for merging

- At least 1 approving review
- All CI checks must pass (lint, typecheck, tests, Docker build)
- Review threads must be resolved
- Branch must be up to date with `main`

## Branch Protection

The `main` branch is protected with the following rules:

- **No direct pushes** — all changes go through pull requests
- **No force pushes** or branch deletion
- **Required status checks** — CI must pass before merging
- **Required reviews** — at least 1 approving review
- **Stale review dismissal** — re-review required after new pushes

## Setting Up Branch Protection

A repository admin can apply the branch protection ruleset by running:

```bash
gh api repos/OWNER/REPO/rulesets \
  --method POST \
  --input .github/branch-protection.json
```

Replace `OWNER/REPO` with the actual repository path (e.g., `k3nn3dy-ai/kali-mcp`).
