# go-autobump

A CLI tool that uses [Trivy](https://trivy.dev/) to recursively scan Go modules for vulnerabilities and automatically update dependencies to fix CVEs above a configurable CVSS threshold.

## Features

- 🔍 **Recursive scanning** - Discovers and scans all `go.mod` files in a repository
- 🎯 **CVSS threshold filtering** - Only act on vulnerabilities above a configurable score
- 🔄 **Automatic updates** - Updates vulnerable dependencies to their fixed versions
- 📦 **Smart indirect dependency handling** - Traces dependency chains and updates related packages
- 🚫 **Exclude patterns** - Skip specific directories using glob patterns
- 📋 **VEX document generation** - Create OpenVEX documents for unfixed vulnerabilities
- 🤖 **AI-powered justifications** - Generate VEX justifications using OpenAI-compatible APIs

## Installation

### Using Go Install

```bash
go install github.com/tamcore/go-autobump@latest
```

### Using Go Run

```bash
go run github.com/tamcore/go-autobump@latest [command] [flags]
```

### From Source

```bash
git clone https://github.com/tamcore/go-autobump.git
cd go-autobump
go build -o go-autobump .
```

## Prerequisites

- Go 1.21 or later
- [Trivy](https://trivy.dev/) installed and available in PATH

## Usage

### Scan for Vulnerabilities

Scan all go.mod files and report vulnerabilities above the CVSS threshold:

```bash
# Scan current directory
go-autobump scan

# Scan specific path
go-autobump scan --path /path/to/repo

# Scan with custom CVSS threshold (default: 7.0)
go-autobump scan --cvss-threshold 8.0

# Exclude certain directories
go-autobump scan --exclude "examples/*/go.mod" --exclude "vendor/**"
```

### Update Vulnerable Dependencies

Automatically update dependencies to fix vulnerabilities:

```bash
# Update dependencies in current directory
go-autobump update

# Update with major version bumps allowed
go-autobump update --allow-major

# Preview changes without applying them
go-autobump update --dry-run

# Skip running go mod tidy after updates
go-autobump update --skip-tidy
```

### Generate VEX Documents

Generate OpenVEX documents for vulnerabilities that cannot be automatically fixed:

```bash
# Generate VEX document
go-autobump update --generate-vex

# Custom VEX output path
go-autobump update --generate-vex --vex-output ".vex/vulnerabilities.json"

# Use AI to generate justifications (requires API key)
go-autobump update --generate-vex --ai-api-key "$OPENAI_API_KEY"
```

## Configuration

Create a `.autobump.yaml` file in your project root or home directory:

```yaml
# Target directory to scan
path: "."

# Exclude patterns for go.mod files (glob patterns)
exclude:
  - "vendor/**"
  - "examples/*/go.mod"
  - "testdata/**"

# Minimum CVSS score threshold (default: 7.0)
cvss-threshold: 7.0

# Skip running 'go mod tidy' after updates
skip-tidy: false

# Preview changes without applying them
dry-run: false

# Allow major version bumps (e.g., v1 -> v2)
allow-major: false

# Generate VEX documents for unfixed vulnerabilities
generate-vex: false

# Output path for VEX documents
vex-output: ".vex.openvex.json"

# AI configuration for VEX justification generation
ai:
  # API key (or use AUTOBUMP_AI_API_KEY env var)
  api-key: ""
  # API endpoint (OpenAI, IONOS Modelhub, Azure OpenAI, etc.)
  endpoint: "https://api.openai.com/v1"
  # Model to use
  model: "gpt-4o"
```

## CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--path` | Target directory or go.mod file to scan | `.` |
| `--exclude` | Glob patterns to exclude (repeatable) | `[]` |
| `--cvss-threshold` | Minimum CVSS score to act on | `7.0` |
| `--dry-run` | Preview changes without applying | `false` |
| `--skip-tidy` | Skip running go mod tidy | `false` |
| `--allow-major` | Allow major version bumps | `false` |
| `--generate-vex` | Generate VEX document for unfixed CVEs | `false` |
| `--vex-output` | Output path for VEX document | `.vex.openvex.json` |
| `--ai-api-key` | API key for AI provider | |
| `--ai-endpoint` | AI API endpoint | `https://api.openai.com/v1` |
| `--ai-model` | AI model to use | `gpt-4o` |

## GitHub Actions Workflow

### Basic Workflow

```yaml
name: Security - Update Vulnerable Dependencies

on:
  schedule:
    # Run weekly on Monday at 9am UTC
    - cron: '0 9 * * 1'
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  update-dependencies:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install Trivy
        run: |
          sudo apt-get install -y wget apt-transport-https gnupg lsb-release
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
          sudo apt-get update
          sudo apt-get install -y trivy

      - name: Update Trivy DB
        run: trivy --download-db-only

      - name: Run go-autobump
        run: |
          go run github.com/tamcore/go-autobump@latest update \
            --cvss-threshold 7.0 \
            --allow-major

      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v6
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          commit-message: "fix(deps): update vulnerable dependencies"
          title: "Security: Update vulnerable dependencies"
          body: |
            This PR was automatically generated by [go-autobump](https://github.com/tamcore/go-autobump).
            
            It updates dependencies with known vulnerabilities (CVSS >= 7.0) to their fixed versions.
            
            Please review the changes and ensure tests pass before merging.
          branch: security/update-vulnerable-deps
          delete-branch: true
```

### Advanced Workflow with VEX Generation

```yaml
name: Security - Scan and Update Dependencies

on:
  schedule:
    - cron: '0 9 * * 1'
  workflow_dispatch:
  push:
    paths:
      - '**/go.mod'
      - '**/go.sum'

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    outputs:
      has-vulnerabilities: ${{ steps.scan.outputs.has-vulnerabilities }}
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install Trivy
        run: |
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
          sudo apt-get update && sudo apt-get install -y trivy
          trivy --download-db-only

      - name: Scan for vulnerabilities
        id: scan
        run: |
          OUTPUT=$(go run github.com/tamcore/go-autobump@latest scan --cvss-threshold 7.0 2>&1)
          echo "$OUTPUT"
          if echo "$OUTPUT" | grep -q "No vulnerabilities found"; then
            echo "has-vulnerabilities=false" >> $GITHUB_OUTPUT
          else
            echo "has-vulnerabilities=true" >> $GITHUB_OUTPUT
          fi

  update:
    needs: scan
    if: needs.scan.outputs.has-vulnerabilities == 'true'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install Trivy
        run: |
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
          sudo apt-get update && sudo apt-get install -y trivy
          trivy --download-db-only

      - name: Update dependencies and generate VEX
        env:
          AUTOBUMP_AI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          go run github.com/tamcore/go-autobump@latest update \
            --cvss-threshold 7.0 \
            --allow-major \
            --generate-vex \
            --vex-output .vex.openvex.json

      - name: Upload VEX artifact
        uses: actions/upload-artifact@v4
        with:
          name: vex-document
          path: .vex.openvex.json
        if: hashFiles('.vex.openvex.json') != ''

      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v6
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          commit-message: "fix(deps): update vulnerable dependencies"
          title: "Security: Update vulnerable dependencies"
          body: |
            ## Automated Security Update
            
            This PR updates dependencies with known vulnerabilities (CVSS >= 7.0).
            
            ### Changes
            - Updated vulnerable dependencies to fixed versions
            - Generated VEX document for any unfixed vulnerabilities
            
            ### Generated by
            [go-autobump](https://github.com/tamcore/go-autobump)
          branch: security/update-vulnerable-deps
          delete-branch: true
```

### Monorepo Workflow with Exclusions

```yaml
name: Security - Update Dependencies (Monorepo)

on:
  schedule:
    - cron: '0 9 * * 1'
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install Trivy
        run: |
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
          sudo apt-get update && sudo apt-get install -y trivy
          trivy --download-db-only

      - name: Update dependencies
        run: |
          go run github.com/tamcore/go-autobump@latest update \
            --cvss-threshold 7.0 \
            --allow-major \
            --exclude "examples/*/go.mod" \
            --exclude "testdata/**" \
            --exclude "vendor/**"

      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v6
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          commit-message: "fix(deps): update vulnerable dependencies"
          title: "Security: Update vulnerable dependencies"
          branch: security/update-vulnerable-deps
```

## How It Works

1. **Discovery** - Recursively finds all `go.mod` files in the target path
2. **Scanning** - Uses Trivy to scan each module for vulnerabilities
3. **Filtering** - Filters vulnerabilities by CVSS score threshold
4. **Analysis** - Determines if each vulnerability is in a direct or indirect dependency
5. **Update Strategy**:
   - **Direct dependencies**: Updates directly using `go get`
   - **Indirect dependencies**: 
     1. First tries direct update
     2. Traces dependency chain using `go mod why`
     3. Falls back to updating related packages from the same namespace
6. **Verification** - Re-scans after updates to confirm fixes
7. **VEX Generation** - Creates OpenVEX documents for any remaining unfixed vulnerabilities

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read [AGENTS.md](AGENTS.md) for development guidelines.
