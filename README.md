# Skill Security Scanner

A Python CLI tool that analyzes skill.md files for security vulnerabilities using a local Ollama LLM.

## Overview

This tool performs comprehensive security analysis on AI skill files before installation. It checks for:
- Hidden instructions and steganography
- Prompt injection attacks
- Credential and PII exposure
- External data fetching and exfiltration
- Code execution attempts
- Network operations and sandbox escapes
- Social engineering patterns

## Features

- 🔍 **13 Security Categories** - Comprehensive vulnerability detection
- 🌐 **URL Classification** - Risk-based categorization of external links
- 🎨 **Color-Coded Output** - Clear pass/fail/warning indicators
- 📊 **JSON Support** - Machine-readable output for CI/CD integration
- 🔒 **Safe Analysis** - Uses LLM for analysis only, no system access

## Requirements

- Python 3.12+
- Ollama running locally (or accessible instance)
- kimi-k2.5:cloud model (or compatible model)

## Installation

```bash
# Clone or navigate to the repository
cd skillcheck

# Install dependencies
pip install -e .

# Or with pip and optional features
pip install -e ".[geolocation]"  # Include geoip2 for IP geolocation
pip install -e ".[all]"         # Include all optional features
```

### Optional: GeoLite2 IP Geolocation Database

To enable IP geolocation features (identifying countries for IP addresses in URLs):

1. **Register for a free MaxMind account:**
   - Go to: https://www.maxmind.com/en/geolite2/signup
   - Sign up for a free account
   - Accept the GeoLite2 End User License Agreement

2. **Generate a License Key:**
   - Log in to: https://www.maxmind.com/en/accounts/current/license-key
   - Create a new license key

3. **Download the Database:**
   - Go to: https://www.maxmind.com/en/accounts/current/geoip/downloads
   - Download `GeoLite2-Country` (country-level data, ~5MB)
   - Or download `GeoLite2-City` (city-level data, ~30MB)
   - Choose the `.mmdb` binary format

4. **Install the Database:**
   ```bash
   # Option 1: Place in project root (recommended for development)
   cp ~/Downloads/GeoLite2-Country.mmdb /home/paul/source/pythonProjects/skillcheck/
   
   # Option 2: Create data directory
   mkdir -p /home/paul/source/pythonProjects/skillcheck/data
   cp ~/Downloads/GeoLite2-Country.mmdb /home/paul/source/pythonProjects/skillcheck/data/
   
   # Option 3: System-wide location
   sudo mkdir -p /usr/share/GeoIP/
   sudo cp ~/Downloads/GeoLite2-Country.mmdb /usr/share/GeoIP/
   ```

5. **Install Python Dependencies:**
   ```bash
   pip install geoip2
   ```

6. **Test the Setup:**
   ```python
   python -c "from ip_geolocation import lookup_ip_geolocation; print(lookup_ip_geolocation('8.8.8.8'))"
   ```

**Note:** The GeoLite2 database is not included in this repository (see `.gitignore`).
It must be downloaded separately and is subject to MaxMind's license terms.
Users must keep the database updated (max 30 days old per license agreement).

## Usage

### Basic Usage

```bash
# Analyze a skill file
python main.py path/to/skill.md

# JSON output for programmatic use
python main.py path/to/skill.md --format=json

# Custom Ollama instance
python main.py path/to/skill.md --host http://ollama.internal:11434 --model llama3.2

# Use OpenAI API instead of Ollama
export OPENAI_API_KEY=sk-your-key-here
python main.py path/to/skill.md --openai

# Increase parallel threads (default: 3)
python main.py path/to/skill.md --threads=4

# Skip translation of non-English content
python main.py path/to/skill.md --no-translate

# Show detailed progress indicators
python main.py path/to/skill.md --verbose

# Force pass (exit 0) even with critical issues (manual review only)
python main.py path/to/skill.md --force-pass

# Extract and translate non-English content (no analysis)
python main.py path/to/skill.md --translate
```

### Examples

#### Safe Skill File
```bash
$ python main.py tests/safe_skill.md

🔍 Security Analysis: tests/safe_skill.md
═══════════════════════════════════════════════════

✅ Hidden Instructions     [PASS]
✅ Jailbreaking           [PASS]
✅ Credential Exposure    [PASS]
✅ PII Leakage            [PASS]
✅ Token Exfiltration     [PASS]
✅ External Data Fetch    [PASS]
✅ Data Exfiltration      [PASS]
✅ Code Execution         [PASS]
✅ File System Access     [PASS]
✅ Network Operations     [PASS]
✅ Sandbox Escape         [PASS]
✅ Indirect Injection     [PASS]
✅ Social Engineering     [PASS]

🌐 External URLs: None

📊 Summary: 13/13 PASSED
```

#### Unsafe Skill File
```bash
$ python main.py tests/unsafe_skill.md

🔍 Security Analysis: tests/unsafe_skill.md
═══════════════════════════════════════════════════

❌ Hidden Instructions     [CRITICAL] Base64 payload detected
✅ Jailbreaking           [PASS]
❌ Credential Exposure    [CRITICAL] API key: sk-abc123...
✅ PII Leakage            [PASS]
⚠️  Token Exfiltration     [MEDIUM] Suspicious pattern
✅ External Data Fetch    [PASS]
⚠️  Data Exfiltration      [MEDIUM] Potential exfil pattern
❌ Code Execution         [CRITICAL] Shell command detected
✅ File System Access     [PASS]
✅ Network Operations     [PASS]
✅ Sandbox Escape         [PASS]
⚠️  Indirect Injection     [MEDIUM] External URL referenced
✅ Social Engineering     [PASS]

🌐 External URLs:
   ⚠️  https://docs.example.com (Established company - review)
   ❌ https://bit.ly/3xMal     (URL shortener)
   ❌ https://192.168.1.1/api  (IP address)

📊 Summary: 3 CRITICAL, 3 MEDIUM, 7 PASSED
```

#### JSON Output
```bash
$ python main.py tests/unsafe_skill.md --format=json | jq .

{
  "file": "tests/unsafe_skill.md",
  "timestamp": "2025-01-15T10:30:00Z",
  "checks": [
    {
      "category": "hidden_instructions",
      "passed": false,
      "severity": "critical",
      "description": "Base64 encoded payload detected",
      "evidence": ["Line 45: `...base64...`"]
    }
    // ... more checks
  ],
  "urls": {
    "all": ["https://docs.example.com", "https://bit.ly/3xMal"],
    "trusted": [],
    "medium": ["https://docs.example.com"],
    "malicious": ["https://bit.ly/3xMal"]
  },
  "summary": {
    "total_checks": 13,
    "passed": 7,
    "failed": 3,
    "critical": 3,
    "high": 0,
    "medium": 3,
    "low": 0
  },
  "exit_code": 1
}
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no critical issues |
| 1 | Critical security issues detected |
| 2 | File not found or read error |
| 3 | Ollama connection failed |
| 4 | Invalid arguments |

## Security Check Categories

1. **Hidden Instructions** - Base64, Unicode tricks, invisible characters, steganography
2. **Jailbreaking Attempts** - System prompt overrides, role-playing attacks
3. **Credential Exposure** - API keys, tokens, passwords, secrets
4. **PII Leakage** - Email, phone, SSN, addresses, names
5. **Token Exfiltration** - Patterns sending tokens to external sites
6. **External Data Fetching** - URLs in fetch/read operations
7. **Data Exfiltration** - Patterns exfiltrating conversation data
8. **Code Execution** - Shell commands, eval(), exec(), subprocess
9. **File System Access** - Read/write operations, path traversal
10. **Network Operations** - Webhooks, HTTP requests, sockets
11. **Sandbox Escape** - Container/VM escape attempts
12. **Indirect Injection** - Loading from compromised external sources
13. **Social Engineering** - Deceptive instructions, trust exploitation

## URL Risk Classification

### Trusted (Low Risk)
- docs.claude.ai, anthropic.com, opencode.ai
- platform.openai.com, openai.com

### Medium Risk (Review Required)
Established companies with controlled content:
- google.com, microsoft.com, amazon.com
- apple.com, salesforce.com, adobe.com

### Suspicious (High Risk)
Open contribution platforms:
- github.com, gist.github.com, pastebin.com
- codepen.io, jsfiddle.net, replit.com

### Malicious (Critical)
- URL shorteners (bit.ly, tinyurl, t.co)
- IP addresses in URLs
- Known malicious domains
- Suspicious TLDs (.tk, .ml, .cf)

### Unknown (Flag for Review)
- Any domain not in known lists
- Newly registered domains

## Integration Examples

### GitHub Actions
```yaml
name: Security Check
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install ollama colorama
      - name: Run security check
        run: |
          python main.py skills/*.md --format=json > results.json
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: results.json
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skill-security-check
        name: Security check for skill files
        entry: python main.py
        language: system
        files: '.*\.md$'
```

### Shell Script
```bash
#!/bin/bash
# check-skills.sh

EXIT_CODE=0

for skill in skills/*.md; do
    echo "Checking: $skill"
    python main.py "$skill" --format=json > "results/$(basename $skill .md).json"
    if [ $? -ne 0 ]; then
        echo "❌ Security issues found in $skill"
        EXIT_CODE=1
    fi
done

exit $EXIT_CODE
```

## Architecture

```
skillcheck/
├── main.py                    # CLI entry point
├── analyzer.py                # Ollama LLM integration
├── prompt_builder.py          # Security analysis prompts
├── result_parser.py           # Parse LLM responses
├── formatter.py               # Output formatting
├── url_classifier.py          # URL categorization
├── pyproject.toml             # Dependencies
├── PRD.md                     # Product requirements
└── tests/
    ├── safe_skill.md          # Clean test file
    └── unsafe_skill.md        # Vulnerable test file
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_API_BASE` | Full base URL for Ollama API | `http://127.0.0.1:11434` |
| `OLLAMA_HOST` | Hostname only (used if API_BASE not set) | `127.0.0.1` |
| `OLLAMA_MODEL` | Model name to use | `kimi-k2.5:cloud` |
| `OPENAI_API_KEY` | OpenAI API key (required for `--openai` flag) | - |
| `OPENAI_MODEL` | OpenAI model name | `gpt-4o-mini` |
| `OPENAI_BASE_URL` | Custom OpenAI-compatible API base URL | - |

The tool checks environment variables in this priority order:
1. `OLLAMA_API_BASE` (full URL: `http://127.0.0.1:11434`)
2. `OLLAMA_HOST` (hostname only: `127.0.0.1`)
3. Default: `http://127.0.0.1:11434`

### Setup Examples

```bash
# Option 1: Set full API base URL
export OLLAMA_API_BASE=http://127.0.0.1:11434
python main.py skill.md

# Option 2: Set hostname only (uses default port 11434)
export OLLAMA_HOST=127.0.0.1
python main.py skill.md

# Option 3: Command line overrides (highest priority)
export OLLAMA_API_BASE=http://127.0.0.1:11434
python main.py skill.md --host http://192.168.1.100:11434

# Option 4: Custom model
export OLLAMA_MODEL=kimi-k2.5:cloud
python main.py skill.md
```

### Ollama Setup
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull kimi-k2.5:cloud

# Start server
ollama serve
```

## Development

### Running Tests
```bash
# Test safe skill (should exit 0)
python main.py tests/safe_skill.md
echo "Exit code: $?"

# Test unsafe skill (should exit 1)
python main.py tests/unsafe_skill.md
echo "Exit code: $?"

# Test JSON output
python main.py tests/safe_skill.md --format=json | jq .
```

### Adding New Checks

1. Update `prompt_builder.py` with new category description
2. Add category to `result_parser.py` validation
3. Update `formatter.py` display logic
4. Update documentation in README.md and PRD.md

## Troubleshooting

### Connection Issues
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Test with explicit host
python main.py skill.md --host http://localhost:11434
```

### Model Not Found
```bash
# List available models
ollama list

# Pull required model
ollama pull kimi-k2.5:cloud
```

## License

MIT License - See LICENSE file for details.

## Contributing

### Development Setup

```bash
git clone https://github.com/Paul-J-Barrett/skillcheck.git
cd skillcheck
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
pip install -r requirements-dev.txt
```

### Pull Request Guidelines

1. Add tests for new detection methods
2. Update documentation
3. Ensure all existing tests pass
4. Follow PEP 8 style guidelines

## Disclaimer

**IMPORTANT LEGAL NOTICE**

This is a personal pet project created for my own use and shared with the community. While built with AI assistance to help mitigate risks when using AI agent skills, it comes with important limitations:

- **No Warranty**: This software is provided "as-is" without any warranty of any kind, express or implied
- **Best-Effort Detection**: No security scanner can catch 100% of threats or vulnerabilities
- **Not Professional Security Advice**: This tool does not constitute professional security consulting or advice
- **User Responsibility**: You are solely responsible for:
  - Reviewing and understanding any security findings before taking action
  - Determining whether a skill is safe to use in your environment
  - Any consequences resulting from use of this tool or the skills it analyzes
  - Ensuring compliance with your organization's security policies

**AI-Generated Code Notice**: This project was developed with assistance from AI systems. While efforts have been made to ensure quality and security, AI-generated code may contain errors, oversights, or security issues.

**Usage Liability**: The author(s) assume no liability for:
- Damages arising from use or inability to use this software
- Security breaches or data loss
- Decisions made based on tool output
- False positives or false negatives in detection

**By using this tool, you acknowledge that ultimate responsibility for security decisions lies entirely with you, the user.**

## Security

This tool is designed for security analysis only. It:
- Reads skill files (read-only access)
- Sends content to Ollama for analysis
- Does not execute any code from analyzed files
- Does not make external network requests (except to Ollama)

**Note**: Always review skill files manually before installation, especially when critical issues are detected.
