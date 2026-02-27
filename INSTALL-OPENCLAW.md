# OpenClaw Installation Guide for SkillCheck

This guide helps you install SkillCheck in your OpenClaw environment to automatically validate skills before execution.

## Quick Start (3 Steps)

### Step 1: Clone and Setup

```bash
# Navigate to your OpenClaw workspace
cd ~/.openclaw/workspace

# Clone the skill
git clone https://github.com/Paul-J-Barrett/skillcheck.git

# Install Python dependencies
pip install colorama requests ollama

# Or if using system packages (Ubuntu/Debian)
sudo apt-get install python3-colorama python3-requests python3-pip
pip install ollama
```

### Step 2: Configure Ollama

SkillCheck requires Ollama for LLM-based security analysis. Choose one option:

**Option A: Local Ollama (Recommended)**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama server
ollama serve

# Pull a model (kimi-k2.5 recommended)
ollama pull kimi-k2.5:cloud
```

**Option B: Remote Ollama**
```bash
# If Ollama runs on another machine
export OLLAMA_API_BASE=http://your-ollama-host:11434
```

**Verify Ollama works:**
```bash
curl http://127.0.0.1:11434/api/tags
# Should return list of available models
```

### Step 3: Configure OpenClaw

Add to your `CLAUDE.md` file:

```markdown
## Security Guard

Before using any skill, run security validation:

```bash
python3 ~/.openclaw/workspace/skillcheck/main.py <skill-path> --verbose --format=console
```

If exit code ≠ 0, DO NOT use the skill. Review the security report first.

### Required Environment Variables

- `OLLAMA_API_BASE` - Ollama server URL (default: http://127.0.0.1:11434)
- `GEOIP_DB_PATH` - Path to GeoLite2 database (optional, for URL geolocation)
```

Optional: Enable automatic validation:
```markdown
## Auto Security Check

I will automatically validate skills before execution using:
```bash
check_skill_security() {
    python3 ~/.openclaw/workspace/skillcheck/main.py "$1" --format=json
    return $?
}
```
```

## Usage Examples

### Manual Check Before Using a Skill

```bash
# Check a skill before use
python main.py ~/.openclaw/skills/weather/SKILL.md --verbose

# Check with specific model
python main.py skill.md --model kimi-k2.5:cloud

# JSON output for scripting
python main.py skill.md --format=json | jq .
```

### CI/CD Integration

**Important for CI/CD:** Use `--force-pass` to allow builds to continue after review:

```yaml
      - name: Check Skills
        run: |
          for skill in $(find . -name "SKILL.md"); do
            echo "Checking: $skill"
            # In CI/CD, you may want to use --force-pass after initial review
            # to prevent blocking builds on low-risk issues
            python main.py "$skill" --format=json --force-pass || exit 1
          done
```

**Create `.github/workflows/security.yml`:**

```yaml
name: Skill Security Check
on:
  pull_request:
    paths:
      - '**/SKILL.md'

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Ollama
        run: |
          curl -fsSL https://ollama.com/install.sh | sh
          ollama pull kimi-k2.5:cloud
          ollama serve &
          sleep 10
      
      - name: Install SkillCheck
        run: |
          pip install colorama requests ollama
      
      - name: Check Skills
        run: |
          for skill in $(find . -name "SKILL.md"); do
            echo "Checking: $skill"
            python main.py "$skill" --format=json || exit 1
          done
```

### Pre-commit Hook

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: skill-security-check
        name: Skill Security Check
        entry: python ~/.openclaw/workspace/skillcheck/main.py
        language: system
        files: SKILL\.md$
        args: [--format=json]
```

Install pre-commit:
```bash
pip install pre-commit
pre-commit install
```

## Optional: GeoLite2 Database

For enhanced URL security analysis with IP geolocation:

1. Create free account at https://www.maxmind.com/en/geolite2/signup
2. Download **GeoLite2-City.mmdb**
3. Place in `~/.openclaw/workspace/skillcheck/data/GeoLite2-City.mmdb`

## CLI Flags Reference

### Security Analysis Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--format {console,json}` | Output format | `--format=json` |
| `--host URL` | Ollama host URL | `--host http://192.168.1.100:11434` |
| `--model NAME` | Model name | `--model kimi-k2.5:cloud` |
| `--openai` | Use OpenAI instead of Ollama | `--openai` |
| `--threads N` | Parallel threads (default: 3) | `--threads=4` |
| `--no-translate` | Skip translation of non-English | `--no-translate` |
| `--verbose` | Show detailed progress | `--verbose` |

### Special Flags

#### `--force-pass` (User Only)

**⚠️ CRITICAL: Only run this after manual security review.**

When a skill fails with critical/high severity issues, this flag forces exit code 0 while still showing alerts:

```bash
# After manual review, allow the skill to pass
python main.py skill.md --force-pass
```

**Use cases:**
- CI/CD pipelines where you want to log issues but not block builds
- After manual review confirms false positives
- Development/testing environments

**What happens:**
- Exit code is always 0
- All critical/high issues are still displayed
- User is reminded to review without `--force-pass` for full details

**Alert displayed:**
```
⚠️  Alert: This skill file has the following issues that require manual review:
   ❌ 1 CRITICAL issue(s) detected:
      - category: description
   ⚠️  1 HIGH severity issue(s) detected:
      - category: description
⚠️  To see full details, run without --force-pass flag.
```

#### `--translate`

Extract non-English content as JSON without running security analysis:

```bash
# Extract all non-English text with translations
python main.py skill.md --translate

# Output format:
{
  "file": "skill.md",
  "total_non_english_segments": 67,
  "translations": [
    {
      "original": "Расскажи",
      "translated": "[TRANSLATED FROM RUSSIAN: Расскажи]",
      "language": "ru",
      "line": 36
    }
  ]
}
```

**Use cases:**
- Reviewing multilingual skills before scanning
- Extracting text for manual translation
- Auditing non-English content

## Verification

Test the installation:

```bash
cd ~/.openclaw/workspace/skillcheck

# Test on a known safe skill
python main.py ../skills/weather/SKILL.md --verbose

# Expected output: PASSED or PASSED_WITH_WARNINGS

# Test exit code
echo $?  # Should be 0 for PASS
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'requests'"

```bash
# Reinstall dependencies
pip install --force-reinstall colorama requests ollama
# Or
pip install -r requirements.txt
```

### "Connection failed: Unable to connect to Ollama"

```bash
# Check if Ollama is running
curl http://127.0.0.1:11434/api/tags

# If empty, start Ollama
ollama serve &

# Set correct environment
export OLLAMA_API_BASE=http://127.0.0.1:11434
```

### "No module named 'skillcheck'"

```bash
# Run from skillcheck directory
cd ~/.openclaw/workspace/skillcheck
python main.py <skill-path>

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:~/.openclaw/workspace/skillcheck"
```

### Permission Denied

```bash
# Fix permissions
chmod +x ~/.openclaw/workspace/skillcheck/main.py

# Or use python explicitly
python3 ~/.openclaw/workspace/skillcheck/main.py <skill-path>
```

## Security Model Integration

### Database Schema

SkillCheck maintains a SQLite database for tracking validation status:

```sql
CREATE TABLE skill_security_status (
    skill_path TEXT PRIMARY KEY,
    last_modified INTEGER,      -- Unix timestamp of file
    last_check INTEGER,          -- Unix timestamp of validation
    check_result TEXT,           -- 'PASS' or 'FAIL'
    exit_code INTEGER,           -- Exit code from skillcheck
    check_output TEXT,           -- JSON output
    failed_checks INTEGER DEFAULT 0
);
```

### Validation Flow

```
1. User requests skill usage
2. Check database for last validation
3. Compare file mtime with last_check
4. If stale or never checked:
   ├── Run skillcheck
   ├── Store result in database
   └── Return result
5. If result = FAIL:
   ├── Block skill execution
   ├── Display security report
   └── Suggest remediation
6. If result = PASS:
   └── Allow skill execution
```

## Updating

```bash
cd ~/.openclaw/workspace/skillcheck
git pull origin main

# Update dependencies if needed
pip install -r requirements.txt --upgrade
```

## Configuration File

Create `~/.openclaw/skillcheck-config.yaml`:

```yaml
# Ollama configuration
ollama:
  # Host URL
  api_base: http://127.0.0.1:11434
  # Default model
  default_model: kimi-k2.5:cloud
  # Timeout in seconds
  timeout: 120

# GeoIP configuration (optional)
geoip:
  # Path to GeoLite2 database
  db_path: ~/.openclaw/workspace/skillcheck/data/GeoLite2-City.mmdb
  # Enable URL geolocation
  enabled: true

# Scanner settings
scanner:
  # Risk score thresholds
  safe_threshold: 10      # Below this = safe
  warning_threshold: 30   # 10-30 = warnings
  danger_threshold: 50    # Above this = danger
  
  # Output settings
  default_format: json    # json, console, markdown
  verbose: false

# CI/CD settings
ci:
  # Fail build on high risk?
  fail_on_high_risk: true
  # Include in report
  show_passed_checks: false
```

## Support

- GitHub Issues: https://github.com/Paul-J-Barrett/skillcheck/issues
- OpenClaw Community: https://discord.com/invite/clawd

## Security Best Practices

1. **Never trust a skill without checking** - Even from trusted sources
2. **Use in CI/CD** - Automate security checks
3. **Keep Ollama updated** - Regular model updates improve detection
4. **Review failures carefully** - Some detections are false positives
5. **Report new threats** - Help improve detection patterns

## License

MIT - See LICENSE file in repository

---

**Remember:** This tool provides security analysis but does not guarantee safety. Always review skills manually before use in production systems.
