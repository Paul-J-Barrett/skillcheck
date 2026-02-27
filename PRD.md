# Product Requirements Document: Skill Security Scanner

## Overview
A Python CLI tool that analyzes skill.md files for security vulnerabilities using a local Ollama LLM (kimi-k2.5:cloud).

## Goals
- Detect prompt injection attacks and malicious patterns in skill files
- Provide actionable security analysis before skill installation
- Support both human-readable and JSON output formats
- Enable CI/CD integration through exit codes
- Detect multilingual/hidden content in non-English languages
- Geolocate IP addresses to identify high-risk countries

## Security Check Categories

### 1. Multilingual Content Detection **(NEW - First Check)**
- Detect if content is not in English
- Identify the detected language
- Translate content to English for re-analysis
- Re-run all security checks on translated content
- Flag original file for review if translation reveals hidden intent

### 2. Hidden Instructions
- Base64 encoding
- Unicode tricks (homoglyphs, RTL override)
- Invisible characters (zero-width spaces)
- Steganography in markdown
- Multi-lingual prompts (Hidden intent in non-native languages)

### 3. Jailbreaking Attempts
- System prompt overrides
- Role-playing attacks ("DAN", "Developer Mode")
- Instruction hierarchy violations
- Ignore previous instructions patterns

### 4. Credential/Key Exposure
- API keys (sk-*, ak_*, etc.)
- Database connection strings
- Passwords in plaintext
- Private tokens

### 5. PII Leakage
- Email addresses
- Phone numbers
- SSN/credit card patterns
- Physical addresses
- Personal names in context

### 6. Token Exfiltration
- Patterns sending tokens to external endpoints
- Encoded token transmission
- Log-based exfiltration

### 7. External Data Fetching
- URLs referenced in fetch/read operations
- Instructions to load external content
- Import/include from remote sources

### 8. Data Exfiltration
- Exfiltrating conversation data
- Exporting user context
- Unauthorized data transmission patterns

### 9. Code Execution
- Shell commands (bash, sh, cmd)
- eval() and exec() patterns
- subprocess calls
- System command execution

### 10. File System Access
- Read/write file operations
- Path traversal attempts (../, ..\\)
- Sensitive file access (/etc/passwd, .env)

### 11. Network Operations
- HTTP/HTTPS requests
- Webhook calls
- Socket connections
- DNS manipulation

### 12. Sandbox Escape
- Container escape attempts
- VM breakout patterns
- Privilege escalation

### 13. Indirect Prompt Injection
- Loading instructions from external URLs
- Dynamic content that may be compromised
- Third-party dependencies

### 14. Social Engineering
- Deceptive instructions
- Trust exploitation
- Authority impersonation

## URL Classification

### Risk Levels

#### Trusted (Low Risk)
- docs.claude.ai
- anthropic.com
- opencode.ai
- platform.openai.com

#### Medium Risk (Review Required)
Established companies with controlled content:
- google.com
- microsoft.com
- amazon.com
- apple.com

#### Suspicious (High Risk)
Open contribution platforms:
- github.com
- gist.github.com
- pastebin.com
- codepen.io
- jsfiddle.net

#### Malicious (Critical)
- URL shorteners (bit.ly, tinyurl, etc.)
- IP addresses with high-risk geolocation
- Known malicious domains
- Suspicious TLDs (.tk, .ml, etc.)

#### Unknown (Flag for Review)
- Any domain not in known lists
- Newly registered domains
- Parked domains

### Geolocation-Based Risk Classification **(NEW)**

When URLs contain IP addresses, perform geolocation lookup to identify high-risk countries:

#### Critical Risk Countries (Immediate Flag)
- China (CN)
- North Korea (KP)
- Iran (IR)
- Russia (RU)
- Belarus (BY)
- Myanmar (MM)
- Syria (SY)
- Cuba (CU)
- Venezuela (VE) - politically high risk
- Afghanistan (AF)

#### Implementation Notes:
- Use free IP geolocation API (e.g., ip-api.com, ipapi.co)
- Cache results to avoid repeated lookups
- Fall back to "unknown" if geolocation fails
- Add classification reason: "IP address located in high-risk country: [Country Name]"

## Parallel Analysis Architecture **(NEW)**

### Problem
Sending all 13 security checks in one prompt may exceed token limits or overwhelm the LLM.

### Solution
Break down analysis into parallel batches using threading:

#### Batch Configuration:
```python
BATCH_SIZE = 2  # Number of categories per API call
BATCHES = [
    # Batch 1: Content Analysis
    ["multilingual_detection", "hidden_instructions"],
    # Batch 2: Attack Patterns
    ["jailbreaking_attempts", "social_engineering"],
    # Batch 3: Credential/PII
    ["credential_exposure", "pii_leakage"],
    # Batch 4: Data Security
    ["token_exfiltration", "data_exfiltration"],
    # Batch 5: External Access
    ["external_data_fetching", "indirect_prompt_injection"],
    # Batch 6: System Access
    ["code_execution", "file_system_access"],
    # Batch 7: Network/Sandbox
    ["network_operations", "sandbox_escape"],
]
```

#### Workflow:
1. **Phase 1: Multilingual Detection (Sequential)**
   - Must complete first
   - If non-English detected:
     - Translate to English
     - Store translation
     - Re-run analysis on translated content

2. **Phase 2: Parallel Security Analysis (Threading)**
   - Spawn 2 threads per batch
   - Each thread calls Ollama with specific categories
   - Collect results as they complete
   - Aggregate into final report

3. **Phase 3: URL Analysis (Sequential)**
   - Extract all URLs from skill file
   - Classify each URL
   - Geolocate IP addresses
   - Apply risk ratings

#### Thread Safety:
- Each thread gets its own Ollama connection
- Use ThreadPoolExecutor for managing threads
- Implement timeout per batch
- Aggregate results in thread-safe manner

#### Multilingual Check Priority:
```
1. Run multilingual_detection check first
2. If non-English:
   a. Detect language
   b. Translate to English
   c. Replace skill_content with translation
   d. Re-run multilingual check (should now pass)
   e. Continue with remaining checks on translated content
3. Log translation in output
4. Flag original file for review
```

## Configuration

### Environment Variables

#### Ollama Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `OLLAMA_API_BASE` | Full base URL for Ollama API | `http://127.0.0.1:11434` |
| `OLLAMA_HOST` | Hostname only (used if API_BASE not set) | `127.0.0.1` |
| `OLLAMA_MODEL` | Model name to use | `kimi-k2.5:cloud` |

#### OpenAI Configuration

| Variable | Description | Required For |
|----------|-------------|--------------|
| `OPENAI_API_KEY` | OpenAI API key | `--openai` flag |
| `OPENAI_MODEL` | Model name (default: gpt-4o-mini) | `--openai` flag |
| `OPENAI_BASE_URL` | API base URL (optional) | `--openai` flag |

#### Geolocation Configuration **(NEW)**

| Variable | Description | Default |
|----------|-------------|---------|
| `IPGEO_API_KEY` | API key for IP geolocation service | Optional (free tier) |
| `IPGEO_PROVIDER` | Provider: "ipapi", "ipapi-co", "maxmind" | `ipapi` (free) |

The tool checks environment variables in this priority order:
1. `OLLAMA_API_BASE` (full URL: `http://127.0.0.1:11434`)
2. `OLLAMA_HOST` (hostname only: `127.0.0.1`)
3. Default: `http://127.0.0.1:11434`

When using `--openai` flag:
- Requires `OPENAI_API_KEY` to be set
- Uses `OPENAI_MODEL` if set, otherwise defaults to `gpt-4o-mini`
- Supports custom base URL via `OPENAI_BASE_URL` for OpenAI-compatible APIs

## CLI Interface

### Arguments
```
python main.py <skill_file_path> [options]
```

### Options
- `--format`: Output format (`console` or `json`, default: `console`)
- `--host`: Ollama host URL (overrides env vars)
- `--model`: Model name (overrides env vars)
- `--openai`: Use OpenAI API instead of Ollama (requires `OPENAI_API_KEY` env var)
- `--threads`: Number of parallel threads (default: 2) **(NEW)**
- `--no-translate`: Skip translation of non-English content **(NEW)**

### Examples
```bash
# Using environment variables
export OLLAMA_API_BASE=http://127.0.0.1:11434
export OLLAMA_MODEL=kimi-k2.5:cloud
python main.py tests/unsafe_skill.md

# Override with command line
python main.py tests/safe_skill.md --format=json --host http://192.168.1.100:11434

# JSON output
python main.py tests/safe_skill.md --format=json

# Custom model
python main.py skill.md --model llama3.2

# Use OpenAI instead of Ollama
export OPENAI_API_KEY=sk-your-key-here
python main.py tests/safe_skill.md --openai

# Use OpenAI with custom model
export OPENAI_API_KEY=sk-your-key-here
export OPENAI_MODEL=gpt-4
python main.py tests/safe_skill.md --openai

# Parallel analysis with 4 threads **(NEW)**
python main.py skill.md --threads=4

# Skip translation **(NEW)**
python main.py skill.md --no-translate
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no critical issues found |
| 1 | Critical security issues detected |
| 2 | File not found or read error |
| 3 | Ollama connection failed |
| 4 | Invalid arguments |

## Output Format

### Console Output
```
🔍 Security Analysis: unsafe_skill.md
═══════════════════════════════════════════════════

🌍 Language Detection:
   ⚠️  Original language: Russian (ru)
   ✅ Translated to English for analysis

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
   ❌ https://192.168.1.1/api  (IP address - located in Russia)

📊 Summary: 3 CRITICAL, 3 MEDIUM, 7 PASSED
```

### JSON Output Structure
```json
{
  "file": "unsafe_skill.md",
  "timestamp": "2025-01-15T10:30:00Z",
  "language": {
    "detected": "ru",
    "translated": true,
    "original_language": "Russian"
  },
  "checks": [
    {
      "category": "multilingual_detection",
      "passed": false,
      "severity": "medium",
      "description": "Content detected in Russian language",
      "evidence": ["Line 1-35: Cyrillic text detected"],
      "original_language": "ru",
      "translated": true
    },
    {
      "category": "hidden_instructions",
      "passed": false,
      "severity": "critical",
      "description": "Base64 encoded payload detected",
      "evidence": ["Line 45: `...base64...`"]
    }
  ],
  "urls": {
    "all": ["https://docs.example.com", "https://bit.ly/3xMal", "https://192.168.1.1/api"],
    "trusted": [],
    "medium": ["https://docs.example.com"],
    "suspicious": [],
    "malicious": ["https://bit.ly/3xMal", "https://192.168.1.1/api"],
    "unknown": [],
    "geolocation": {
      "192.168.1.1": {
        "country": "Russia",
        "country_code": "RU",
        "risk_level": "critical"
      }
    }
  },
  "summary": {
    "total_checks": 14,
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

## Architecture

### File Structure
```
skillcheck/
├── main.py                    # CLI entry, arg parsing, exit codes, orchestration
├── analyzer.py                # Ollama LLM integration with threading
├── prompt_builder.py          # Security analysis prompts (batch-based)
├── result_parser.py           # Parse LLM JSON responses
├── formatter.py               # Console & JSON output formatting
├── url_classifier.py          # URL categorization with geolocation
├── ip_geolocation.py          # IP geolocation lookup **(NEW)**
├── language_detector.py       # Language detection & translation **(NEW)**
├── pyproject.toml             # Project dependencies
└── tests/
    ├── safe_skill.md          # Clean test file
    ├── unsafe_skill.md        # Multiple vulnerabilities
    └── multilingual_skill.md  # Non-English content **(NEW)**
```

### Module Responsibilities

#### main.py
- Parse command-line arguments
- Read environment variables
- Read skill file content
- Orchestrate analysis workflow with threading
- Handle exit codes
- Manage output formatting
- **NEW**: Coordinate parallel analysis batches
- **NEW**: Handle translation workflow

#### analyzer.py
- Connect to Ollama instance
- Send analysis prompts to LLM in parallel batches
- Handle connection errors
- Retry on failure
- **NEW**: Support concurrent API calls via threading
- **NEW**: Batch result aggregation

#### prompt_builder.py
- Define security analysis prompts for each batch
- Include category descriptions
- Specify JSON output format
- **NEW**: Multilingual detection prompt
- **NEW**: Translation prompt
- **NEW**: Batch-specific prompts

#### result_parser.py
- Parse LLM JSON responses
- Validate structure
- Extract check results
- Handle parsing errors
- **NEW**: Aggregate results from multiple threads

#### formatter.py
- Format results for console output
- Format results as JSON
- Apply color coding
- Generate summary statistics
- **NEW**: Display language detection results
- **NEW**: Display geolocation information

#### url_classifier.py
- Categorize URLs by risk level
- Maintain domain lists
- Support override flags
- Provide classification reasoning
- **NEW**: Geolocation-based risk assessment
- **NEW**: IP address geolocation lookup

#### ip_geolocation.py **(NEW)**
- Lookup IP address geolocation
- Cache results to avoid repeated lookups
- Identify high-risk countries
- Provide classification reasoning
- Support multiple providers (ip-api.com, ipapi.co)

#### language_detector.py **(NEW)**
- Detect language of skill file content
- Translate non-English content to English
- Cache translations
- Support multiple languages
- Integration with analyzer for re-testing

## Module Interface Specifications

### Module: language_detector.py **(NEW)**

**Purpose**: Detect language and translate non-English content

**Input**:
```python
{
  "content": str,           # Raw content of skill file
  "target_language": str    # Target language for translation (default: "en")
}
```

**Output**:
```python
{
  "detected_language": str,     # ISO 639-1 code (e.g., "en", "ru", "zh")
  "language_name": str,         # Human-readable name (e.g., "Russian")
  "is_english": bool,           # True if content is already English
  "translated_content": str,    # Translated content if not English
  "translation_confidence": float,  # 0.0-1.0 confidence score
  "success": bool,
  "error": str | None
}
```

**High-Risk Languages**:
- Content in languages from high-risk countries should be flagged
- Translation may be less reliable for these languages

---

### Module: ip_geolocation.py **(NEW)**

**Purpose**: Lookup IP address geolocation

**Input**:
```python
{
  "ip_address": str,        # IP address to lookup
  "cache": dict | None      # Optional cache dict for results
}
```

**Output**:
```python
{
  "ip": str,
  "country": str,             # Full country name
  "country_code": str,        # ISO 3166-1 alpha-2 (e.g., "RU", "CN")
  "city": str,
  "region": str,
  "risk_level": str,          # "trusted", "medium", "suspicious", "malicious"
  "reason": str,              # Explanation of risk level
  "success": bool,
  "error": str | None
}
```

**High-Risk Countries**:
- China (CN) → malicious
- North Korea (KP) → malicious
- Iran (IR) → malicious
- Russia (RU) → malicious
- Belarus (BY) → malicious
- Myanmar (MM) → malicious
- Syria (SY) → malicious
- Cuba (CU) → malicious
- Venezuela (VE) → suspicious (politically high risk)
- Afghanistan (AF) → suspicious

---

### Module: url_classifier.py

**Purpose**: Classify URLs by risk level

**Input**:
```python
{
  "urls": list[str],            # List of URLs to classify
  "overrides": dict | None      # Optional: {"domain.com": "trusted"}
}
```

**Output**:
```python
{
  "classified_urls": {
    "trusted": list[str],
    "medium": list[str],
    "suspicious": list[str],
    "malicious": list[str],
    "unknown": list[str]
  },
  "classifications": [
    {
      "url": str,
      "category": str,           # "trusted", "medium", "suspicious", "malicious", "unknown"
      "reason": str,             # Explanation of classification
      "geolocation": dict | None   # **NEW**: Geolocation data for IP addresses
    }
  ],
  "geolocation_summary": {       # **NEW**: Summary of high-risk IPs
    "high_risk_count": int,
    "high_risk_countries": list[str]
  }
}
```

**Classification Rules**:
- **Trusted**: docs.claude.ai, anthropic.com, opencode.ai, platform.openai.com
- **Medium**: Established companies (google.com, microsoft.com, amazon.com, etc.)
- **Suspicious**: Open contribution platforms (github.com, pastebin.com)
- **Malicious**: URL shorteners, IP addresses from high-risk countries, suspicious TLDs (.tk, .ml)
- **Unknown**: All other domains

---

### Module: prompt_builder.py

**Purpose**: Build LLM prompts for security analysis

**Input**:
```python
{
  "skill_content": str,        # Raw content of skill file
  "skill_filename": str,      # Name of skill file
  "categories": list[str],    # **NEW**: Categories to check in this batch
  "is_translation": bool      # **NEW**: True if analyzing translated content
}
```

**Output**:
```python
str  # Formatted prompt string for LLM
```

**Error Handling**: None (pure function)

---

### Module: analyzer.py

**Purpose**: Connect to LLM providers (Ollama/OpenAI) and send analysis requests

**Input**:
```python
{
  "skill_content": str,       # Skill file content
  "skill_filename": str,      # Filename
  "provider": str,            # "ollama" or "openai"
  "model": str,               # Model name
  "host": str | None,         # Ollama host URL
  "api_key": str | None,      # OpenAI API key
  "base_url": str | None,     # Custom base URL
  "threads": int,             # **NEW**: Number of parallel threads
  "batch_size": int           # **NEW**: Categories per batch
}
```

**Output**:
```python
{
  "success": bool,
  "response": str | None,      # Raw LLM response text
  "error": str | None,         # Error message if failed
  "batches_completed": int,    # **NEW**: Number of batches completed
  "translation_performed": bool  # **NEW**: True if translation was done
}
```

**Error Handling**:
- Connection errors → Return error with retry suggestion
- Timeout errors → Return error with timeout message
- Authentication errors → Return error for OpenAI key issues
- Invalid responses → Return error for parsing failures
- **NEW**: Thread errors → Aggregate and report

---

### Module: result_parser.py

**Purpose**: Parse and validate LLM JSON responses

**Input**:
```python
{
  "raw_response": str,        # Raw text from LLM
  "skill_filename": str,       # For error context
  "batch_categories": list[str]  # **NEW**: Expected categories in this batch
}
```

**Output**:
```python
{
  "success": bool,
  "data": {
    "checks": [...],          # Only checks from this batch
    "urls": {...},
    "summary": {...}
  } | None,
  "error": str | None
}
```

**Validation Rules**:
- Must have exactly the number of checks specified for this batch
- Each check must have required keys
- Severity must be in valid set
- **NEW**: Validate only expected categories are present

---

### Module: formatter.py

**Purpose**: Format results for console or JSON output

**Input**:
```python
{
  "parsed_result": dict,        # From result_parser
  "skill_filename": str,
  "format": str,                # "console" or "json"
  "language_info": dict | None  # **NEW**: Language detection results
}
```

**Output (console format)**:
```python
str  # Formatted console output with colors and emojis
```

**Output (json format)**:
```python
{
  "file": str,
  "timestamp": str,             # ISO 8601 format
  "language": dict,               # **NEW**: Language detection info
  "checks": list[dict],
  "urls": dict,
  "summary": dict,
  "exit_code": int
}
```

**Exit Code Calculation**:
- `0`: No critical issues
- `1`: One or more critical issues (includes high-risk IP geolocation)

---

### Module: main.py

**Purpose**: CLI entry point and orchestration

**Input (CLI arguments)**:
```
python main.py <skill_file> [options]

Positional:
  skill_file          Path to skill.md file

Options:
  --format            Output format: "console" or "json" (default: "console")
  --host              Ollama host URL (overrides OLLAMA_API_BASE env var)
  --model             Model name (overrides OLLAMA_MODEL env var)
  --openai            Use OpenAI instead of Ollama
  --threads           Number of parallel threads (default: 2)
  --no-translate      Skip translation of non-English content
```

**Environment Variables**:
```python
{
  "OLLAMA_API_BASE": str | None,
  "OLLAMA_HOST": str | None,
  "OLLAMA_MODEL": str | None,
  "OPENAI_API_KEY": str | None,
  "OPENAI_MODEL": str | None,
  "OPENAI_BASE_URL": str | None,
  "IPGEO_API_KEY": str | None,      # **NEW**
  "IPGEO_PROVIDER": str | None      # **NEW**
}
```

**Output**:
- Console: Print formatted output to stdout
- JSON: Print JSON to stdout
- Exit code: 0 (success) or 1 (critical issues)

**Workflow**:
```
1. Parse CLI args
2. Read env vars
3. Read skill file content
4. **NEW**: Run language_detector.detect_language()
5. **NEW**: If non-English and not --no-translate:
   a. Translate content
   b. Update skill_content with translation
   c. Mark translation_performed = True
6. **NEW**: Initialize thread pool with --threads
7. **NEW**: Split categories into batches of 2
8. **NEW**: For each batch:
   a. Spawn threads to call analyzer.analyze_batch()
   b. Collect results
   c. Parse with result_parser
9. **NEW**: Aggregate results from all batches
10. Extract URLs and classify with url_classifier
11. **NEW**: Geolocate IP addresses with ip_geolocation
12. Format output with formatter
13. Print output
14. Exit with appropriate code
```

**Error Handling**:
- File not found → Exit code 2
- Connection failed → Exit code 3
- Invalid arguments → Exit code 4
- Parse error → Exit code 1
- **NEW**: Translation failure → Continue with original language, flag warning

## Dependencies

```toml
[project]
name = "skillcheck"
version = "0.1.0"
description = "Security scanner for AI skill files"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "ollama>=0.6.1",
    "colorama>=0.4.6",
    "requests>=2.32.5",
    "langdetect>=1.0.9",           # **NEW**: Language detection
    "deep-translator>=1.11.4",       # **NEW**: Translation
]
```

## Implementation Phases

### Phase 1: Core Infrastructure
1. prompt_builder.py - Define LLM security analysis prompts
2. analyzer.py - Ollama connection with threading support
3. result_parser.py - Parse LLM JSON responses
4. formatter.py - Output formatting

### Phase 2: Security Analysis Features
5. url_classifier.py - URL categorization logic
6. **NEW**: ip_geolocation.py - IP geolocation lookup
7. **NEW**: language_detector.py - Language detection & translation

### Phase 3: Parallel Analysis **(NEW)**
8. Implement threading for parallel batch analysis
9. Add batch aggregation logic
10. Implement translation workflow

### Phase 4: CLI Interface
11. main.py - CLI interface and orchestration
12. Add --threads and --no-translate options
13. Update exit codes for new risk levels

### Phase 5: Testing
14. Create multilingual_skill.md test file
15. Test parallel analysis with mock responses
16. Test IP geolocation with mock data
17. Test translation workflow
18. Test all exit codes and output formats

## Test Files

### safe_skill.md
Clean skill file demonstrating best practices:
- No hidden instructions
- No credential exposure
- No external data fetching
- Proper documentation
- English language only

### unsafe_skill.md
Contains multiple vulnerability types:
- Base64 encoded commands
- API key in plaintext
- URL shortener links
- Shell command execution
- External data fetching instructions

### multilingual_skill.md **(NEW)**
Contains non-English content for testing:
- Russian text with hidden instructions
- Chinese text with credential exposure
- Mixed language content

## Future Enhancements

1. **Configuration file** for custom URL lists and rules
2. **Ignore patterns** for false positives
3. **Baseline mode** to track changes over time
4. **Integration** with CI/CD pipelines
5. **Severity override** configuration
6. **Additional LLM providers** support
7. **Custom batch sizes** for different workloads
8. **Caching** for geolocation and translation results
9. **Offline mode** without external API calls
10. **Custom high-risk country lists**
