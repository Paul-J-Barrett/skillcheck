# Credits and Attributions

This file lists all third-party resources, libraries, and data used by Skill Security Scanner.

## Core Dependencies

### Python Standard Library
- **License:** PSF License Agreement (compatible with MIT)
- **Usage:** Core functionality including `ipaddress`, `pathlib`, `typing`, `concurrent.futures`
- **Copyright:** Python Software Foundation

### colorama
- **License:** BSD 3-Clause
- **Copyright:** Jonathan Hartley
- **Repository:** https://github.com/tartley/colorama
- **Usage:** Cross-platform colored terminal output

### ollama
- **License:** MIT
- **Repository:** https://github.com/ollama/ollama-python
- **Usage:** Python client for Ollama API

### requests
- **License:** Apache License 2.0
- **Copyright:** Kenneth Reitz
- **Repository:** https://github.com/psf/requests
- **Usage:** HTTP library for API calls

## Optional Dependencies

### geoip2
- **License:** Apache License 2.0
- **Copyright:** MaxMind, Inc.
- **Repository:** https://github.com/maxmind/GeoIP2-python
- **Usage:** IP geolocation database reader (optional)
- **Note:** Requires local GeoLite2 database file (see Data Attributions below)

### langdetect
- **License:** Apache License 2.0
- **Copyright:** Michal Danilak
- **Repository:** https://github.com/Mimino666/langdetect
- **Usage:** Language detection (optional)

### deep-translator
- **License:** MIT
- **Repository:** https://github.com/nidhaloff/deep-translator
- **Usage:** Translation services (optional)

## Data Attributions

### MaxMind GeoLite2
- **Product:** GeoLite2 Free Geolocation Database
- **Copyright:** MaxMind, Inc.
- **Website:** https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- **License:** MaxMind License (commercial redistribution restrictions apply)
- **Attribution Notice:**
  > This product includes GeoLite2 data created by MaxMind, available from
  > https://www.maxmind.com

**Important:** If you use the optional geolocation feature with MaxMind GeoLite2
database, you must comply with the MaxMind License terms. The database is **NOT**
included with this software and must be obtained separately from MaxMind.

## Research Attributions

### Cisco AI Defense
- **Research:** "AI agent skills are a security nightmare" (February 2026)
- **Website:** https://blogs.cisco.com/security/ai-defense
- **Tool Reference:** Cisco AI Skill Scanner
  - Repository: https://github.com/cisco-ai-defense/skill-scanner
- **Usage:** Security research findings and threat taxonomy (AI001-AI007)

**Note:** The threat taxonomy (AI001-AI007) and security patterns are derived from
Cisco's published research and open-source scanner. This implementation is
independent and does not include any code from Cisco's proprietary scanner.

## Testing Resources

### Test Fixtures
Sample skill files in `tests/fixtures/` are created specifically for testing
this software and are released under the same MIT license as the main project.

## License Summary

| Component | License | Notes |
|-----------|---------|-------|
| Skill Security Scanner | MIT | This project |
| Python Standard Library | PSF | Compatible with MIT |
| colorama | BSD-3 | Terminal colors |
| ollama | MIT | LLM client |
| requests | Apache-2.0 | HTTP requests |
| geoip2 (optional) | Apache-2.0 | Requires GeoLite2 data |
| GeoLite2 data | MaxMind | Must be obtained separately |
| langdetect (optional) | Apache-2.0 | Language detection |
| deep-translator (optional) | MIT | Translation |

## Third-Party Trademarks

- **Claude** is a trademark of Anthropic, PBC
- **GitHub** is a trademark of GitHub, Inc.
- **Ollama** is a trademark of Ollama, Inc.
- **OpenAI** is a trademark of OpenAI, Inc.
- **MaxMind** and **GeoLite2** are trademarks of MaxMind, Inc.
- **Cisco** is a trademark of Cisco Systems, Inc.

All trademarks are property of their respective owners. Use of these names
in this project does not imply endorsement.

## Contributing

When contributing to this project, ensure you:

1. Only submit code you have the right to license under MIT
2. Do not include proprietary or confidential materials
3. Document any new third-party dependencies in this file
4. Include appropriate license headers in new source files

## Questions

For questions about licensing or attribution, please open an issue in the
project repository.
