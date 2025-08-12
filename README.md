# AI Vulnerability to Semgrep Rules

Automatically generate Semgrep/OpenGrep detection rules from real-world vulnerabilities using AI analysis.

## Overview

This project processes vulnerability databases to extract vulnerable and fixed code examples, then uses LLMs to generate static analysis rules for detecting similar security issues. Currently supports:

- **Go vulnerabilities** from [vuln.go.dev](https://vuln.go.dev)
- **npm vulnerabilities** from GitHub Security Advisory Database
- **Semgrep rule generation** with real-world vulnerability references

## Features

🔍 **Vulnerability Processing**
- Fetches vulnerability data from multiple sources
- Downloads patches and code diffs from GitHub
- Generates good/bad code examples using LLM analysis
- Enhanced JSON parsing with automatic retry mechanism

🛡️ **Semgrep Rule Generation** 
- Creates detection rules from vulnerability patterns
- References real CVE/vulnerability IDs in rule messages
- Supports multiple detection strategies per vulnerability
- Generates comprehensive rulesets

📊 **Progress Tracking**
- Real-time progress monitoring with success rates
- Resume capability for interrupted processing
- Detailed logging and debugging output

## Quick Start

### Prerequisites

```bash
# Install dependencies
pip install requests beautifulsoup4 packaging tenacity

# Install and start Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b  # or qwen2.5-coder:14b for better code analysis
ollama serve
```

### Go Vulnerabilities

```bash
# Process Go vulnerabilities
python vuln2examples.py --out ./go-vulns --debug --save-llm --workers 1 --model llama3.2:3b

# Monitor progress
tail -F go-vulns/progress.log

# Generate Semgrep rules
python vuln2semgrep.py --input ./go-vulns --output ./semgrep-rules --debug --only-with-examples
```

### npm Vulnerabilities

```bash
# Process npm vulnerabilities 
python vuln2examples-npm.py --out ./npm-vulns --debug --save-llm --workers 1 --model llama3.2:3b

# Monitor progress
tail -F npm-vulns/progress.log
```

## Architecture

### vuln2examples.py (Go)
- Fetches vulnerabilities from vuln.go.dev
- Processes GitHub commits/PRs for code diffs
- Uses LLM to extract vulnerable vs secure code patterns
- Enhanced with JSON preprocessing and retry logic

### vuln2examples-npm.py (npm)
- Fetches vulnerabilities from GitHub Security Advisory Database
- Processes npm package vulnerabilities
- Generates JavaScript/Node.js security examples

### vuln2semgrep.py (Rule Generation)
- Converts vulnerability examples to Semgrep rules
- Includes real vulnerability references in rule messages
- Creates comprehensive detection patterns

## Output Structure

```
out/
├── progress.log                    # Real-time processing status
├── GO-2025-3857/                  # Per-vulnerability directories
│   ├── debug.txt                  # Processing logs
│   ├── raw_diff.patch            # Original GitHub patch
│   ├── llm_raw.txt              # LLM response
│   ├── GO-2025-3857_bad.go      # Vulnerable code example
│   └── GO-2025-3857_good.go     # Secure code example
└── semgrep_rules/
    ├── GO-2025-3857.yml         # Generated Semgrep rules
    └── all_vulnerability_rules.yml # Combined ruleset
```

## Configuration

### Command Line Options

```bash
# Processing options
--out DIR              # Output directory
--model MODEL          # Ollama model (llama3.2:3b, qwen2.5-coder:14b)
--workers N            # Concurrent workers (default: 1)
--debug               # Verbose logging
--save-llm            # Save raw LLM responses
--limit N             # Limit vulnerabilities processed

# Go-specific options  
--http-diff-first     # Use HTTP for patches instead of git clone
--only GO-ID          # Process specific vulnerability
--skip GO-ID          # Skip specific vulnerabilities

# Resume functionality
# Script automatically resumes from last completed vulnerability
```

### Performance Tuning

- **Model selection**: `llama3.2:3b` (fast) vs `qwen2.5-coder:14b` (better code analysis)
- **Workers**: Use 1 worker to avoid Ollama API conflicts
- **HTTP-first**: Faster patch fetching without git clone

## Example Generated Rules

```yaml
rules:
  - id: policy-lowercase-bypass
    pattern: strutil.RemoveDuplicates($POLICIES, false)
    message: |
      Policy deduplication without lowercase normalization can lead to privilege escalation
      (similar to GO-2025-3857: OpenBao Root Namespace Operator May Elevate Token Privileges)
    severity: HIGH
    languages: [go]
```

## Statistics

Current processing capabilities:
- **2,100+ Go vulnerabilities** from vuln.go.dev
- **4,000+ npm vulnerabilities** from GitHub Advisory Database  
- **100% success rate** with enhanced JSON processing
- **~1-2 minutes per vulnerability** processing time

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)  
5. Open Pull Request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- [vuln.go.dev](https://vuln.go.dev) for Go vulnerability database
- [GitHub Security Advisory Database](https://github.com/advisories) for npm vulnerabilities
- [Ollama](https://ollama.ai) for local LLM inference
- [Semgrep](https://semgrep.dev) for static analysis framework