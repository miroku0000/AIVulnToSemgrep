# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python security research tool that processes Go vulnerability data to generate minimal code examples demonstrating security issues. The tool fetches vulnerability information from multiple sources, analyzes fix commits, and uses LLM generation to create educational code examples.

## Core Commands

### Running the Tool
```bash
# Basic usage - generate examples for all vulnerabilities
python vuln2examples.py --out ./out --debug --save-llm

# Process specific vulnerability
python vuln2examples.py --out ./out --only GO-2025-3857 --debug --save-llm --workers 1

# Use HTTP diff first (avoids git clone issues)
python vuln2examples.py --out ./out --only GO-2025-3857 --debug --save-llm --workers 1 --http-diff-first

# Flat output structure
python vuln2examples.py --out ./out --flat-output --debug
```

### Dependencies
The tool requires these Python packages:
- requests
- beautifulsoup4
- packaging
- tenacity
- (Standard library: argparse, concurrent.futures, dataclasses, json, os, re, subprocess, sys, pathlib, typing)

### External Dependencies
- Git (for repository cloning)
- Ollama server (default: http://127.0.0.1:11434) with a model like llama3.1

## Architecture

### Core Data Flow
1. **Discovery**: Fetch vulnerability IDs from Nutanix vuln list or Go vulnerability database
2. **Data Gathering**: For each vulnerability:
   - Fetch HTML reports and JSON metadata
   - Extract affected modules and fix references
   - Parse commit/PR URLs
3. **Diff Generation**: Obtain code diffs via:
   - HTTP patch downloads from GitHub (.patch endpoints)
   - Git operations (clone, show, diff between tags)
4. **LLM Processing**: Generate educational examples using Ollama
5. **Output**: Save structured reports with code examples

### Key Components

#### Data Sources (`vuln2examples.py:41-47`)
- **NUTANIX_VULN_LIST**: Primary source for vulnerability discovery
- **GO_INDEX_VULNS**: Fallback vulnerability index
- **GO_VULN_JSON_FMT**: Individual vulnerability metadata
- **PKG_VULN_FMT**: Package-specific vulnerability pages

#### HTTP and Git Operations (`vuln2examples.py:295-467`)
- **ensure_repo_cached()**: Manages local git repository cache
- **fetch_commit_patch()/fetch_pr_patch()**: HTTP-based diff retrieval
- **diff_for_fix()**: Central diff generation with multiple fallback strategies

#### LLM Integration (`vuln2examples.py:473-528`)
- **ollama_generate()**: Interfaces with Ollama API
- **build_llm_prompt()**: Constructs vulnerability analysis prompts
- Uses strict JSON schema for code example extraction

#### Main Processing (`vuln2examples.py:544-774`)
- **process_vuln()**: Core per-vulnerability processing pipeline
- Handles parallel execution via ThreadPoolExecutor
- Comprehensive error handling and logging

### Output Structure
```
out/
├── GO-YYYY-NNNN/          # Per-vulnerability directories
│   ├── metadata.json      # Vulnerability data and module info
│   ├── report.json        # Final analysis results
│   ├── debug.txt          # Processing logs
│   ├── raw_diff.patch     # Source code diff
│   ├── llm_raw.txt        # Raw LLM response (if --save-llm)
│   ├── GO-YYYY-NNNN_bad.go   # Vulnerable code example
│   └── GO-YYYY-NNNN_good.go  # Fixed code example
```

### Configuration Options
- **--http-diff-first**: Prioritizes HTTP patch download over git operations
- **--repo-cache**: Directory for cached git repositories (default: ./_repo_cache)
- **--workers**: Parallel processing threads (default: 3)
- **--model**: Ollama model name (default: llama3.1)
- **--seed**: LLM seed for reproducible outputs

### Error Handling Patterns
The tool implements extensive fallback mechanisms:
1. Multiple vulnerability data sources
2. HTTP patch download → git operations → HTTP fallback
3. Regex-based LLM response parsing for malformed JSON
4. Per-vulnerability error isolation in parallel processing

### Environment Variables
- **GITHUB_TOKEN**: Optional GitHub API authentication for higher rate limits
- **OLLAMA_URL**: Override default Ollama server URL

## Semgrep Rule Generation (vuln2semgrep.py)

### Purpose
Extends vulnerability analysis by generating semgrep/opengrep rules to detect similar vulnerability patterns in source code.

### Usage
```bash
# Generate rules for vulnerabilities with code examples
python vuln2semgrep.py --input ./out --output ./semgrep_rules --only-with-examples --create-master --debug

# Process all vulnerabilities (including those without examples)
python vuln2semgrep.py --input ./out --output ./semgrep_rules --debug

# Use different model
python vuln2semgrep.py --input ./out --output ./semgrep_rules --model llama3.2:3b --debug
```

### Key Features
1. **Multi-Strategy Rule Generation**: Creates 3-5 different semgrep rules per vulnerability:
   - Direct pattern matching for vulnerable code
   - Missing parameter detection
   - Inconsistent usage patterns
   - Defensive pattern violations
   - Generalized patterns for similar vulnerabilities

2. **Comprehensive Prompting**: Uses detailed prompts that help the LLM understand:
   - The core security issue
   - Coding patterns that lead to the vulnerability
   - Key indicators in source code
   - Function call patterns and parameter requirements

3. **Output Organization**:
   ```
   semgrep_rules/
   ├── GO-2025-3859.yml              # Individual rule file
   ├── GO-2025-3859_metadata.json   # Rule metadata
   ├── GO-2025-3859_raw.txt         # Raw LLM response (debug)
   ├── all_vulnerability_rules.yml  # Master ruleset
   └── ...
   ```

4. **Quality Controls**:
   - YAML validation and error handling
   - Extracts YAML from markdown if needed
   - Includes severity levels and clear messages
   - Focuses on false positive reduction

### Rule Generation Process
1. **Input Analysis**: Reads vulnerability metadata, reports, diffs, and code examples
2. **Context Building**: Creates comprehensive prompts with security analysis
3. **LLM Generation**: Uses Ollama to generate multiple detection strategies
4. **Rule Processing**: Validates and formats semgrep rules
5. **Output Creation**: Saves individual rules and creates master ruleset

### Integration with Main Tool
```bash
# Complete workflow: vulnerability analysis + rule generation
python vuln2examples.py --out ./out --debug --save-llm --workers 1 --http-diff-first --model qwen2.5-coder:14b
python vuln2semgrep.py --input ./out --output ./semgrep_rules --only-with-examples --create-master --debug
```

## Development Notes

- All file operations use UTF-8 encoding
- HTTP requests include retry logic with exponential backoff
- Git operations have comprehensive error handling
- The tool is designed to handle partial failures gracefully
- Debug output is saved per-vulnerability for troubleshooting
- Semgrep rule generation uses extended context windows (16k tokens) for comprehensive analysis
- YAML parsing includes fallback mechanisms for various LLM response formats