#!/usr/bin/env python3
"""
vuln2semgrep.py - Generate semgrep rules from vulnerability analysis

This script processes the output from vuln2examples.py and generates
semgrep/opengrep rules to detect similar vulnerability patterns in source code.

Usage:
    python vuln2semgrep.py --input ./out --output ./semgrep_rules --debug
"""

import argparse
import json
import os
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests


# Ollama integration (reused from vuln2examples.py)
def ollama_generate(prompt: str, model: str, url: str, seed: Optional[int], max_tokens: int = 4096) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_ctx": 16384},
    }
    if seed is not None:
        payload["options"]["seed"] = int(seed)
    r = requests.post(f"{url.rstrip('/')}/api/generate", json=payload, timeout=300)
    r.raise_for_status()
    return r.json().get("response", "")


def read_vulnerability_data(vuln_dir: Path) -> Optional[Dict[str, Any]]:
    """Read vulnerability data from a processed vulnerability directory."""
    try:
        # Try to read from debug.txt to get summary info
        debug_file = vuln_dir / "debug.txt"
        summary = ""
        cve = ""
        
        if debug_file.exists():
            with open(debug_file, 'r', encoding='utf-8') as f:
                debug_content = f.read()
                # Extract summary and CVE from debug content
                import re
                summary_match = re.search(r'- Summary: (.+)', debug_content)
                if summary_match:
                    summary = summary_match.group(1).strip()
                cve_match = re.search(r'- CVE: (.+)', debug_content)
                if cve_match:
                    cve = cve_match.group(1).strip()
        
        # Try metadata/report files (may not exist in current format)
        metadata = {}
        report = {"summary": summary, "cve": cve}
        
        metadata_file = vuln_dir / "metadata.json"
        report_file = vuln_dir / "report.json"
        
        if metadata_file.exists():
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
                
        if report_file.exists():
            with open(report_file, 'r', encoding='utf-8') as f:
                report.update(json.load(f))
            
        # Read diff if available
        diff_file = vuln_dir / "raw_diff.patch"
        diff_content = ""
        if diff_file.exists() and diff_file.stat().st_size > 0:
            with open(diff_file, 'r', encoding='utf-8') as f:
                diff_content = f.read()
                
        # Read code examples if available
        bad_code = ""
        good_code = ""
        bad_file = vuln_dir / f"{vuln_dir.name}_bad.go"
        good_file = vuln_dir / f"{vuln_dir.name}_good.go"
        
        if bad_file.exists():
            with open(bad_file, 'r', encoding='utf-8') as f:
                bad_code = f.read()
                
        if good_file.exists():
            with open(good_file, 'r', encoding='utf-8') as f:
                good_code = f.read()
                
        return {
            "go_id": metadata.get("go_id", vuln_dir.name),  # Use directory name as fallback
            "metadata": metadata,
            "report": report,
            "diff": diff_content,
            "bad_code": bad_code,
            "good_code": good_code,
            "vuln_dir": vuln_dir
        }
    except Exception as e:
        print(f"Error reading vulnerability data from {vuln_dir}: {e}")
        return None


def build_semgrep_generation_prompt(vuln_data: Dict[str, Any]) -> str:
    """Build a comprehensive prompt for generating semgrep rules."""
    
    go_id = vuln_data["go_id"]
    summary = vuln_data["report"].get("summary", "")
    cve = vuln_data["report"].get("cve", "")
    diff = vuln_data["diff"][:10000] if vuln_data["diff"] else ""  # Limit diff size
    bad_code = vuln_data["bad_code"]
    good_code = vuln_data["good_code"]
    
    # Extract rationale if available
    rationale = ""
    if vuln_data["report"].get("results"):
        rationale = vuln_data["report"]["results"][0].get("rationale", "")
    
    prompt = f"""You are a security expert specializing in static analysis and semgrep rule creation. 

VULNERABILITY ANALYSIS:
- Vulnerability ID: {go_id}
- CVE: {cve}
- Summary: {summary}
- Analysis: {rationale}

VULNERABLE CODE EXAMPLE:
```go
{bad_code}
```

FIXED CODE EXAMPLE:
```go
{good_code}
```

CODE DIFF (showing the actual fix):
```diff
{diff}
```

YOUR TASK:
Generate comprehensive semgrep rules to detect this vulnerability pattern in Go source code. Follow these steps:

1. UNDERSTAND THE VULNERABILITY:
   - What is the core security issue?
   - What coding patterns lead to this vulnerability?
   - What are the key indicators in the code?

2. IDENTIFY DETECTION PATTERNS:
   - What function calls are involved?
   - What parameter patterns indicate the vulnerability?
   - What missing parameters or inconsistent usage should be flagged?

3. CREATE SEMGREP RULES:
   Generate 3-5 semgrep rules with different detection strategies:
   
   Rule 1: Direct pattern matching for the vulnerable code pattern
   Rule 2: Missing parameter detection (if applicable)
   Rule 3: Inconsistent usage patterns
   Rule 4: Defensive pattern violations
   Rule 5: Broader pattern for similar vulnerabilities

4. RULE REQUIREMENTS:
   - Use proper YAML format
   - Include clear rule IDs and messages that reference the real vulnerability ({go_id}, {cve})
   - Set appropriate severity levels
   - Messages should mention this specific vulnerability as an example (e.g., "Similar to {go_id}: {summary}")
   - Add explanatory comments
   - Include both specific and generalized patterns
   - Consider false positive reduction

5. RESPONSE FORMAT:
   Provide your analysis followed by the semgrep rules in YAML format.

EXAMPLE MESSAGE FORMAT:
   message: "Policy deduplication without lowercase normalization can lead to privilege escalation (similar to {go_id}: {summary})"

RESPOND WITH VALID YAML ONLY - NO MARKDOWN FORMATTING:"""

    return prompt


def generate_semgrep_rules(vuln_data: Dict[str, Any], model: str, ollama_url: str, seed: Optional[int], debug: bool = False) -> Optional[Dict[str, Any]]:
    """Generate semgrep rules for a vulnerability using LLM."""
    
    prompt = build_semgrep_generation_prompt(vuln_data)
    
    if debug:
        print(f"Generating semgrep rules for {vuln_data['go_id']}...")
    
    try:
        response = ollama_generate(prompt, model=model, url=ollama_url, seed=seed, max_tokens=4096)
        
        if debug:
            print(f"LLM response length: {len(response)} chars")
        
        # Try to parse as YAML
        try:
            rules_data = yaml.safe_load(response)
            return {
                "go_id": vuln_data["go_id"],
                "rules": rules_data,
                "raw_response": response
            }
        except yaml.YAMLError as e:
            # Try to extract YAML from the response
            yaml_match = re.search(r'```ya?ml\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
            if yaml_match:
                yaml_content = yaml_match.group(1)
                rules_data = yaml.safe_load(yaml_content)
                return {
                    "go_id": vuln_data["go_id"],
                    "rules": rules_data,
                    "raw_response": response
                }
            else:
                # Try to parse the entire response as YAML
                lines = response.strip().split('\n')
                # Remove any leading explanation text and find the start of YAML
                yaml_start = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith('rules:') or line.strip().startswith('-'):
                        yaml_start = i
                        break
                
                yaml_content = '\n'.join(lines[yaml_start:])
                rules_data = yaml.safe_load(yaml_content)
                return {
                    "go_id": vuln_data["go_id"],
                    "rules": rules_data,
                    "raw_response": response
                }
    except Exception as e:
        if debug:
            print(f"Error generating semgrep rules for {vuln_data['go_id']}: {e}")
        return None


def save_semgrep_rules(rules_data: Dict[str, Any], output_dir: Path, debug: bool = False):
    """Save generated semgrep rules to files."""
    
    go_id = rules_data["go_id"]
    rules = rules_data["rules"]
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save individual rule file
    rule_file = output_dir / f"{go_id}.yml"
    with open(rule_file, 'w', encoding='utf-8') as f:
        yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
    
    # Save raw response for debugging
    if debug:
        raw_file = output_dir / f"{go_id}_raw.txt"
        with open(raw_file, 'w', encoding='utf-8') as f:
            f.write(rules_data["raw_response"])
    
    # Save metadata
    metadata_file = output_dir / f"{go_id}_metadata.json"
    metadata = {
        "go_id": go_id,
        "generated_rules_count": len(rules.get("rules", [])) if "rules" in rules else 0,
        "rule_file": str(rule_file.name)
    }
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    if debug:
        print(f"Saved semgrep rules for {go_id} to {rule_file}")


def process_vulnerabilities(input_dir: Path, output_dir: Path, model: str, ollama_url: str, 
                          seed: Optional[int], debug: bool, only_with_examples: bool):
    """Process all vulnerabilities and generate semgrep rules."""
    
    if not input_dir.exists():
        print(f"Input directory {input_dir} does not exist")
        return
    
    # Find all vulnerability directories
    vuln_dirs = [d for d in input_dir.iterdir() if d.is_dir() and d.name.startswith("GO-")]
    
    if debug:
        print(f"Found {len(vuln_dirs)} vulnerability directories")
    
    processed = 0
    generated = 0
    
    for vuln_dir in sorted(vuln_dirs):
        vuln_data = read_vulnerability_data(vuln_dir)
        if not vuln_data:
            if debug:
                print(f"Skipping {vuln_dir.name} - no valid data")
            continue
        
        # Skip if only processing vulnerabilities with code examples
        if only_with_examples and (not vuln_data["bad_code"] or not vuln_data["good_code"]):
            if debug:
                print(f"Skipping {vuln_dir.name} - no code examples")
            continue
        
        processed += 1
        
        # Generate semgrep rules
        rules_data = generate_semgrep_rules(vuln_data, model, ollama_url, seed, debug)
        if rules_data:
            save_semgrep_rules(rules_data, output_dir, debug)
            generated += 1
        else:
            if debug:
                print(f"Failed to generate rules for {vuln_dir.name}")
    
    print(f"Processing complete: {processed} vulnerabilities processed, {generated} rule sets generated")


def create_master_ruleset(output_dir: Path, debug: bool = False):
    """Create a master semgrep ruleset combining all individual rules."""
    
    if not output_dir.exists():
        return
    
    master_rules = {"rules": []}
    rule_files = list(output_dir.glob("GO-*.yml"))
    
    if debug:
        print(f"Combining {len(rule_files)} rule files into master ruleset")
    
    for rule_file in sorted(rule_files):
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rules_data = yaml.safe_load(f)
                if "rules" in rules_data:
                    master_rules["rules"].extend(rules_data["rules"])
                elif isinstance(rules_data, list):
                    master_rules["rules"].extend(rules_data)
        except Exception as e:
            if debug:
                print(f"Error processing {rule_file}: {e}")
    
    # Save master ruleset
    master_file = output_dir / "all_vulnerability_rules.yml"
    with open(master_file, 'w', encoding='utf-8') as f:
        yaml.dump(master_rules, f, default_flow_style=False, sort_keys=False)
    
    print(f"Created master ruleset with {len(master_rules['rules'])} rules: {master_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate semgrep rules from vulnerability analysis"
    )
    parser.add_argument("--input", required=True, help="Input directory (vuln2examples.py output)")
    parser.add_argument("--output", default="./semgrep_rules", help="Output directory for semgrep rules")
    parser.add_argument("--model", default="qwen2.5-coder:14b", help="Ollama model name")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama base URL")
    parser.add_argument("--seed", type=int, default=None, help="LLM seed for reproducibility")
    parser.add_argument("--debug", action="store_true", help="Verbose logging")
    parser.add_argument("--only-with-examples", action="store_true", 
                       help="Only process vulnerabilities that have good/bad code examples")
    parser.add_argument("--create-master", action="store_true", 
                       help="Create master ruleset combining all rules")
    
    args = parser.parse_args()
    
    input_dir = Path(args.input).resolve()
    output_dir = Path(args.output).resolve()
    
    if args.debug:
        print(f"Input directory: {input_dir}")
        print(f"Output directory: {output_dir}")
        print(f"Model: {args.model}")
        print(f"Only with examples: {args.only_with_examples}")
    
    # Process vulnerabilities
    process_vulnerabilities(
        input_dir=input_dir,
        output_dir=output_dir,
        model=args.model,
        ollama_url=args.ollama_url,
        seed=args.seed,
        debug=args.debug,
        only_with_examples=args.only_with_examples
    )
    
    # Create master ruleset if requested
    if args.create_master:
        create_master_ruleset(output_dir, args.debug)


if __name__ == "__main__":
    main()