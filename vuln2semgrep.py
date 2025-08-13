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
def ollama_generate(prompt: str, model: str, url: str, seed: Optional[int], max_tokens: int = 4096, low_fp_mode: bool = False) -> str:
    # Adjust parameters based on mode
    if low_fp_mode:
        temperature = 0.02  # Very low temperature for maximum consistency in low-FP mode
        top_p = 0.6         # More focused sampling
    else:
        temperature = 0.1   # Standard temperature
        top_p = 0.9         # Standard sampling
        
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 32768,  # Increased context window from 16384 to 32768
            "num_predict": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
        },
    }
    if seed is not None:
        payload["options"]["seed"] = int(seed)
    r = requests.post(f"{url.rstrip('/')}/api/generate", json=payload, timeout=900)  # Increased timeout from 300s to 900s (15 minutes)
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
    diff = vuln_data["diff"][:2000] if vuln_data["diff"] else ""  # Limit diff size
    bad_code = vuln_data["bad_code"]
    good_code = vuln_data["good_code"]
    
    # Extract rationale if available
    rationale = ""
    if vuln_data["report"].get("results"):
        rationale = vuln_data["report"]["results"][0].get("rationale", "")
    
    prompt = f"""You are an expert creating Semgrep rules. Generate practical semgrep rules to detect vulnerability patterns like {go_id}: {summary}

VULNERABLE CODE:
```go
{bad_code}
```

FIXED CODE:
```go
{good_code}
```

ANALYSIS INSTRUCTIONS:
1. Compare the vulnerable vs fixed code - what specific check/validation was ADDED in the fix?
2. If the fix adds a security check, create a pattern-not rule to detect its absence
3. Focus on SPECIFIC security-relevant patterns, not generic if statements
4. Avoid overly broad patterns like `if $CONDITION {{ ... }}`

PATTERN GUIDANCE:
- For MISSING validations: Use patterns + pattern-not to detect absence of specific checks
- For UNSAFE operations: Target the specific dangerous function call or operation  
- For BOUNDS issues: Focus on array/slice access without proper checks
- For TYPE issues: Target specific type checks or conversions
- Balance SPECIFICITY: Specific enough to avoid false positives, general enough to catch variants
- Use metavariables ($VAR) to generalize patterns beyond exact function names

EXAMPLES:

GOOD (specific pattern with metavariables):
```yaml
patterns:
  - pattern: |
      for $I, $V := range $OBJ.$VOTES {{
        $RESULT[$I] = $V.$METHOD()
      }}
  - pattern-not: |
      if $OBJ.$TYPE != $EXPECTED_TYPE {{
        ...
      }}
      for $I, $V := range $OBJ.$VOTES {{
        $RESULT[$I] = $V.$METHOD()  
      }}
```

BAD (too generic):
```yaml
pattern: if $CONDITION {{ ... }}
```

BAD (too specific):
```yaml
pattern: func specificFunctionName(exact params) {{ ... }}
```

GOOD (balanced specificity):
```yaml
patterns:
  - pattern: |
      if $DATA[$INDEX] == '[' || $DATA[$INDEX] == '{{' {{
        return $RET
      }}
  - pattern-not: |
      if $DATA[$INDEX] == '[' || $DATA[$INDEX] == '{{' {{
        $END := $BLOCK_END_FUNC(...)
        ...
      }}
```

OUTPUT (YAML only, no markdown backticks):
rules:
- id: specific-vulnerability-name
  message: "Missing security validation: [describe what check is missing]"
  severity: HIGH
  patterns:
    - pattern: |
        [pattern matching vulnerable code context]
    - pattern-not: |
        [pattern matching the security check that should be present]
  languages: [go]

Generate 1-2 SPECIFIC rules targeting the actual security issue:"""

    return prompt


def build_comprehensive_low_fp_prompt(vuln_data: Dict[str, Any]) -> str:
    """Build a comprehensive low false positive prompt for semgrep rule generation."""
    
    go_id = vuln_data["go_id"]
    summary = vuln_data["report"].get("summary", "")
    cve = vuln_data["report"].get("cve", "")
    bad_code = vuln_data["bad_code"]
    good_code = vuln_data["good_code"]
    diff = vuln_data["diff"][:2000] if vuln_data["diff"] else ""
    
    # Extract rationale if available
    rationale = ""
    if vuln_data["report"].get("results"):
        rationale = vuln_data["report"]["results"][0].get("rationale", "")
    
    prompt = f"""You are a security expert creating HIGH-PRECISION semgrep rules with MINIMAL FALSE POSITIVES.

VULNERABILITY: {go_id}
DESCRIPTION: {summary}
CVE: {cve}
RATIONALE: {rationale}

VULNERABLE CODE:
```go
{bad_code}
```

FIXED CODE (shows the validation that prevents the vulnerability):
```go
{good_code}
```

CRITICAL REQUIREMENTS FOR LOW FALSE POSITIVE RULES:

1. **SPECIFICITY OVER COVERAGE**:
   - Target EXACT vulnerability patterns, not general code structures
   - Include specific method names, variable types, and context
   - Example: Match `CommitSig()` not just any `$METHOD()`
   - Example: Match `votes` field specifically, not just `$ARRAY`

2. **VALIDATION DETECTION STRATEGIES**:
   
   **Strategy A: Same-function validation detection**
   ```yaml
   patterns:
     - pattern: |
         for $I, $V := range $OBJ.votes {{
           $RESULT[$I] = $V.CommitSig()
         }}
     - pattern-not-inside: |
         if $OBJ.signedMsgType != $VALUE {{
           panic($MSG)
         }}
   ```
   
   **Strategy B: Require specific vulnerable method signatures**
   ```yaml
   patterns:
     - pattern: |
         func ($RECV *VoteSet) MakeCommit() *Commit {{
           ...
           for $I, $V := range $RECV.votes {{
             commitSigs[$I] = $V.CommitSig()
           }}
           ...
         }}
     - pattern-not-inside: |
         if $RECV.signedMsgType != tmproto.PrecommitType {{
           panic($MSG)
         }}
   ```

3. **WHITELIST SAFE PATTERNS** (use pattern-not-inside extensively):
   - Detect when proper validation exists
   - Look for panic/return statements in validation blocks
   - Match the EXACT validation from the fixed code

4. **AVOID THESE FALSE POSITIVE GENERATORS**:
   ❌ `for $I, $V := range $ARRAY` (too broad)
   ❌ `$OBJ.$METHOD()` (matches everything)
   ❌ `if $CONDITION` (matches all conditions)
   
   ✅ `for $I, $V := range $OBJ.votes` (specific field)
   ✅ `$V.CommitSig()` (specific method)
   ✅ `if $OBJ.signedMsgType != tmproto.PrecommitType` (exact validation)

5. **SEMGREP SYNTAX REQUIREMENTS**:
   - Use exact field names and method names from the vulnerability
   - Test patterns are syntactically valid
   - Include multiple pattern-not-inside clauses for comprehensive whitelisting

6. **VALIDATION PATTERNS TO DETECT**:
   From the FIXED CODE, identify the exact validation added:
   - What field is checked? (e.g., `signedMsgType`)
   - What value is expected? (e.g., `tmproto.PrecommitType`) 
   - What action is taken? (e.g., `panic`, `return error`)

7. **COMPREHENSIVE WHITELISTING**:
   Anticipate developer variations - developers might write the same validation differently:
   - `if field != value` vs `if field == value` 
   - `panic(msg)` vs `return error` vs `log.Fatal()`
   - Different variable names: `vs`, `voteSet`, `voteset`, `obj`
   - Different constants: `PrecommitType`, `"PrecommitType"`, `PRECOMMIT_TYPE`

YOUR TASK: Generate 1-2 HIGHLY SPECIFIC rules that:
1. Match the EXACT vulnerable pattern from the bad code
2. Use EXACT field names, method names, and types
3. Whitelist the EXACT validation from the good code
4. Include 4-6 pattern-not-inside clauses covering validation variations
5. Have ZERO false positives on legitimate code

OUTPUT (YAML only, no markdown backticks):
rules:
- id: {go_id.lower().replace('-', '_')}_comprehensive
  message: "Specific description mentioning exact methods/fields from {go_id}: {summary}"
  severity: HIGH
  patterns:
    - pattern-either:
      - pattern: |
          # Exact vulnerable pattern with specific names
      - pattern: |
          # Alternative vulnerable pattern if applicable
    # Extensive whitelisting of all safe patterns (REQUIRED: 4-6 clauses minimum)
    - pattern-not-inside: |
        # Safe pattern 1 (exact from fixed code)
    - pattern-not-inside: |  
        # Safe pattern 2 (alternative format)
    - pattern-not-inside: |
        # Safe pattern 3 (different variable names)
    - pattern-not-inside: |
        # Safe pattern 4 (different constants/actions)
    - pattern-not-inside: |
        # Safe pattern 5 (any other variations you can think of)
  languages: [go]

Focus on PRECISION over coverage. Better to catch 50% of similar vulnerabilities with 0% false positives than 90% with 20% false positives."""

    return prompt


def clean_semgrep_pattern(pattern: str) -> str:
    """Clean up semgrep patterns to remove formatting issues."""
    if not pattern:
        return pattern
    
    # Only strip leading/trailing whitespace, preserve internal structure
    pattern = pattern.strip()
    
    # Remove regex-style anchors that shouldn't be in semgrep patterns
    pattern = re.sub(r'^\^|\$$', '', pattern)
    
    # Fix escaped dots (regex style) - semgrep uses literal dots
    pattern = re.sub(r'\\\\.', '.', pattern)
    
    # Remove regex quantifiers that don't belong in semgrep (only at end of lines)
    lines = pattern.split('\n')
    cleaned_lines = []
    for line in lines:
        line = re.sub(r'[*+?]\s*$', '', line)
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)


def clean_semgrep_message(message: str, go_id: str, summary: str) -> str:
    """Clean up and standardize semgrep rule messages."""
    if not message:
        return f"Potential security vulnerability. Similar to {go_id}: {summary}"
    
    # Remove extra whitespace and newlines
    message = message.strip()
    message = re.sub(r'\s+', ' ', message)
    
    # Ensure vulnerability reference is included
    if go_id not in message:
        if not message.endswith('.'):
            message += '.'
        message += f" Similar to {go_id}: {summary}"
    
    return message


def fix_yaml_formatting(yaml_text: str) -> str:
    """Fix common YAML formatting issues in LLM responses."""
    lines = yaml_text.split('\n')
    fixed_lines = []
    
    for line in lines:
        # Fix message lines that contain unquoted colons
        if line.strip().startswith('message:'):
            # Extract the message part
            if ':' in line[8:]:  # Skip 'message:' part
                message_part = line[line.index(':') + 1:].strip()
                if not (message_part.startswith('"') and message_part.endswith('"')):
                    # Quote the message if it contains colons
                    if ':' in message_part:
                        indent = len(line) - len(line.lstrip())
                        line = ' ' * indent + f'message: "{message_part}"'
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def clean_semgrep_rules_data(rules_data: dict, go_id: str, summary: str) -> dict:
    """Post-process generated semgrep rules to fix formatting issues."""
    if not rules_data or "rules" not in rules_data:
        return rules_data
    
    cleaned_rules = []
    
    for rule in rules_data["rules"]:
        if not isinstance(rule, dict):
            continue
            
        cleaned_rule = {}
        
        # Clean each field
        for key, value in rule.items():
            if key == "pattern":
                cleaned_rule[key] = clean_semgrep_pattern(str(value))
            elif key == "message":
                cleaned_rule[key] = clean_semgrep_message(str(value), go_id, summary)
            elif key == "languages" and isinstance(value, list):
                # Ensure languages is properly formatted
                cleaned_rule[key] = ["go"] if "go" not in value else value
            else:
                # Keep other fields as-is but strip whitespace if string
                if isinstance(value, str):
                    cleaned_rule[key] = value.strip()
                else:
                    cleaned_rule[key] = value
        
        # Ensure required fields
        if "languages" not in cleaned_rule:
            cleaned_rule["languages"] = ["go"]
        if "severity" not in cleaned_rule:
            cleaned_rule["severity"] = "MEDIUM"
            
        cleaned_rules.append(cleaned_rule)
    
    return {"rules": cleaned_rules}


def generate_semgrep_rules(vuln_data: Dict[str, Any], model: str, ollama_url: str, seed: Optional[int], debug: bool = False, output_dir: Optional[Path] = None, low_fp: bool = False) -> Optional[Dict[str, Any]]:
    """Generate semgrep rules for a vulnerability using LLM."""
    
    # Choose prompt based on low_fp flag
    if low_fp:
        prompt = build_comprehensive_low_fp_prompt(vuln_data)
        if debug:
            print(f"Using comprehensive low false positive prompt for {vuln_data['go_id']}")
    else:
        prompt = build_semgrep_generation_prompt(vuln_data)
    
    if debug:
        print(f"Generating semgrep rules for {vuln_data['go_id']}...")
    
    try:
        # Use different parameters for low-FP mode for more consistent output
        if low_fp:
            # More conservative parameters for higher precision
            max_tokens = 6144  # More space for comprehensive patterns
        else:
            max_tokens = 4096
            
        response = ollama_generate(prompt, model=model, url=ollama_url, seed=seed, max_tokens=max_tokens, low_fp_mode=low_fp)
        
        if debug:
            print(f"LLM response length: {len(response)} chars")
            # Save raw response for debugging
            if output_dir:
                debug_file = output_dir / f"{vuln_data['go_id']}_debug_response.txt"
                debug_file.parent.mkdir(parents=True, exist_ok=True)
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(response)
        
        # Multiple strategies to extract YAML from LLM response
        go_id = vuln_data["go_id"]
        summary = vuln_data["report"].get("summary", "")
        
        def try_parse_yaml(yaml_text):
            """Try to parse YAML and return cleaned rules."""
            try:
                # Pre-process YAML to fix common issues
                yaml_text = fix_yaml_formatting(yaml_text)
                
                rules_data = yaml.safe_load(yaml_text)
                if rules_data and ("rules" in rules_data or isinstance(rules_data, list)):
                    # Ensure proper structure
                    if isinstance(rules_data, list):
                        rules_data = {"rules": rules_data}
                    cleaned_rules = clean_semgrep_rules_data(rules_data, go_id, summary)
                    return cleaned_rules
            except Exception as e:
                if debug:
                    print(f"YAML parsing failed for {go_id}: {e}")
            return None
        
        # Strategy 1: Try parsing entire response as YAML
        cleaned_rules = try_parse_yaml(response)
        if cleaned_rules:
            return {
                "go_id": go_id,
                "rules": cleaned_rules,
                "raw_response": response
            }
        
        # Strategy 2: Extract YAML from markdown code blocks
        yaml_patterns = [
            r'```ya?ml\s*(.*?)\s*```',  # Standard yaml blocks
            r'```\s*(rules:.*?)```',     # Code blocks starting with rules:
            r'```\s*(- id:.*?)```'       # Code blocks starting with - id:
        ]
        
        for pattern in yaml_patterns:
            yaml_match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if yaml_match:
                yaml_content = yaml_match.group(1).strip()
                cleaned_rules = try_parse_yaml(yaml_content)
                if cleaned_rules:
                    return {
                        "go_id": go_id,
                        "rules": cleaned_rules,
                        "raw_response": response
                    }
        
        # Strategy 3: Find YAML section by looking for rules: or - id:
        lines = response.strip().split('\n')
        yaml_start = -1
        yaml_end = len(lines)
        
        # Find start of YAML (rules: or first - id:)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('rules:') or stripped.startswith('- id:'):
                yaml_start = i
                break
        
        if yaml_start >= 0:
            # Find end of YAML (look for explanatory text after)
            for i in range(yaml_start + 1, len(lines)):
                line = lines[i].strip()
                # Stop at explanatory text indicators
                if (line and not line.startswith('-') and not line.startswith(' ') 
                    and not line.startswith('id:') and not line.startswith('message:') 
                    and not line.startswith('severity:') and not line.startswith('pattern:')
                    and not line.startswith('languages:') and ':' not in line):
                    yaml_end = i
                    break
            
            yaml_content = '\n'.join(lines[yaml_start:yaml_end])
            cleaned_rules = try_parse_yaml(yaml_content)
            if cleaned_rules:
                return {
                    "go_id": go_id,
                    "rules": cleaned_rules,
                    "raw_response": response
                }
        
        # Strategy 4: Extract everything between first 'rules:' and last 'languages:'
        rules_match = re.search(r'(rules:.*?languages:\s*\[.*?\])', response, re.DOTALL | re.IGNORECASE)
        if rules_match:
            yaml_content = rules_match.group(1)
            cleaned_rules = try_parse_yaml(yaml_content)
            if cleaned_rules:
                return {
                    "go_id": go_id,
                    "rules": cleaned_rules,
                    "raw_response": response
                }
    except Exception as e:
        if debug:
            print(f"Error generating semgrep rules for {vuln_data['go_id']}: {e}")
        return None


def validate_and_refine_rule(rule_data: dict, vuln_data: Dict[str, Any], model: str, ollama_url: str, seed: Optional[int], debug: bool = False) -> Optional[dict]:
    """LLM-based rule validation and refinement."""
    
    go_id = vuln_data["go_id"]
    summary = vuln_data["report"].get("summary", "")
    bad_code = vuln_data["bad_code"]
    good_code = vuln_data["good_code"]
    
    # Convert rule to YAML string for analysis
    rule_yaml = yaml.dump(rule_data, default_flow_style=False, sort_keys=False)
    
    prompt = f"""You are a Semgrep rule quality expert. Analyze this generated rule for potential issues.

ORIGINAL VULNERABILITY: {go_id} - {summary}

GENERATED RULE:
```yaml
{rule_yaml}
```

VULNERABLE CODE EXAMPLE:
```go
{bad_code}
```

FIXED CODE EXAMPLE:
```go
{good_code}
```

ANALYSIS REQUIREMENTS:
1. Is this rule TOO BROAD? (Will it match unrelated, benign code?)
2. Is this rule TOO NARROW? (Will it miss similar vulnerability patterns?)
3. Are there obvious false positive scenarios?
4. Does the pattern correctly target the ABSENCE of security checks rather than their presence?
5. Is the Semgrep syntax correct and efficient?

EVALUATION CRITERIA:
- A rule is TOO BROAD if it matches common, safe coding patterns
- A rule is TOO NARROW if it only matches this exact vulnerability instance
- Good rules balance precision (low false positives) with recall (catch variants)
- Patterns should use appropriate metavariables and ellipsis for flexibility

VULNERABILITY PATTERN ANALYSIS:
- Does this vulnerability involve MISSING security checks rather than present ones?
- Should the pattern use 'pattern-not' to detect absent validations?
- Is the pattern matching safe code that DOES check security conditions?
- Would legitimate code trigger this rule frequently?

COMMON OVERLY BROAD PATTERNS TO AVOID:
- Matching any method call + any security check (safe code does this!)
- Matching presence of security checks instead of their absence
- Using 'and' when you should use 'pattern-not'
- Matching common object methods without context

BETTER PATTERN EXAMPLES:
For authentication bypass vulnerabilities, prefer:
```yaml
# GOOD: Detect authentication without proper checks
pattern: |
  func $AUTH_FUNC($...ARGS) {{
    ...
    return $SUCCESS
  }}
pattern-not: |
  func $AUTH_FUNC($...ARGS) {{
    ...
    $USER.is_active
    ...
  }}
pattern-where:
  - metavariable: $AUTH_FUNC
    regex: .*(auth|login|signin).*
```

Instead of:
```yaml  
# BAD: Matches safe code that properly checks is_active
pattern: $OBJ.$METHOD($...ARGS) and $OBJ.is_active
```

RESPONSE FORMAT (JSON only):
{{
  "is_too_broad": true/false,
  "is_too_narrow": true/false,
  "has_syntax_issues": true/false,
  "confidence": 0.0-1.0,
  "issues": ["specific problem 1", "specific problem 2"],
  "false_positive_examples": ["code that would wrongly match"],
  "suggested_improvements": ["specific fix 1", "specific fix 2"],
  "needs_refinement": true/false,
  "refined_rule": {{
    "id": "improved-rule-id",
    "message": "improved message", 
    "severity": "HIGH/MEDIUM/LOW/CRITICAL",
    "pattern": "main pattern that matches vulnerable code",
    "pattern-not": "pattern that excludes safe code (if needed)",
    "pattern-either": ["alternative pattern 1", "alternative pattern 2"],
    "pattern-where": [{{"metavariable": "$VAR", "regex": "pattern"}}],
    "languages": ["go"]
  }}
}}

Respond with JSON only - no explanations:"""

    try:
        if debug:
            print(f"Validating rule for {go_id}...")
        
        response = ollama_generate(prompt, model=model, url=ollama_url, seed=seed, max_tokens=2048)
        
        if debug:
            print(f"Validation response length: {len(response)} chars")
        
        # Try to parse JSON response
        try:
            # Clean up response and extract JSON
            response = response.strip()
            
            # Try direct JSON parsing
            validation_result = json.loads(response)
            return validation_result
            
        except json.JSONDecodeError:
            # Try to extract JSON from response
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL | re.IGNORECASE)
            if json_match:
                json_content = json_match.group(1)
                validation_result = json.loads(json_content)
                return validation_result
            else:
                # Try to find JSON within the response
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_content = response[json_start:json_end]
                    validation_result = json.loads(json_content)
                    return validation_result
        
        if debug:
            print(f"Failed to parse validation response for {go_id}")
        return None
        
    except Exception as e:
        if debug:
            print(f"Error validating rule for {go_id}: {e}")
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


def validate_existing_rules(input_dir: Path, rules_dir: Path, model: str, ollama_url: str, 
                          seed: Optional[int], debug: bool):
    """Validate and refine existing semgrep rules."""
    
    if not rules_dir.exists():
        print(f"Rules directory {rules_dir} does not exist")
        return
        
    rule_files = list(rules_dir.glob("GO-*.yml"))
    if debug:
        print(f"Found {len(rule_files)} existing rule files to validate")
    
    validated = 0
    refined = 0
    
    for rule_file in sorted(rule_files):
        go_id = rule_file.stem
        
        # Read vulnerability data
        vuln_dir = input_dir / go_id
        if not vuln_dir.exists():
            if debug:
                print(f"Skipping {go_id} - no vulnerability data")
            continue
            
        vuln_data = read_vulnerability_data(vuln_dir)
        if not vuln_data:
            if debug:
                print(f"Skipping {go_id} - invalid vulnerability data")
            continue
            
        # Read existing rules
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                existing_rules = yaml.safe_load(f)
        except Exception as e:
            if debug:
                print(f"Error reading {rule_file}: {e}")
            continue
            
        # Validate each rule in the file
        if "rules" not in existing_rules:
            continue
            
        needs_refinement = False
        refined_rules = []
        
        for rule in existing_rules["rules"]:
            validation = validate_and_refine_rule(rule, vuln_data, model, ollama_url, seed, debug)
            
            if validation:
                validated += 1
                
                if debug:
                    print(f"Rule {rule.get('id', 'unknown')} validation:")
                    print(f"  Too broad: {validation.get('is_too_broad', False)}")
                    print(f"  Too narrow: {validation.get('is_too_narrow', False)}")
                    print(f"  Needs refinement: {validation.get('needs_refinement', False)}")
                    if validation.get('issues'):
                        print(f"  Issues: {validation['issues']}")
                
                # Use refined rule if available and needed
                if validation.get('needs_refinement') and validation.get('refined_rule'):
                    refined_rules.append(validation['refined_rule'])
                    needs_refinement = True
                    if debug:
                        print(f"  Using refined rule for {rule.get('id', 'unknown')}")
                else:
                    refined_rules.append(rule)
                    
                # Save validation report
                validation_file = rules_dir / f"{go_id}_validation.json"
                with open(validation_file, 'w', encoding='utf-8') as f:
                    json.dump(validation, f, indent=2)
        
        # Save refined rules if any were improved
        if needs_refinement and refined_rules:
            refined_rules_data = {"rules": refined_rules}
            refined_file = rules_dir / f"{go_id}_refined.yml"
            with open(refined_file, 'w', encoding='utf-8') as f:
                yaml.dump(refined_rules_data, f, default_flow_style=False, sort_keys=False)
            refined += 1
            if debug:
                print(f"Saved refined rules to {refined_file}")
    
    print(f"Validation complete: {len(rule_files)} rule files processed, {validated} rules validated, {refined} rule files refined")


def process_vulnerabilities(input_dir: Path, output_dir: Path, model: str, ollama_url: str, 
                          seed: Optional[int], debug: bool, only_with_examples: bool, limit: Optional[int] = None, low_fp: bool = False):
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
    
    # Filter and apply limit
    if only_with_examples:
        # Only keep directories that have code examples
        vuln_dirs = [d for d in vuln_dirs if (d / f"{d.name}_bad.go").exists()]
        if debug:
            print(f"Found {len(vuln_dirs)} vulnerabilities with code examples")
    
    # Apply limit if specified
    if limit:
        vuln_dirs = vuln_dirs[:limit]
        if debug:
            print(f"Limited to first {limit} vulnerabilities")
    
    for vuln_dir in sorted(vuln_dirs):
        go_id = vuln_dir.name
        
        # Check if rules already exist (resume capability)
        rule_file = output_dir / f"{go_id}.yml"
        if rule_file.exists():
            if debug:
                print(f"Skipping {go_id} - rules already generated")
            continue
        
        vuln_data = read_vulnerability_data(vuln_dir)
        if not vuln_data:
            if debug:
                print(f"Skipping {vuln_dir.name} - no valid data")
            continue
        
        # Skip if no vulnerability data (this should not happen after pre-filtering)
        if not vuln_data["bad_code"] or not vuln_data["good_code"]:
            if debug:
                print(f"Skipping {vuln_dir.name} - missing code examples")
            continue
        
        processed += 1
        
        # Generate semgrep rules
        rules_data = generate_semgrep_rules(vuln_data, model, ollama_url, seed, debug, output_dir, low_fp)
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
    parser.add_argument("--validate-rules", action="store_true",
                       help="Validate and refine existing rules using LLM analysis")
    parser.add_argument("--limit", type=int, default=None, 
                       help="Limit processing to first N vulnerabilities (for testing)")
    parser.add_argument("--low-fp", action="store_true",
                       help="Generate low false positive rules with comprehensive validation whitelisting")
    
    args = parser.parse_args()
    
    input_dir = Path(args.input).resolve()
    output_dir = Path(args.output).resolve()
    
    if args.debug:
        print(f"Input directory: {input_dir}")
        print(f"Output directory: {output_dir}")
        print(f"Model: {args.model}")
        print(f"Only with examples: {args.only_with_examples}")
    
    # Validate existing rules if requested
    if args.validate_rules:
        validate_existing_rules(
            input_dir=input_dir,
            rules_dir=output_dir,
            model=args.model,
            ollama_url=args.ollama_url,
            seed=args.seed,
            debug=args.debug
        )
    else:
        # Process vulnerabilities to generate new rules
        process_vulnerabilities(
            input_dir=input_dir,
            output_dir=output_dir,
            model=args.model,
            ollama_url=args.ollama_url,
            seed=args.seed,
            debug=args.debug,
            only_with_examples=args.only_with_examples,
            limit=args.limit,
            low_fp=args.low_fp
        )
    
    # Create master ruleset if requested
    if args.create_master:
        create_master_ruleset(output_dir, args.debug)


if __name__ == "__main__":
    main()