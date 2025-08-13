#!/usr/bin/env python3
"""
Integrated Batch Generator with Iterative Refinement

This combines the batch rule generation with the iterative refinement process
to ensure each rule is tested and improved before saving.
"""

import json
import os
import sys
import yaml
import requests
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from refinement_quality_tracker import RefinementQualityTracker

def extract_descriptive_vulnerability_message(summary, details=""):
    """Extract a descriptive vulnerability message with educational context."""
    summary_lower = summary.lower()
    details_lower = details.lower() if details else ""
    combined = f"{summary_lower} {details_lower}"
    
    # Detailed vulnerability patterns with educational context
    if 'infinite loop' in summary_lower:
        return 'Infinite loop vulnerability - code may loop indefinitely causing DoS'
    elif 'denial of service' in summary_lower or 'dos' in summary_lower:
        return 'Denial of service vulnerability - application may become unresponsive'
    elif 'memory corruption' in summary_lower and ('finalizer' in combined or 'garbage collect' in combined):
        return 'CGO memory corruption - premature finalization may cause use-after-free (add runtime.KeepAlive)'
    elif 'memory corruption' in summary_lower:
        return 'Memory corruption vulnerability - may lead to crashes or code execution'
    elif 'code execution' in summary_lower:
        return 'Remote code execution vulnerability - attacker may execute arbitrary code'
    elif 'buffer overflow' in summary_lower:
        return 'Buffer overflow vulnerability - may overwrite memory and enable code execution'
    elif 'memory leak' in summary_lower:
        return 'Memory leak vulnerability - may cause resource exhaustion and DoS'
    elif 'use after free' in summary_lower:
        return 'Use-after-free vulnerability - accessing freed memory may cause corruption'
    elif 'double free' in summary_lower:
        return 'Double free vulnerability - freeing memory twice may cause heap corruption'
    elif 'race condition' in summary_lower:
        return 'Race condition vulnerability - concurrent access may cause unpredictable behavior'
    elif 'null pointer' in summary_lower:
        return 'Null pointer dereference - accessing null pointer causes application crash'
    elif 'integer overflow' in summary_lower:
        return 'Integer overflow vulnerability - arithmetic overflow may cause unexpected behavior'
    elif 'sql injection' in summary_lower:
        return 'SQL injection vulnerability - untrusted input may manipulate database queries'
    elif 'cross-site scripting' in summary_lower or 'xss' in summary_lower:
        return 'Cross-site scripting vulnerability - malicious scripts may execute in user browsers'
    elif 'path traversal' in summary_lower:
        return 'Path traversal vulnerability - may allow access to files outside intended directory'
    elif 'authentication' in summary_lower:
        return 'Authentication bypass vulnerability - may allow unauthorized access'
    elif 'authorization' in summary_lower:
        return 'Authorization bypass vulnerability - may allow privilege escalation'
    elif 'injection' in summary_lower:
        return 'Injection vulnerability - untrusted input may be interpreted as commands'
    elif 'validation' in summary_lower or 'input' in summary_lower:
        return 'Input validation vulnerability - insufficient validation may allow malicious input'
    elif 'privilege' in summary_lower:
        return 'Privilege escalation vulnerability - may allow elevation of user permissions'
    elif 'information disclosure' in summary_lower:
        return 'Information disclosure vulnerability - sensitive data may be exposed'
    elif 'finalizer' in summary_lower or 'garbage collect' in summary_lower:
        return 'Memory management vulnerability - improper finalizer usage may cause corruption'
    elif 'crash' in summary_lower:
        return 'Application crash vulnerability - may cause service disruption'
    elif 'panic' in summary_lower:
        return 'Panic vulnerability - unhandled condition may crash the application'
    elif 'bounds' in summary_lower or 'index' in summary_lower:
        return 'Bounds check vulnerability - array/slice access may be out of bounds'
    else:
        # Fallback with more context
        return 'Security vulnerability - review code for potential security issues'

def build_comprehensive_low_fp_prompt(vuln_id, metadata, bad_code, good_code, diff_content):
    """Build the comprehensive low FP prompt (same as before)."""
    
    # Extract the actual summary from the nested structure
    summary = metadata.get('vuln_json', {}).get('summary', 'N/A')
    if summary == 'N/A':
        # Try alternative locations
        summary = metadata.get('summary', 'N/A')
    
    # Generate descriptive message for the rule
    details = metadata.get('vuln_json', {}).get('details', '')
    descriptive_message = extract_descriptive_vulnerability_message(summary, details)
    
    prompt = f"""You are a security expert creating HIGH-PRECISION semgrep rules with MINIMAL FALSE POSITIVES.

⚠️  CRITICAL: Pattern blocks must contain ONLY pure Go code. NO COMMENTS (# or //) allowed in patterns!

VULNERABILITY: {vuln_id}
DESCRIPTION: {summary}

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
         for $I, $V := range $OBJECT.votes {{
           $RESULT[$I] = $V.CommitSig()
         }}
     - pattern-not-inside: |
         if $OBJECT.signedMsgType != $VALUE {{
           panic($MSG)
         }}
   ```
   
   **Strategy B: Require specific vulnerable method signatures**
   ```yaml
   patterns:
     - pattern: |
         func ($RECEIVER *VoteSet) MakeCommit() *Commit {{
           ...
           for $I, $V := range $RECEIVER.votes {{
             commitSigs[$I] = $V.CommitSig()
           }}
           ...
         }}
     - pattern-not-inside: |
         if $RECEIVER.signedMsgType != tmproto.PrecommitType {{
           panic($MSG)
         }}
   ```

3. **WHITELIST SAFE PATTERNS** (use pattern-not-inside extensively):
   - Detect when proper validation exists
   - Look for panic/return statements in validation blocks
   - Match the EXACT validation from the fixed code

4. **AVOID THESE FALSE POSITIVE GENERATORS**:
   ❌ `for $I, $V := range $ARRAY` (too broad)
   ❌ `$OBJECT.$METHOD()` (matches everything)
   ❌ `if $CONDITION` (matches all conditions)
   ❌ `$votes` (lowercase metavariable - INVALID)
   
   ✅ `for $I, $V := range $OBJECT.votes` (specific field)
   ✅ `$V.CommitSig()` (specific method)
   ✅ `if $OBJECT.signedMsgType != tmproto.PrecommitType` (exact validation)
   ✅ `$VOTES` (uppercase metavariable - CORRECT)

5. **SEMGREP SYNTAX REQUIREMENTS**:
   - **METAVARIABLES MUST BE ALL UPPERCASE**: Use $VOTES not $votes, $RESULT not $result, $OBJECT not $obj
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

YOUR TASK: Generate 1 HIGHLY SPECIFIC rule that:
1. Match the EXACT vulnerable pattern from the bad code
2. Use EXACT field names, method names, and types from the vulnerability
3. Whitelist the EXACT validation from the good code
4. Include 4-6 pattern-not-inside clauses covering validation variations
5. Have ZERO false positives on legitimate code
6. **CRITICAL**: Use only COMPLETE, VALID Go syntax with proper indentation

**FOCUS ON THE CORE VULNERABILITY ONLY** - Don't mix different vulnerability patterns in one rule.

RESPONSE FORMAT - Return valid YAML only:
```yaml
rules:
  - id: {vuln_id.lower().replace('-', '_')}_comprehensive
    message: "{descriptive_message} (CVE: {vuln_id})"
    severity: HIGH
    patterns:
      - pattern-either:
        - pattern: |
            for $I, $V := range $OBJECT.votes {{
              $RESULT[$I] = $V.CommitSig()
            }}
      # Extensive whitelisting of all safe patterns (REQUIRED: 4-6 clauses minimum)
      - pattern-not-inside: |
          if $OBJECT.signedMsgType != tmproto.PrecommitType {{
            panic($MSG)
          }}
      - pattern-not-inside: |
          if $OBJECT.signedMsgType != "PrecommitType" {{
            panic($MSG)
          }}
      - pattern-not-inside: |
          if $OBJECT.signedMsgType != PrecommitType {{
            panic($MSG)
          }}
      - pattern-not-inside: |
          if $VOTES.signedMsgType != tmproto.PrecommitType {{
            return error($MSG)
          }}
      - pattern-not-inside: |
          if $VOTES.signedMsgType != "PrecommitType" {{
            return error($MSG)
          }}
    languages: [go]
```

Focus on PRECISION over coverage. Better to catch 50% of similar vulnerabilities with 0% false positives than 90% with 20% false positives."""
    return prompt

def remove_comments_from_rule(rule_content: str) -> Tuple[str, bool]:
    """Remove comments from semgrep rule patterns and return (cleaned_rule, was_modified)."""
    lines = rule_content.split('\n')
    modified = False
    cleaned_lines = []
    
    in_pattern_block = False
    pattern_indent = 0
    
    for line in lines:
        # Detect if we're entering a pattern block
        if '- pattern:' in line or '- pattern-either:' in line or '- pattern-not-inside:' in line:
            in_pattern_block = False  # Reset for new pattern
            cleaned_lines.append(line)
            continue
        elif line.strip().endswith('|') and ('pattern:' in line or 'pattern-not-inside:' in line):
            in_pattern_block = True
            pattern_indent = len(line) - len(line.lstrip())
            cleaned_lines.append(line)
            continue
        
        if in_pattern_block:
            # Check if we're still in the pattern block (proper indentation)
            if line.strip() and len(line) - len(line.lstrip()) <= pattern_indent:
                in_pattern_block = False
            else:
                # Remove comments from pattern lines
                original_line = line
                # Remove # comments
                if '#' in line:
                    # Preserve indentation, remove comment and trailing whitespace
                    indent = line[:len(line) - len(line.lstrip())]
                    content = line.strip()
                    if content.startswith('#'):
                        # Entire line is a comment, skip it
                        modified = True
                        continue
                    else:
                        # Remove inline comments
                        if '#' in content:
                            content = content.split('#')[0].rstrip()
                            line = indent + content
                            if line != original_line:
                                modified = True
                
                # Remove // comments
                if '//' in line:
                    indent = line[:len(line) - len(line.lstrip())]
                    content = line.strip()
                    if content.startswith('//'):
                        # Entire line is a comment, skip it
                        modified = True
                        continue
                    else:
                        # Remove inline comments
                        if '//' in content:
                            content = content.split('//')[0].rstrip()
                            line = indent + content
                            if line != original_line:
                                modified = True
                
                # Only add non-empty lines
                if line.strip():
                    cleaned_lines.append(line)
                elif original_line.strip():  # Was non-empty before cleaning
                    modified = True
                else:
                    cleaned_lines.append(line)  # Preserve empty lines for structure
                continue
        
        # Not in pattern block, keep line as-is
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines), modified

def validate_go_syntax_basic(pattern: str) -> Tuple[bool, str]:
    """Basic validation of Go syntax patterns."""
    issues = []
    
    # Check for comments first
    if '#' in pattern or '//' in pattern:
        issues.append("Pattern contains comments (# or //) which are not allowed")
    
    # Check for basic indentation issues
    lines = pattern.split('\n')
    for i, line in enumerate(lines):
        if line.strip():
            # Check for proper indentation (should be consistent)
            leading_spaces = len(line) - len(line.lstrip())
            if leading_spaces % 2 != 0 and leading_spaces % 4 != 0:
                issues.append(f"Line {i+1}: Inconsistent indentation ({leading_spaces} spaces)")
    
    # Check for incomplete code patterns
    if "// ..." in pattern or "rest of function" in pattern.lower():
        issues.append("Pattern contains incomplete code (avoid '// ...' or 'rest of function')")
    
    # Check for matching braces
    open_braces = pattern.count('{')
    close_braces = pattern.count('}')
    if open_braces != close_braces:
        issues.append(f"Mismatched braces: {open_braces} opening, {close_braces} closing")
    
    # Check for valid Go control structures
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('for ') and not ('{' in stripped or stripped.endswith('{')):
            issues.append("For loop missing opening brace")
        if stripped.startswith('if ') and not ('{' in stripped or stripped.endswith('{')):
            issues.append("If statement missing opening brace")
    
    if issues:
        return False, "; ".join(issues)
    return True, "Basic Go syntax appears valid"

def validate_semgrep_rule(rule_file: Path) -> Tuple[bool, str]:
    """Validate semgrep rule syntax and return (is_valid, error_message)."""
    try:
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        result = subprocess.run([
            'semgrep', '--config', str(rule_file), '--validate'
        ], capture_output=True, text=True, timeout=30, env=env, encoding='utf-8', errors='replace')
        
        if result.returncode == 0:
            # Check if validation found errors in the output
            output = result.stderr + result.stdout
            if "Configuration is valid" in output and "0 configuration error(s)" in output:
                return True, "Rule syntax is valid"
            else:
                return False, f"Validation warnings: {output}"
        else:
            # Extract meaningful error message
            error_output = result.stderr + result.stdout
            return False, f"Semgrep validation failed: {error_output}"
            
    except Exception as e:
        return False, f"Error validating rule: {e}"

def run_semgrep_on_code(rule_file: Path, code_content: str) -> Tuple[bool, int, str]:
    """Run semgrep on code content and return (has_findings, finding_count, output)."""
    try:
        # Write code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, encoding='utf-8') as f:
            f.write(code_content)
            temp_file = f.name
        
        # Run semgrep with environment encoding fix
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        result = subprocess.run([
            'semgrep', '--config', str(rule_file), '--json', temp_file
        ], capture_output=True, text=True, timeout=30, env=env, encoding='utf-8', errors='replace')
        
        # Clean up
        os.unlink(temp_file)
        
        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
                findings = output.get('results', [])
                return len(findings) > 0, len(findings), result.stdout
            except json.JSONDecodeError:
                return False, 0, f"JSON decode error: {result.stdout}"
        else:
            return False, 0, f"Semgrep error (code {result.returncode}): {result.stderr}"
            
    except Exception as e:
        return False, 0, f"Error running semgrep: {e}"

def generate_test_cases(vuln_id: str, rule_content: str, vulnerability_description: str, 
                       bad_example: str, good_example: str, model: str = "qwen2.5-coder:7b") -> Dict[str, List[str]]:
    """Generate test cases using LLM to test rule effectiveness."""
    
    prompt = f"""You are a security testing expert. Generate comprehensive test cases for a semgrep rule.

VULNERABILITY: {vuln_id}
DESCRIPTION: {vulnerability_description}

ORIGINAL VULNERABLE CODE:
```go
{bad_example}
```

ORIGINAL FIXED CODE:
```go
{good_example}
```

SEMGREP RULE TO TEST:
```yaml
{rule_content}
```

GENERATE TEST CASES:

1. **TRUE POSITIVES** (3 cases): Code that SHOULD trigger the rule
   - The exact vulnerable pattern
   - One variation with different variable names
   - One edge case that should still be caught

2. **TRUE NEGATIVES** (3 cases): Code that should NOT trigger the rule  
   - The properly fixed version
   - Similar looking but safe pattern
   - One edge case that should be ignored

3. **POTENTIAL FALSE POSITIVES** (2 cases): Safe code that might incorrectly trigger
   - Code that looks similar but has proper validation
   - Common pattern that isn't a vulnerability

4. **POTENTIAL FALSE NEGATIVES** (2 cases): Vulnerable code that might be missed
   - Slightly obfuscated version of the vulnerability
   - Different but equivalent vulnerable pattern

RESPONSE FORMAT (JSON only):
```json
{{
  "true_positives": [
    "package main\\n\\nfunc vulnerable1() {{\\n  // code here\\n}}",
    "package main\\n\\nfunc vulnerable2() {{\\n  // code here\\n}}"
  ],
  "true_negatives": [
    "package main\\n\\nfunc safe1() {{\\n  // code here\\n}}",
    "package main\\n\\nfunc safe2() {{\\n  // code here\\n}}"
  ],
  "potential_false_positives": [
    "package main\\n\\nfunc maybeWronglyDetected() {{\\n  // code here\\n}}"
  ],
  "potential_false_negatives": [
    "package main\\n\\nfunc maybeWronglyMissed() {{\\n  // code here\\n}}"
  ]
}}
```

Generate realistic, syntactically correct Go code for each test case. Focus on the specific vulnerability pattern and validation approaches."""

    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,  # Lower temperature for faster, more consistent generation
                    "top_p": 0.7,
                    "num_ctx": 8192  # Reduced context to speed up processing
                }
            },
            timeout=600  # Increased from 300 to 600 seconds
        )
        
        if response.status_code == 200:
            result = response.json()
            generated_text = result.get('response', '')
            
            # Extract JSON from response
            json_start = generated_text.find('{')
            json_end = generated_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_content = generated_text[json_start:json_end]
                return json.loads(json_content)
            else:
                print(f"Could not extract JSON from LLM response")
                return {}
                
        else:
            print(f"LLM request failed: {response.status_code}")
            return {}
            
    except Exception as e:
        print(f"Error generating test cases: {e}")
        return {}

def analyze_rule_performance(rule_file: Path, test_cases: Dict[str, List[str]]) -> Dict[str, Any]:
    """Test the rule against all test cases and analyze performance."""
    
    results = {
        "true_positives": {"expected": 0, "detected": 0, "missed": [], "details": []},
        "true_negatives": {"expected": 0, "passed": 0, "false_alarms": [], "details": []},
        "potential_false_positives": {"cases": 0, "triggered": 0, "examples": [], "details": []},
        "potential_false_negatives": {"cases": 0, "missed": 0, "examples": [], "details": []}
    }
    
    # Test true positives (should be detected)
    for i, code in enumerate(test_cases.get("true_positives", [])):
        has_findings, count, output = run_semgrep_on_code(rule_file, code)
        results["true_positives"]["expected"] += 1
        
        if has_findings:
            results["true_positives"]["detected"] += 1
        else:
            results["true_positives"]["missed"].append(f"TP_{i+1}")
            
        results["true_positives"]["details"].append({
            "case": f"TP_{i+1}",
            "detected": has_findings,
            "count": count,
            "code_snippet": code[:200] + "..." if len(code) > 200 else code
        })
    
    # Test true negatives (should NOT be detected)  
    for i, code in enumerate(test_cases.get("true_negatives", [])):
        has_findings, count, output = run_semgrep_on_code(rule_file, code)
        results["true_negatives"]["expected"] += 1
        
        if not has_findings:
            results["true_negatives"]["passed"] += 1
        else:
            results["true_negatives"]["false_alarms"].append(f"TN_{i+1}")
            
        results["true_negatives"]["details"].append({
            "case": f"TN_{i+1}",
            "clean": not has_findings,
            "count": count,
            "code_snippet": code[:200] + "..." if len(code) > 200 else code
        })
    
    # Test potential false positives
    for i, code in enumerate(test_cases.get("potential_false_positives", [])):
        has_findings, count, output = run_semgrep_on_code(rule_file, code)
        results["potential_false_positives"]["cases"] += 1
        
        if has_findings:
            results["potential_false_positives"]["triggered"] += 1
            results["potential_false_positives"]["examples"].append(f"PFP_{i+1}")
            
        results["potential_false_positives"]["details"].append({
            "case": f"PFP_{i+1}",
            "triggered": has_findings,
            "count": count,
            "code_snippet": code[:200] + "..." if len(code) > 200 else code
        })
    
    # Test potential false negatives
    for i, code in enumerate(test_cases.get("potential_false_negatives", [])):
        has_findings, count, output = run_semgrep_on_code(rule_file, code)
        results["potential_false_negatives"]["cases"] += 1
        
        if not has_findings:
            results["potential_false_negatives"]["missed"] += 1
            results["potential_false_negatives"]["examples"].append(f"PFN_{i+1}")
            
        results["potential_false_negatives"]["details"].append({
            "case": f"PFN_{i+1}",
            "missed": not has_findings,
            "count": count,
            "code_snippet": code[:200] + "..." if len(code) > 200 else code
        })
    
    return results

def generate_rule_improvements(rule_content: str, performance_analysis: Dict[str, Any], 
                             test_cases: Dict[str, List[str]], vuln_id: str, 
                             validation_errors: str = "", 
                             model: str = "qwen2.5-coder:7b") -> str:
    """Use LLM to generate improved rule based on performance analysis."""
    
    # Collect problematic cases
    issues = []
    
    # False negatives (missed true positives)
    for detail in performance_analysis["true_positives"]["details"]:
        if not detail["detected"]:
            issues.append(f"MISSED VULNERABILITY ({detail['case']}): {detail['code_snippet']}")
    
    # False positives (triggered on safe code)
    for detail in performance_analysis["true_negatives"]["details"]:
        if not detail["clean"]:
            issues.append(f"FALSE POSITIVE ({detail['case']}): {detail['code_snippet']}")
            
    # Additional false positives from potential cases
    for detail in performance_analysis["potential_false_positives"]["details"]:
        if detail["triggered"]:
            issues.append(f"POTENTIAL FALSE POSITIVE ({detail['case']}): {detail['code_snippet']}")
    
    if not issues and not validation_errors:
        return rule_content  # Rule is already good
    
    validation_section = ""
    if validation_errors:
        validation_section = f"""
SEMGREP VALIDATION ERRORS:
{validation_errors}

CRITICAL: Fix all syntax errors first before addressing performance issues.
"""

    prompt = f"""You are a semgrep rule expert. Fix this rule based on validation and performance analysis.

**SYNTAX ERROR FIXING PRIORITY:**
1. **REMOVE ALL COMMENTS IMMEDIATELY** - Delete any # or // comments from pattern blocks
2. **Fix Go syntax errors** - ensure all patterns are valid Go code
3. **Proper indentation** - use consistent 2 or 4 space indentation
4. **Complete code blocks** - no incomplete patterns or placeholder comments
5. **Valid metavariables** - all UPPERCASE ($VAR not $var)
6. **Then address performance issues**

VULNERABILITY: {vuln_id}

CURRENT RULE:
```yaml
{rule_content}
```
{validation_section}
PERFORMANCE ISSUES FOUND:
{chr(10).join(issues[:10])}  # Limit to first 10 issues

ANALYSIS SUMMARY:
- True Positives: {performance_analysis['true_positives']['detected']}/{performance_analysis['true_positives']['expected']} detected
- True Negatives: {performance_analysis['true_negatives']['passed']}/{performance_analysis['true_negatives']['expected']} clean
- False Positives: {len(performance_analysis['true_negatives']['false_alarms'])} cases
- Missed Vulnerabilities: {len(performance_analysis['true_positives']['missed'])} cases

INSTRUCTIONS:
1. **Fix Syntax Errors**: Address any semgrep validation errors first (metavariables must be uppercase, valid Go syntax)
2. **Fix False Negatives**: Broaden patterns to catch missed vulnerabilities
3. **Fix False Positives**: Add more pattern-not-inside clauses to whitelist safe code
4. **Improve Precision**: Make patterns more specific where needed
5. **Validate Logic**: Ensure pattern-not-inside clauses work correctly

CRITICAL SEMGREP SYNTAX RULES:
- **METAVARIABLES MUST BE ALL UPPERCASE**: Use $VOTES not $votes, $RESULT not $result, $OBJECT not $obj
- **Examples of CORRECT metavariables**: $VAR, $VOTES, $RESULT, $OBJECT, $METHOD, $FIELD
- **Examples of INCORRECT metavariables**: $var, $votes, $result, $obj, $method, $field

**GO SYNTAX REQUIREMENTS (CRITICAL):**
- **Proper indentation**: Each nested level must be indented with 2 or 4 spaces
- **Complete code blocks**: All opening braces must have matching closing braces
- **Valid Go statements**: Each line must be syntactically correct Go
- **No incomplete patterns**: Avoid placeholder comments like '// ... rest of function' - use complete, valid Go code
- **ABSOLUTELY NO COMMENTS**: Never include ANY comments (# or //) inside pattern blocks - they cause syntax errors
- **PURE GO CODE ONLY**: Pattern blocks must contain ONLY valid Go code with no explanatory text
- **Test each pattern**: Every pattern must be valid Go that could compile

**CORRECT Go Pattern Example:**
- Proper indentation (4 spaces per level)
- Complete code blocks with matching braces
- Valid Go syntax throughout

**INCORRECT Go Pattern Example:**
- Missing indentation
- Incomplete code with placeholder comments
- Invalid Go syntax

REQUIREMENTS:
- Keep the rule ID and basic structure
- Fix syntax errors as highest priority
- Focus on the specific issues identified
- Add comprehensive pattern-not-inside for false positives
- Generalize patterns slightly for false negatives
- Ensure syntactically valid semgrep YAML

Return the improved rule in YAML format only:"""

    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Low temperature for precise fixes
                    "top_p": 0.7,
                    "num_ctx": 20480
                }
            },
            timeout=600  # Increased from 300 to 600 seconds
        )
        
        if response.status_code == 200:
            result = response.json()
            generated_text = result.get('response', '')
            
            # Extract YAML from response
            yaml_start = generated_text.find('rules:')
            if yaml_start == -1:
                yaml_start = generated_text.find('- id:')
            
            if yaml_start != -1:
                # Try to extract clean YAML
                lines = generated_text[yaml_start:].split('\n')
                yaml_lines = []
                for line in lines:
                    if line.strip() and not line.startswith('```'):
                        yaml_lines.append(line)
                    elif line.startswith('```') and yaml_lines:
                        break
                
                improved_yaml = '\n'.join(yaml_lines)
                
                # Validate YAML
                try:
                    yaml.safe_load(improved_yaml)
                    return improved_yaml
                except yaml.YAMLError:
                    print("Generated YAML is invalid, returning original rule")
                    return rule_content
            else:
                print("Could not extract YAML from improvement response")
                return rule_content
                
        else:
            print(f"Rule improvement request failed: {response.status_code}")
            return rule_content
            
    except Exception as e:
        print(f"Error generating rule improvements: {e}")
        return rule_content

def generate_refined_rule(vuln_id, input_dir, model="qwen2.5-coder:7b", max_iterations=1, quality_tracker=None):
    """Generate a comprehensive rule with iterative refinement."""
    
    vuln_dir = Path(input_dir) / vuln_id
    
    # Load data
    metadata_file = vuln_dir / "metadata.json"
    if not metadata_file.exists():
        print(f"No metadata found for {vuln_id}")
        return None, None
        
    with open(metadata_file, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    
    # Load code examples  
    bad_file = vuln_dir / f"{vuln_id}_bad.go"
    good_file = vuln_dir / f"{vuln_id}_good.go"
    
    bad_code = ""
    good_code = ""
    
    if bad_file.exists():
        with open(bad_file, 'r', encoding='utf-8') as f:
            bad_code = f.read()
    
    if good_file.exists():
        with open(good_file, 'r', encoding='utf-8') as f:
            good_code = f.read()
    
    diff_file = vuln_dir / "raw_diff.patch"
    diff_content = ""
    if diff_file.exists():
        with open(diff_file, 'r', encoding='utf-8') as f:
            diff_content = f.read()
    
    # Generate initial rule
    prompt = build_comprehensive_low_fp_prompt(vuln_id, metadata, bad_code, good_code, diff_content)
    
    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.02,  # Very low for consistency
                    "top_p": 0.6,         
                    "num_ctx": 20480,     
                    "repeat_penalty": 1.1
                }
            },
            timeout=600  # Increased from 300 to 600 seconds
        )
        
        if response.status_code != 200:
            print(f"Initial rule generation failed for {vuln_id}: {response.status_code}")
            return None, None
            
        result = response.json()
        generated_text = result.get('response', '')
        
        # Extract YAML
        yaml_start = generated_text.find('```yaml')
        yaml_end = generated_text.find('```', yaml_start + 7)
        
        if yaml_start != -1 and yaml_end != -1:
            current_rule_content = generated_text[yaml_start + 7:yaml_end].strip()
        else:
            current_rule_content = generated_text.strip()
        
        # Remove comments from rule if present
        cleaned_rule, was_modified = remove_comments_from_rule(current_rule_content)
        if was_modified:
            print(f"    Automatically removed comments from rule")
            current_rule_content = cleaned_rule
        
        # Validate initial YAML
        try:
            yaml.safe_load(current_rule_content)
        except yaml.YAMLError as e:
            print(f"Initial YAML validation failed for {vuln_id}: {e}")
            return None, None
            
    except Exception as e:
        print(f"Error generating initial rule for {vuln_id}: {e}")
        return None, None
    
    # Iterative refinement
    best_score = 0
    best_rule = current_rule_content
    # Extract the actual summary from the nested structure
    vuln_description = metadata.get('vuln_json', {}).get('summary', 'Unknown vulnerability')
    if vuln_description == 'Unknown vulnerability':
        vuln_description = metadata.get('summary', 'Unknown vulnerability')
    
    for iteration in range(max_iterations):
        print(f"    Iteration {iteration + 1}/{max_iterations}")
        
        # Create temporary rule file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False, encoding='utf-8') as f:
            f.write(current_rule_content)
            temp_rule_file = Path(f.name)
        
        try:
            # Validate rule syntax first
            print(f"      Validating rule syntax...")
            is_valid, validation_message = validate_semgrep_rule(temp_rule_file)
            if not is_valid:
                print(f"      Syntax validation failed: {validation_message}")
            
            # Generate test cases
            print(f"      Generating test cases...")
            test_cases = generate_test_cases(vuln_id, current_rule_content, vuln_description, 
                                           bad_code, good_code, model)
            
            if not test_cases:
                print(f"      Failed to generate test cases")
                os.unlink(temp_rule_file)
                break
            
            # Analyze performance (only if rule is syntactically valid)
            if is_valid:
                print(f"      Testing rule performance...")
                performance = analyze_rule_performance(temp_rule_file, test_cases)
                
                # Calculate score
                tp_rate = performance["true_positives"]["detected"] / max(1, performance["true_positives"]["expected"])
                tn_rate = performance["true_negatives"]["passed"] / max(1, performance["true_negatives"]["expected"])
                score = (tp_rate + tn_rate) / 2
                
                print(f"      Score: {score:.2f} (TP: {tp_rate:.2f}, TN: {tn_rate:.2f})")
                
                # Track quality metrics
                if quality_tracker:
                    iteration_start_time = time.time() if 'iteration_start_time' in locals() else time.time()
                    quality_tracker.record_iteration(vuln_id, iteration + 1, {
                        'score': score,
                        'tp_rate': tp_rate,
                        'tn_rate': tn_rate,
                        'syntax_valid': is_valid,
                        'validation_errors': [validation_message] if not is_valid else [],
                        'false_positives': performance["true_negatives"]["expected"] - performance["true_negatives"]["passed"],
                        'false_negatives': performance["true_positives"]["expected"] - performance["true_positives"]["detected"],
                        'pattern_complexity': len(current_rule_content.split('pattern')),
                        'message_quality': 'educational' if any(word in current_rule_content.lower() for word in ['vulnerability', 'security', 'add', 'use', 'ensure']) else 'generic',
                        'processing_time': time.time() - iteration_start_time
                    })
                
                # Check if this is the best so far
                if score > best_score:
                    best_score = score
                    best_rule = current_rule_content
                    print(f"      New best score: {best_score:.2f}")
            else:
                # Give poor score for invalid rules
                performance = {
                    "true_positives": {"detected": 0, "expected": 1, "missed": [], "details": []},
                    "true_negatives": {"passed": 0, "expected": 1, "false_alarms": [], "details": []},
                    "potential_false_positives": {"details": []},
                    "potential_false_negatives": {"details": []}
                }
                score = 0.0
                print(f"      Score: 0.00 (syntax invalid)")
                
                # Track quality metrics for invalid rules
                if quality_tracker:
                    iteration_start_time = time.time() if 'iteration_start_time' in locals() else time.time()
                    quality_tracker.record_iteration(vuln_id, iteration + 1, {
                        'score': 0.0,
                        'tp_rate': 0.0,
                        'tn_rate': 0.0,
                        'syntax_valid': False,
                        'validation_errors': [validation_message],
                        'false_positives': 0,
                        'false_negatives': 0,
                        'pattern_complexity': 0,
                        'message_quality': 'generic',
                        'processing_time': time.time() - iteration_start_time
                    })
            
            # Generate improvements for next iteration
            if iteration < max_iterations - 1:  # Don't improve on last iteration
                print(f"      Generating improvements...")
                validation_errors = "" if is_valid else validation_message
                improved_rule = generate_rule_improvements(current_rule_content, performance, 
                                                         test_cases, vuln_id, validation_errors, model)
                
                if improved_rule != current_rule_content:
                    # Remove comments from improved rule
                    cleaned_improved, was_modified = remove_comments_from_rule(improved_rule)
                    if was_modified:
                        print(f"      Automatically cleaned comments from improved rule")
                    current_rule_content = cleaned_improved
                    print(f"      Rule improved")
                else:
                    print(f"      No improvements generated")
                    break
            
        except Exception as e:
            print(f"      Error in iteration {iteration + 1}: {e}")
            
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_rule_file)
            except:
                pass
    
    print(f"    Final score: {best_score:.2f}")
    
    # Final comment cleanup
    final_cleaned_rule, was_modified = remove_comments_from_rule(best_rule)
    if was_modified:
        print(f"    Final comment cleanup applied")
        best_rule = final_cleaned_rule
    
    # Final validation check
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False, encoding='utf-8') as f:
        f.write(best_rule)
        final_temp_file = Path(f.name)
    
    try:
        is_valid, _ = validate_semgrep_rule(final_temp_file)
        if not is_valid:
            print(f"    WARNING: Final rule failed validation, adjusting score")
            best_score = 0.0
    finally:
        os.unlink(final_temp_file)
    
    # Finalize quality tracking for this rule
    if quality_tracker:
        quality_tracker.finalize_rule(vuln_id)
    
    return best_rule, best_score

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate refined semgrep rules')
    parser.add_argument('--input', default='./out', help='Input directory with vulnerability data')
    parser.add_argument('--output', default='./refined_batch_rules', help='Output directory for rules')
    parser.add_argument('--model', default='gemma3:4b', help='Model to use (gemma3:4b for GPU efficiency)')
    parser.add_argument('--only-with-examples', action='store_true', help='Only process vulns with examples')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--limit', type=int, help='Limit number of vulnerabilities to process')
    
    args = parser.parse_args()
    
    input_dir = args.input
    output_dir = args.output
    model = args.model
    
    # Create output directory
    Path(output_dir).mkdir(exist_ok=True)
    
    # Initialize quality tracker
    quality_tracker = RefinementQualityTracker("./refinement_reports")
    
    # Find vulnerabilities with code examples
    input_path = Path(input_dir)
    vuln_dirs = []
    
    for d in input_path.iterdir():
        if d.is_dir() and d.name.startswith("GO-"):
            # Check if has code examples
            bad_file = d / f"{d.name}_bad.go"
            good_file = d / f"{d.name}_good.go"
            if bad_file.exists() and good_file.exists():
                vuln_dirs.append(d.name)
    
    print(f"Found {len(vuln_dirs)} vulnerabilities with code examples")
    
    # Limit for testing if specified
    if args.limit:
        vuln_dirs = vuln_dirs[:args.limit]
        print(f"Limited to first {args.limit} vulnerabilities")
    
    generated = 0
    failed = 0
    total_score = 0
    
    for vuln_id in sorted(vuln_dirs):
        print(f"\nProcessing {vuln_id}...")
        
        # Check if already exists
        output_file = Path(output_dir) / f"{vuln_id}.yml"
        if output_file.exists():
            print(f"  Skipping - already exists")
            continue
        
        rule_content, score = generate_refined_rule(vuln_id, input_dir, model, quality_tracker=quality_tracker)
        
        if rule_content:
            # Save rule
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rule_content)
            print(f"  SUCCESS Generated: {output_file}")
            generated += 1
            total_score += score
        else:
            print(f"  FAILED Failed to generate rule")
            failed += 1
    
    print(f"\nIntegrated batch processing complete:")
    print(f"  Generated: {generated}")
    print(f"  Failed: {failed}")
    print(f"  Average Score: {total_score / generated if generated > 0 else 0:.2f}")
    
    # Generate and save quality report
    print(f"\nGenerating quality improvement report...")
    report = quality_tracker.generate_comprehensive_report()
    quality_tracker.print_summary_report(report)
    
    # Save detailed report
    report_path = Path("./refinement_reports") / f"batch_quality_report_{len(quality_tracker.histories)}_rules.json"
    report.save_report(report_path)
    print(f"Detailed quality report saved to: {report_path}")

if __name__ == "__main__":
    main()