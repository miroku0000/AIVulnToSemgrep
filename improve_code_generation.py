#!/usr/bin/env python3
"""
Improvements for better good/bad code generation in vuln2examples.py

This script contains improved prompts and processing functions
that can be integrated into the main tool.
"""

import json
import re
import requests
from typing import Optional


def improved_ollama_generate(prompt: str, model: str, url: str, seed: Optional[int], max_tokens: int = 2048) -> str:
    """Improved Ollama generation with longer timeout and better error handling."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 8192,
            "temperature": 0.3,  # Lower temperature for more consistent output
            "top_p": 0.9,
        },
    }
    if seed is not None:
        payload["options"]["seed"] = int(seed)
    
    # Increased timeout to 5 minutes
    r = requests.post(f"{url.rstrip('/')}/api/generate", json=payload, timeout=300)
    r.raise_for_status()
    return r.json().get("response", "")


def build_improved_llm_prompt(go_id: str, cve: Optional[str], module: str, summary: str, diff_text: str) -> str:
    """Improved prompt that's more focused and easier for the LLM to process."""
    
    # More aggressive diff trimming for faster processing
    trimmed_diff = diff_text
    if len(trimmed_diff) > 50_000:  # Reduced from 150k
        trimmed_diff = trimmed_diff[:50_000] + "\n... [TRUNCATED]"
    
    # Extract just the key parts of the diff
    diff_lines = trimmed_diff.split('\n')
    key_changes = []
    
    for line in diff_lines:
        if line.startswith('+') and not line.startswith('+++'):
            key_changes.append(line)
        elif line.startswith('-') and not line.startswith('---'):
            key_changes.append(line)
    
    # Limit to most important changes
    if len(key_changes) > 20:
        key_changes = key_changes[:20] + ["... [MORE CHANGES TRUNCATED]"]
    
    key_changes_text = '\n'.join(key_changes)
    
    return f"""You are analyzing a security vulnerability fix. Create minimal Go code examples.

VULNERABILITY INFO:
- ID: {go_id}
- CVE: {cve or "unknown"}  
- Module: {module}
- Issue: {summary[:200]}...

KEY CHANGES FROM DIFF:
{key_changes_text}

TASK: Create two minimal Go code snippets showing the vulnerability and fix.

REQUIREMENTS:
1. Make examples short and focused (5-15 lines each)
2. Show the core security issue clearly
3. Use simple, standalone functions when possible
4. Focus on the actual code change pattern

OUTPUT FORMAT - Respond with valid JSON only:
{{
  "rationale": "Brief explanation of the security issue and fix",
  "bad_example": "func vulnerable() {{\\n  // vulnerable code here\\n}}",
  "good_example": "func secure() {{\\n  // fixed code here\\n}}"
}}

NO MARKDOWN, NO BACKTICKS, NO EXTRA TEXT - JUST JSON."""


def extract_code_from_response(response: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Improved code extraction with multiple fallback strategies."""
    
    # Strategy 1: Try to parse as JSON directly
    try:
        data = json.loads(response)
        return (
            data.get("rationale", ""),
            data.get("bad_example", ""),
            data.get("good_example", "")
        )
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Extract JSON from response
    json_match = re.search(r'\{[^{}]*"rationale"[^{}]*\}', response, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            return (
                data.get("rationale", ""),
                data.get("bad_example", ""),
                data.get("good_example", "")
            )
        except json.JSONDecodeError:
            pass
    
    # Strategy 3: Extract individual fields with regex
    rationale_match = re.search(r'"rationale":\s*"([^"]*)"', response)
    bad_match = re.search(r'"bad_example":\s*"([^"]*)"', response)
    good_match = re.search(r'"good_example":\s*"([^"]*)"', response)
    
    rationale = rationale_match.group(1) if rationale_match else ""
    bad_code = bad_match.group(1) if bad_match else ""
    good_code = good_match.group(1) if good_match else ""
    
    # Decode escaped newlines
    bad_code = bad_code.replace('\\n', '\n').replace('\\"', '"')
    good_code = good_code.replace('\\n', '\n').replace('\\"', '"')
    
    return rationale, bad_code, good_code


def build_simplified_prompt(go_id: str, summary: str, diff_text: str) -> str:
    """Ultra-simplified prompt for faster processing."""
    
    # Extract just added lines (the fix)
    added_lines = []
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            added_lines.append(line[1:].strip())  # Remove + prefix
    
    # Take first few important additions
    key_additions = added_lines[:10]
    
    return f"""Vulnerability {go_id}: {summary[:100]}

The fix added these lines:
{chr(10).join(key_additions)}

Create JSON with bad_example and good_example showing the vulnerability and fix:
{{"bad_example": "// vulnerable code", "good_example": "// fixed code"}}"""


def process_vulnerable_diff_retry(go_id: str, cve: Optional[str], module: str, summary: str, 
                                 diff_text: str, model: str, ollama_url: str, seed: Optional[int]) -> Optional[dict]:
    """Process with multiple retry strategies for better success rate."""
    
    strategies = [
        ("full", build_improved_llm_prompt),
        ("simple", lambda gid, c, m, s, d: build_simplified_prompt(gid, s, d)),
    ]
    
    for strategy_name, prompt_func in strategies:
        print(f"Trying {strategy_name} strategy for {go_id}...")
        
        try:
            if strategy_name == "simple":
                prompt = prompt_func(go_id, summary, diff_text)
            else:
                prompt = prompt_func(go_id, cve, module, summary, diff_text)
            
            response = improved_ollama_generate(prompt, model, ollama_url, seed, max_tokens=1024)
            
            rationale, bad_code, good_code = extract_code_from_response(response)
            
            if bad_code and good_code:
                return {
                    "rationale": rationale,
                    "bad_example": bad_code,
                    "good_example": good_code,
                    "strategy_used": strategy_name
                }
        except Exception as e:
            print(f"Strategy {strategy_name} failed: {e}")
            continue
    
    return None


# Test function
def test_improved_processing():
    """Test the improved processing on the failed vulnerability."""
    
    # Test data from GO-2025-3832
    go_id = "GO-2025-3832"
    cve = "CVE-2021-21411"
    module = "github.com/oauth2-proxy/oauth2-proxy"
    summary = "OAuth2-Proxy's --gitlab-group GitLab Group Authorization config flag stopped working"
    
    # Sample diff content (simplified)
    diff_text = """
-	p.addGroupsToSession(ctx, s)
+	for _, group := range userInfo.Groups {
+		s.Groups = append(s.Groups, fmt.Sprintf("group:%s", group))
+	}
"""
    
    model = "llama3.2:3b"  # Try with smaller, faster model
    ollama_url = "http://127.0.0.1:11434"
    seed = 42
    
    result = process_vulnerable_diff_retry(go_id, cve, module, summary, diff_text, model, ollama_url, seed)
    
    if result:
        print("✅ SUCCESS!")
        print(f"Strategy: {result['strategy_used']}")
        print(f"Rationale: {result['rationale']}")
        print(f"Bad code: {result['bad_example']}")
        print(f"Good code: {result['good_example']}")
    else:
        print("❌ All strategies failed")


if __name__ == "__main__":
    test_improved_processing()