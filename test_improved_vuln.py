#!/usr/bin/env python3
"""
Test improved vulnerability processing on a real example that failed.
"""

import json
import requests
from pathlib import Path

def ollama_generate_improved(prompt: str, model: str = "llama3.2:3b", url: str = "http://127.0.0.1:11434") -> str:
    """Improved Ollama call with faster model and better settings."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 8192,
            "temperature": 0.3,
            "top_p": 0.9,
        },
    }
    
    r = requests.post(f"{url.rstrip('/')}/api/generate", json=payload, timeout=300)
    r.raise_for_status()
    return r.json().get("response", "")

def test_real_vulnerability():
    """Test with GO-2025-3832 data."""
    
    # Read the actual diff
    diff_file = Path("./out/GO-2025-3832/raw_diff.patch")
    if not diff_file.exists():
        print("Diff file not found")
        return False
    
    with open(diff_file, 'r', encoding='utf-8') as f:
        diff_content = f.read()
    
    # Read metadata for context
    metadata_file = Path("./out/GO-2025-3832/metadata.json")
    with open(metadata_file, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    
    go_id = metadata["go_id"]
    summary = metadata["vuln_json"]["summary"]
    cve = metadata["vuln_json"]["aliases"][0] if metadata["vuln_json"]["aliases"] else "unknown"
    
    # Build improved prompt
    # Extract key changes only
    key_changes = []
    for line in diff_content.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            key_changes.append(line)
        elif line.startswith('-') and not line.startswith('---'):
            key_changes.append(line)
    
    key_changes_text = '\n'.join(key_changes[:15])  # First 15 changes
    
    prompt = f"""Analyze this security vulnerability fix and create minimal Go code examples.

VULNERABILITY:
- ID: {go_id}
- CVE: {cve}
- Issue: GitLab group authorization bypass

KEY CODE CHANGES:
{key_changes_text}

Create JSON with minimal Go code showing vulnerable vs fixed versions:

{{
  "rationale": "explain the security issue in one sentence",
  "bad_example": "func vulnerable() {{ /* code */ }}",
  "good_example": "func secure() {{ /* code */ }}"
}}

Respond with JSON only."""
    
    print(f"Testing with prompt length: {len(prompt)} chars")
    print("Calling Ollama...")
    
    try:
        response = ollama_generate_improved(prompt, model="llama3.2:3b")
        print(f"Response length: {len(response)} chars")
        print("Raw response:")
        print(response)
        
        # Try to parse JSON
        try:
            data = json.loads(response)
            print("\n=== PARSED SUCCESSFULLY ===")
            print(f"Rationale: {data.get('rationale', 'N/A')}")
            print(f"Bad example: {data.get('bad_example', 'N/A')}")
            print(f"Good example: {data.get('good_example', 'N/A')}")
            return True
        except json.JSONDecodeError as e:
            print(f"JSON parsing failed: {e}")
            return False
            
    except Exception as e:
        print(f"Ollama call failed: {e}")
        return False

if __name__ == "__main__":
    success = test_real_vulnerability()
    print(f"\nTest {'PASSED' if success else 'FAILED'}")