#!/usr/bin/env python3
"""
Final improved vulnerability processing that handles the backtick issue.
"""

import json
import re
import requests
from pathlib import Path

def clean_json_response(response: str) -> str:
    """Clean up LLM response to make it valid JSON."""
    
    # Replace backticks with escaped quotes in JSON context
    # This handles the case where LLM uses backticks for code blocks within JSON
    
    # Pattern: "key": `code here`
    response = re.sub(r'("bad_example":\s*)`([^`]*)`', r'\1"\2"', response)
    response = re.sub(r'("good_example":\s*)`([^`]*)`', r'\1"\2"', response)
    
    # Escape newlines in the extracted content
    def escape_content(match):
        key = match.group(1)
        content = match.group(2)
        # Escape newlines and quotes
        content = content.replace('\n', '\\n').replace('"', '\\"')
        return f'{key}"{content}"'
    
    response = re.sub(r'("(?:bad|good)_example":\s*)"([^"]*(?:\\.[^"]*)*)"', escape_content, response)
    
    return response

def extract_json_with_fallbacks(response: str) -> dict:
    """Extract JSON with multiple fallback strategies."""
    
    # Strategy 1: Clean and parse
    try:
        cleaned = clean_json_response(response)
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    
    # Strategy 2: Extract with regex
    rationale_match = re.search(r'"rationale":\s*"([^"]*)"', response)
    
    # For code examples, extract everything between backticks or quotes
    bad_match = re.search(r'"bad_example":\s*[`"]([^`"]*)[`"]', response, re.DOTALL)
    good_match = re.search(r'"good_example":\s*[`"]([^`"]*)[`"]', response, re.DOTALL)
    
    if bad_match and good_match:
        return {
            "rationale": rationale_match.group(1) if rationale_match else "",
            "bad_example": bad_match.group(1).strip(),
            "good_example": good_match.group(1).strip()
        }
    
    # Strategy 3: More flexible extraction
    # Look for patterns like: bad_example followed by code
    bad_code = ""
    good_code = ""
    
    # Split by lines and look for patterns
    lines = response.split('\n')
    in_bad = False
    in_good = False
    
    for line in lines:
        if 'bad_example' in line.lower():
            in_bad = True
            in_good = False
            # Extract any code on the same line
            code_match = re.search(r'[`"](.*?)[`"]', line)
            if code_match:
                bad_code = code_match.group(1)
        elif 'good_example' in line.lower():
            in_good = True
            in_bad = False
            # Extract any code on the same line
            code_match = re.search(r'[`"](.*?)[`"]', line)
            if code_match:
                good_code = code_match.group(1)
        elif in_bad and line.strip():
            # Accumulate bad code
            bad_code += line.strip() + '\n'
        elif in_good and line.strip():
            # Accumulate good code
            good_code += line.strip() + '\n'
    
    if bad_code and good_code:
        return {
            "rationale": rationale_match.group(1) if rationale_match else "Code authorization fix",
            "bad_example": bad_code.strip(),
            "good_example": good_code.strip()
        }
    
    return {}

def test_final_improved():
    """Test the final improved version."""
    
    # Test with the actual response from previous test
    test_response = """{
  "rationale": "The vulnerability allows unauthorized users to access projects by manipulating the group authorization.",
  "bad_example": `
func (p *GitLabProvider) addGroupsToSession(ctx context.Context, s *sessions.SessionState) {
    for _, group := range p.Groups {
        s.Groups = append(s.Groups, fmt.Sprintf("group:%s", group))
    }
}`,
  "good_example": `
func (p *GitLabProvider) addGroupsToSession(ctx context.Context, s *sessions.SessionState) {
    for _, group := range userInfo.Groups {
        s.Groups = append(s.Groups, fmt.Sprintf("group:%s", group))
    }
}
`
}"""
    
    print("Testing JSON extraction on problematic response...")
    
    result = extract_json_with_fallbacks(test_response)
    
    if result and result.get("bad_example") and result.get("good_example"):
        print("SUCCESS! Extracted:")
        print(f"Rationale: {result['rationale']}")
        print(f"Bad example ({len(result['bad_example'])} chars):")
        print(result['bad_example'])
        print(f"Good example ({len(result['good_example'])} chars):")
        print(result['good_example'])
        return True
    else:
        print("FAILED to extract valid data")
        return False

def create_improved_prompt_v2():
    """Create an even better prompt that avoids backticks."""
    
    return """Analyze this Go security vulnerability fix.

VULNERABILITY: GitLab group authorization bypass - groups not properly populated from userinfo

KEY CHANGES:
- p.addGroupsToSession(ctx, s)
+ for _, group := range userInfo.Groups {
+     s.Groups = append(s.Groups, fmt.Sprintf("group:%s", group))
+ }

Create JSON response with Go code examples. IMPORTANT: Use double quotes for code, NOT backticks.

{
  "rationale": "brief explanation here",
  "bad_example": "func bad() { /* old vulnerable code */ }",
  "good_example": "func good() { /* new secure code */ }"
}

Response:"""

if __name__ == "__main__":
    print("=== Testing JSON extraction ===")
    success = test_final_improved()
    
    print(f"\n=== Testing improved prompt ===")
    prompt = create_improved_prompt_v2()
    print(f"Prompt length: {len(prompt)} chars")
    print("Prompt does not contain backticks:", '`' not in prompt)
    
    print(f"\nOverall test: {'PASSED' if success else 'FAILED'}")