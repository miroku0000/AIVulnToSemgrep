#!/usr/bin/env python3
"""
JSON preprocessing to fix common LLM response formatting issues.
"""

import json
import re
from typing import Dict, Any, Optional

def preprocess_llm_json(response: str) -> str:
    """
    Fix common JSON formatting issues in LLM responses.
    
    Common issues:
    1. Backticks in JSON strings: "bad_example": ```code``` 
    2. Unescaped newlines in multiline strings
    3. Missing quotes around code blocks
    4. Truncated JSON responses
    """
    
    # Remove any leading/trailing whitespace and markdown formatting
    response = response.strip()
    
    # Remove markdown code block wrappers if present
    if response.startswith('```json'):
        response = response[7:]  # Remove ```json
    if response.startswith('```'):
        response = response[3:]   # Remove ```
    if response.endswith('```'):
        response = response[:-3]  # Remove trailing ```
    
    response = response.strip()
    
    # Fix backticks in JSON string values
    # Pattern: "key": ```content```  -> "key": "content"
    response = re.sub(
        r'("[^"]*"):\s*```([^`]*)```',
        lambda m: f'{m.group(1)}: "{escape_for_json(m.group(2))}"',
        response,
        flags=re.DOTALL
    )
    
    # Fix backticks with language specifiers
    # Pattern: "key": ```go\ncode\n```  -> "key": "code"
    response = re.sub(
        r'("[^"]*"):\s*```\w*\n([^`]*)```',
        lambda m: f'{m.group(1)}: "{escape_for_json(m.group(2))}"',
        response,
        flags=re.DOTALL
    )
    
    # Fix unquoted backtick blocks
    # Pattern: "key": `content`  -> "key": "content"
    response = re.sub(
        r'("[^"]*"):\s*`([^`]*)`',
        lambda m: f'{m.group(1)}: "{escape_for_json(m.group(2))}"',
        response
    )
    
    # Fix missing closing braces if JSON appears truncated
    if not response.rstrip().endswith('}'):
        # Count opening vs closing braces
        open_braces = response.count('{')
        close_braces = response.count('}')
        if open_braces > close_braces:
            response += '}' * (open_braces - close_braces)
    
    # Fix missing commas between key-value pairs
    # Look for pattern: "value"\n  "key": 
    response = re.sub(
        r'("\s*)\n\s*("[\w_]+":)',
        r'\1,\n  \2',
        response
    )
    
    return response

def escape_for_json(content: str) -> str:
    """Escape content for inclusion in JSON string."""
    content = content.strip()
    # Escape quotes and backslashes
    content = content.replace('\\', '\\\\')
    content = content.replace('"', '\\"')
    # Escape newlines
    content = content.replace('\n', '\\n')
    content = content.replace('\r', '\\r')
    content = content.replace('\t', '\\t')
    return content

def extract_json_with_fallbacks(response: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON from LLM response with multiple fallback strategies.
    """
    
    # Strategy 1: Preprocess and parse normally
    try:
        preprocessed = preprocess_llm_json(response)
        return json.loads(preprocessed)
    except (json.JSONDecodeError, Exception):
        pass
    
    # Strategy 2: Extract with regex patterns
    result = {}
    
    # Extract rationale
    rationale_match = re.search(r'"rationale":\s*"([^"]*)"', response)
    if rationale_match:
        result['rationale'] = rationale_match.group(1)
    
    # Extract code examples with multiple patterns
    # Pattern 1: "bad_example": "code"
    bad_match = re.search(r'"bad_example":\s*"([^"]*)"', response, re.DOTALL)
    if not bad_match:
        # Pattern 2: "bad_example": ```code```
        bad_match = re.search(r'"bad_example":\s*```[^`]*?([^`]*)```', response, re.DOTALL)
    if not bad_match:
        # Pattern 3: "bad_example": `code`
        bad_match = re.search(r'"bad_example":\s*`([^`]*)`', response, re.DOTALL)
    
    good_match = re.search(r'"good_example":\s*"([^"]*)"', response, re.DOTALL)
    if not good_match:
        good_match = re.search(r'"good_example":\s*```[^`]*?([^`]*)```', response, re.DOTALL)
    if not good_match:
        good_match = re.search(r'"good_example":\s*`([^`]*)`', response, re.DOTALL)
    
    if bad_match:
        result['bad_example'] = bad_match.group(1).strip()
    if good_match:
        result['good_example'] = good_match.group(1).strip()
    
    # Strategy 3: Line-by-line extraction for very malformed responses
    if not result.get('bad_example') or not result.get('good_example'):
        lines = response.split('\n')
        current_section = None
        current_code = []
        
        for line in lines:
            line = line.strip()
            if 'bad_example' in line.lower():
                if current_section == 'bad' and current_code:
                    result['bad_example'] = '\n'.join(current_code)
                current_section = 'bad'
                current_code = []
                # Check if code is on the same line
                code_match = re.search(r'[`"](.*?)[`"]', line)
                if code_match:
                    current_code.append(code_match.group(1))
            elif 'good_example' in line.lower():
                if current_section == 'bad' and current_code:
                    result['bad_example'] = '\n'.join(current_code)
                current_section = 'good'
                current_code = []
                code_match = re.search(r'[`"](.*?)[`"]', line)
                if code_match:
                    current_code.append(code_match.group(1))
            elif current_section and line and not line.startswith('"') and not line.startswith('}'):
                # Remove common prefixes
                line = re.sub(r'^[`"]*', '', line)
                line = re.sub(r'[`"]*$', '', line)
                if line:
                    current_code.append(line)
        
        # Save final section
        if current_section == 'good' and current_code:
            result['good_example'] = '\n'.join(current_code)
        elif current_section == 'bad' and current_code:
            result['bad_example'] = '\n'.join(current_code)
    
    return result if result else None

def test_preprocessor():
    """Test the preprocessor with real examples."""
    
    # Test case 1: GO-2025-3857 example
    test1 = """{
  "rationale": "The fix involves changing the policy names before comparing.",
  "bad_example": ```
func (i *IdentityStore) handleEntityUpdateCommon() {
    entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
}
```
  "good_example": ```
func (i *IdentityStore) handleEntityUpdateCommon() {
    entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), true)
}
```"""
    
    # Test case 2: GO-2025-3859 example  
    test2 = """{
  "rationale": "The fix adds userLockoutInfo parameter.",
  "bad_example": "```go
func LoginCreateToken(ctx context.Context) error {
    // old code
}
```
",
  "good_example": "```go
func LoginCreateToken(ctx context.Context, userLockoutInfo *FailedLoginUser) error {
    // new code
}
```"""
    
    print("=== Testing JSON Preprocessor ===\n")
    
    for i, test_case in enumerate([test1, test2], 1):
        print(f"Test Case {i}:")
        print(f"Original length: {len(test_case)} chars")
        
        result = extract_json_with_fallbacks(test_case)
        
        if result and result.get('bad_example') and result.get('good_example'):
            print("SUCCESS - Extracted valid JSON")
            print(f"Rationale: {result.get('rationale', 'N/A')}")
            print(f"Bad example: {len(result['bad_example'])} chars")
            print(f"Good example: {len(result['good_example'])} chars")
        else:
            print("FAILED - Could not extract valid data")
            
        print("-" * 50)

if __name__ == "__main__":
    test_preprocessor()