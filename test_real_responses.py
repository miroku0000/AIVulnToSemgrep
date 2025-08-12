#!/usr/bin/env python3
"""
Test the JSON preprocessor with real failing LLM responses.
"""

from json_preprocessor import extract_json_with_fallbacks
from pathlib import Path

def test_real_llm_responses():
    """Test with actual LLM responses that failed."""
    
    failing_files = [
        "./out/GO-2025-3857/llm_raw.txt",
        "./out/GO-2025-3859/llm_raw.txt", 
        "./out/GO-2025-3856/llm_raw.txt"
    ]
    
    print("=== Testing Real LLM Responses ===\n")
    
    for file_path in failing_files:
        if not Path(file_path).exists():
            print(f"File not found: {file_path}")
            continue
            
        print(f"Testing: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            response = f.read()
        
        print(f"Original length: {len(response)} chars")
        
        result = extract_json_with_fallbacks(response)
        
        if result and result.get('bad_example') and result.get('good_example'):
            print("SUCCESS - Extracted valid JSON")
            print(f"Rationale: {result.get('rationale', 'N/A')[:100]}...")
            print(f"Bad example: {len(result['bad_example'])} chars")
            print(f"Good example: {len(result['good_example'])} chars")
            
            # Show first few lines of extracted code
            bad_lines = result['bad_example'].split('\n')[:3]
            good_lines = result['good_example'].split('\n')[:3]
            print(f"Bad preview: {bad_lines}")
            print(f"Good preview: {good_lines}")
        else:
            print("FAILED - Could not extract valid data")
            if result:
                print(f"Partial result: {list(result.keys())}")
        
        print("-" * 70)

if __name__ == "__main__":
    test_real_llm_responses()