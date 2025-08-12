#!/usr/bin/env python3
"""
Test script for semgrep rule generation.
Tests the vuln2semgrep functionality with a single vulnerability.
"""

import sys
from pathlib import Path
import json

# Add the current directory to the path so we can import vuln2semgrep
sys.path.append(str(Path(__file__).parent))

from vuln2semgrep import read_vulnerability_data, generate_semgrep_rules, save_semgrep_rules

def test_single_vulnerability():
    """Test semgrep rule generation for GO-2025-3859."""
    
    # Configuration
    input_dir = Path("./out")
    output_dir = Path("./test_semgrep_rules")
    model = "qwen2.5-coder:14b"
    ollama_url = "http://127.0.0.1:11434"
    seed = 42
    debug = True
    
    # Find the vulnerability with code examples
    vuln_dir = input_dir / "GO-2025-3859"
    if not vuln_dir.exists():
        print("GO-2025-3859 directory not found")
        return False
    
    print(f"Testing semgrep rule generation for {vuln_dir.name}")
    
    # Read vulnerability data
    vuln_data = read_vulnerability_data(vuln_dir)
    if not vuln_data:
        print("Failed to read vulnerability data")
        return False
    
    print(f"Read vulnerability data: {vuln_data['go_id']}")
    print(f"Has bad code: {bool(vuln_data['bad_code'])}")
    print(f"Has good code: {bool(vuln_data['good_code'])}")
    print(f"Has diff: {bool(vuln_data['diff'])}")
    
    # Generate semgrep rules
    print("Generating semgrep rules...")
    rules_data = generate_semgrep_rules(vuln_data, model, ollama_url, seed, debug)
    
    if not rules_data:
        print("Failed to generate semgrep rules")
        return False
    
    print(f"Generated rules for {rules_data['go_id']}")
    
    # Save rules
    save_semgrep_rules(rules_data, output_dir, debug)
    print(f"Saved rules to {output_dir}")
    
    # Verify output
    rule_file = output_dir / f"{vuln_data['go_id']}.yml"
    if rule_file.exists():
        print(f"✅ Rule file created: {rule_file}")
        print(f"✅ File size: {rule_file.stat().st_size} bytes")
        return True
    else:
        print("❌ Rule file not created")
        return False

if __name__ == "__main__":
    success = test_single_vulnerability()
    sys.exit(0 if success else 1)