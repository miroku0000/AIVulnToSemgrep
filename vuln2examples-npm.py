#!/usr/bin/env python3
"""
vuln2examples-npm.py

Generate minimal vulnerable/secure code examples from npm vulnerabilities via GitHub Security Advisory Database.
Similar to vuln2examples.py but for npm packages using GitHub's Security Advisories API.

Usage example:
  python vuln2examples-npm.py --out ./npm-out --debug --save-llm --workers 1

Requirements:
  pip install requests beautifulsoup4 packaging tenacity
"""

import argparse
import concurrent.futures
import dataclasses
from datetime import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from packaging import version
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

# ---- Constants ---------------------------------------------------------------

GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
OLLAMA_URL_DEFAULT = "http://localhost:11434"

# Schema for LLM response
NPM_JSON_SCHEMA_HINT = """CRITICAL: You must respond with VALID JSON ONLY. Do not add any text before or after the JSON.

Required JSON schema:
{
  "fix_files": [
    {"path": "string", "line_ranges": [[start_line:int, end_line:int]]}
  ],
  "rationale": "string",
  "bad_example": "```javascript\\n...\\n```",
  "good_example": "```javascript\\n...\\n```"
}

IMPORTANT JSON RULES:
- Start your response with { and end with }
- Use double quotes for all strings
- Escape newlines as \\n in JSON strings
- Do NOT use backticks outside of the JSON string values
- Do NOT add explanatory text outside the JSON
- Your entire response must be parseable as valid JSON"""

# ---- HTTP utilities ----------------------------------------------------------

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(requests.RequestException),
)
def http_get(url: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    """Retry-enabled GET request."""
    h = {"User-Agent": "vuln2examples-npm/1.0"}
    if headers:
        h.update(headers)
    return requests.get(url, headers=h, timeout=30)

def run(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    """Run a subprocess and return (exit_code, stdout, stderr)."""
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout, proc.stderr

def ensure_dir(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)

def make_logger(report_dir: Path, enabled: bool = True):
    """Create a logger function that writes to debug.txt."""
    debug_file = report_dir / "debug.txt"
    
    def log(msg: str) -> None:
        if enabled:
            print(msg)
            with open(debug_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
    
    return log

# ---- GitHub Advisory API ----------------------------------------------------

def fetch_npm_advisories(limit: Optional[int] = None) -> List[Dict]:
    """Fetch npm vulnerabilities from GitHub Security Advisories API."""
    advisories = []
    page = 1
    per_page = 100
    
    while True:
        url = f"{GITHUB_ADVISORIES_API}?ecosystem=npm&per_page={per_page}&page={page}"
        try:
            response = http_get(url)
            response.raise_for_status()
            page_advisories = response.json()
            
            if not page_advisories:
                break
                
            advisories.extend(page_advisories)
            
            if limit and len(advisories) >= limit:
                advisories = advisories[:limit]
                break
                
            page += 1
            
        except Exception as e:
            print(f"Error fetching advisories page {page}: {e}")
            break
    
    return advisories

def extract_commit_refs(advisory: Dict) -> List[str]:
    """Extract GitHub commit URLs from advisory references."""
    commit_urls = []
    
    for ref in advisory.get("references", []):
        url = ref.get("url", "")
        if "github.com" in url and "/commit/" in url:
            commit_urls.append(url)
        elif "github.com" in url and "/pull/" in url:
            # Convert PR URL to patch URL
            patch_url = url.replace("/pull/", "/pull/") + ".patch"
            commit_urls.append(patch_url)
    
    return commit_urls

def fetch_commit_patch(commit_url: str) -> Optional[str]:
    """Fetch patch content from GitHub commit or PR URL."""
    try:
        # Convert commit URL to patch URL if needed
        if "/commit/" in commit_url and not commit_url.endswith(".patch"):
            patch_url = commit_url + ".patch"
        elif "/pull/" in commit_url and not commit_url.endswith(".patch"):
            patch_url = commit_url + ".patch"
        else:
            patch_url = commit_url
            
        response = http_get(patch_url, headers={"Accept": "text/x-patch"})
        response.raise_for_status()
        return response.text.strip()
    except Exception as e:
        print(f"Failed to fetch patch from {commit_url}: {e}")
        return None

# ---- Ollama integration ------------------------------------------------------

def ollama_generate(
    prompt: str, model: str, url: str, seed: Optional[int], max_tokens: int = 2048
) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_ctx": 8192},
    }
    if seed is not None:
        payload["options"]["seed"] = int(seed)
    r = requests.post(f"{url.rstrip('/')}/api/generate", json=payload, timeout=600)
    r.raise_for_status()
    return r.json().get("response", "")

def extract_json_with_robust_preprocessing(response: str) -> Optional[dict]:
    """Extract JSON from LLM response with robust preprocessing to handle formatting issues."""
    import re
    
    def preprocess_llm_json(response: str) -> str:
        """Fix common JSON formatting issues in LLM responses."""
        response = response.strip()
        
        # Remove markdown code block wrappers
        if response.startswith('```json'):
            response = response[7:]
        if response.startswith('```'):
            response = response[3:]
        if response.endswith('```'):
            response = response[:-3]
        response = response.strip()
        
        def escape_for_json(content: str) -> str:
            """Escape content for inclusion in JSON string."""
            content = content.strip()
            content = content.replace('\\', '\\\\')
            content = content.replace('"', '\\"')
            content = content.replace('\n', '\\n')
            content = content.replace('\r', '\\r')
            content = content.replace('\t', '\\t')
            return content
        
        # Fix backticks in JSON string values
        response = re.sub(
            r'("[^"]*"):\s*```(?:\w+\s+)?([^`]*)```',
            lambda m: f'{m.group(1)}: "{escape_for_json(m.group(2))}"',
            response,
            flags=re.DOTALL
        )
        
        # Fix single backticks
        response = re.sub(
            r'("[^"]*"):\s*`([^`]*)`',
            lambda m: f'{m.group(1)}: "{escape_for_json(m.group(2))}"',
            response
        )
        
        # Fix trailing commas
        response = re.sub(r',(\s*[}\]])', r'\1', response)
        
        # Fix missing commas between JSON properties
        response = re.sub(r'"\s*\n\s*"', '",\n  "', response)
        
        return response
    
    # Try preprocessing first
    try:
        cleaned = preprocess_llm_json(response)
        return json.loads(cleaned)
    except Exception:
        pass
    
    # Try extracting JSON from response
    json_match = re.search(r'\{.*\}', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except Exception:
            pass
    
    return None

def build_llm_prompt(ghsa_id: str, cve: Optional[str], package: str, summary: str, diff_text: str) -> str:
    trimmed_diff = diff_text
    if len(trimmed_diff) > 150_000:
        trimmed_diff = trimmed_diff[:150_000] + "\n... [TRUNCATED]"
    
    return f"""
You are a security code-diff analyst. Identify the exact lines that fixed the vulnerability and craft minimal JavaScript/Node.js code examples.

Vulnerability:
- GHSA ID: {ghsa_id}
- CVE: {cve or "unknown"}
- Package: {package}
- Summary: {summary}

Diff (unified, minimal context). Lines prefixed with '+' are added in the FIX:
----
{trimmed_diff}
----

Instructions:
1) From the diff, identify the smallest set of changed NEW lines that directly constitute the security fix (e.g., added validation, changed condition, sanitized input).
2) Output JSON exactly as specified below. Make the examples minimal but runnable JavaScript/Node.js snippets isolating the core issue.
3) The bad example should demonstrate the vulnerable behavior; the good example should demonstrate the fix (using the same function/idea).
4) If the diff seems unrelated or insufficient, still provide your best-guess minimal examples from the described vulnerability, and explain your assumption in 'rationale'.

{NPM_JSON_SCHEMA_HINT}
""".strip()

# ---- Work unit ---------------------------------------------------------------

@dataclasses.dataclass
class NpmVulnTask:
    ghsa_id: str
    cve: Optional[str]
    package: str
    summary: str
    severity: str
    references: List[str]

def process_npm_vuln(
    advisory: Dict,
    out_root: Path,
    model: str,
    seed: Optional[int],
    ollama_url: str,
    debug: bool,
    save_llm: bool,
) -> Optional[Path]:
    ghsa_id = advisory.get("ghsa_id", "unknown")
    cve = advisory.get("cve_id")
    summary = advisory.get("summary", "")
    severity = advisory.get("severity", "unknown")
    
    # Get affected package info
    vulnerabilities = advisory.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    
    # Use first affected package
    vuln = vulnerabilities[0]
    package = vuln.get("package", {}).get("name", "unknown")
    
    report_dir = out_root / ghsa_id
    ensure_dir(report_dir)
    log = make_logger(report_dir, enabled=debug)
    
    log(f"[{ghsa_id}] Start processing")
    log(f"  - CVE: {cve}")
    log(f"  - Package: {package}")
    log(f"  - Severity: {severity}")
    log(f"  - Summary: {summary}")
    
    # Extract commit references
    commit_refs = extract_commit_refs(advisory)
    log(f"  - Found {len(commit_refs)} commit references")
    
    if not commit_refs:
        log("  - No commit references found; skipping")
        return None
    
    # Try to fetch a patch
    diff_text = None
    for ref in commit_refs:
        patch = fetch_commit_patch(ref)
        if patch:
            diff_text = patch
            log(f"  - Fetched patch from {ref} (len={len(patch)})")
            break
    
    if not diff_text:
        log("  - No patches available; skipping LLM")
        return None
    
    # Save raw patch
    (report_dir / "raw_patch.patch").write_text(diff_text or "", encoding="utf-8")
    
    # Generate examples using LLM
    prompt = build_llm_prompt(ghsa_id, cve, package, summary, diff_text)
    try:
        llm_resp = ollama_generate(
            prompt, model=model, url=ollama_url, seed=seed, max_tokens=2048
        )
        if save_llm:
            (report_dir / "llm_raw.txt").write_text(llm_resp, encoding="utf-8")
        
        # Use robust JSON preprocessing
        data = extract_json_with_robust_preprocessing(llm_resp)
        
        # If first attempt failed, try a retry with simplified prompt
        if not data or not data.get("bad_example") or not data.get("good_example"):
            log("    - First JSON attempt failed, trying retry with simplified prompt")
            retry_prompt = f"""The previous response was not valid JSON. Please provide ONLY valid JSON using this exact schema:

{NPM_JSON_SCHEMA_HINT}

Based on this vulnerability analysis:
- GHSA ID: {ghsa_id}
- Package: {package}
- Summary: {summary}

Your response must start with {{ and end with }} and be valid JSON only."""
            
            try:
                retry_resp = ollama_generate(
                    retry_prompt, model=model, url=ollama_url, seed=seed, max_tokens=2048
                )
                if save_llm:
                    (report_dir / "llm_retry.txt").write_text(retry_resp, encoding="utf-8")
                
                data = extract_json_with_robust_preprocessing(retry_resp)
                if data and data.get("bad_example") and data.get("good_example"):
                    log("    - Retry successful!")
                    llm_resp = retry_resp
            except Exception as e:
                log(f"    - Retry also failed: {e}")
        
        if not data or not data.get("bad_example") or not data.get("good_example"):
            failed_response_file = report_dir / f"failed_llm_response_{ghsa_id}.txt"
            failed_response_file.write_text(llm_resp, encoding="utf-8")
            log(f"    - ERROR: LLM did not return parsable JSON; raw response saved to {failed_response_file.name}")
            return None
        
        # Extract and save examples
        bad_example = data["bad_example"]
        good_example = data["good_example"]
        
        # Clean up code examples (remove markdown wrappers if present)
        def clean_code(code: str) -> str:
            code = code.strip()
            if code.startswith('```javascript'):
                code = code[13:]
            elif code.startswith('```js'):
                code = code[5:]
            elif code.startswith('```'):
                code = code[3:]
            if code.endswith('```'):
                code = code[:-3]
            return code.strip()
        
        bad_example = clean_code(bad_example)
        good_example = clean_code(good_example)
        
        log(f"    - LLM examples extracted (bad={len(bad_example)} chars, good={len(good_example)} chars)")
        
        # Save examples
        bad_file = report_dir / f"{ghsa_id}_bad.js"
        good_file = report_dir / f"{ghsa_id}_good.js"
        
        bad_file.write_text(bad_example, encoding="utf-8")
        good_file.write_text(good_example, encoding="utf-8")
        
        log(f"    - Wrote {bad_file}")
        log(f"    - Wrote {good_file}")
        
    except Exception as e:
        log(f"    - ERROR: LLM call/parse failed: {e}")
        return None
    
    log(f"[{ghsa_id}] Done; results saved to {report_dir}")
    return report_dir

# ---- Main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Generate minimal examples from npm vulnerabilities via GitHub Security Advisory Database."
    )
    ap.add_argument("--out", required=True, help="Output directory.")
    ap.add_argument("--model", default="llama3.1", help="Ollama model name.")
    ap.add_argument("--ollama-url", default=OLLAMA_URL_DEFAULT, help="Ollama base URL.")
    ap.add_argument("--seed", type=int, default=None, help="LLM seed for reproducibility.")
    ap.add_argument("--limit", type=int, default=None, help="Limit number of vulnerabilities to process.")
    ap.add_argument("--debug", action="store_true", help="Enable debug logging.")
    ap.add_argument("--save-llm", action="store_true", help="Save raw LLM responses.")
    ap.add_argument("--workers", type=int, default=4, help="Number of worker threads.")
    
    args = ap.parse_args()
    
    out_root = Path(args.out)
    ensure_dir(out_root)
    
    print("Fetching npm vulnerabilities from GitHub Security Advisory Database...")
    advisories = fetch_npm_advisories(limit=args.limit)
    
    if not advisories:
        print("No npm advisories found.")
        sys.exit(1)
    
    print(f"Found {len(advisories)} npm advisories")
    
    def work(advisory: Dict):
        try:
            return process_npm_vuln(
                advisory=advisory,
                out_root=out_root,
                model=args.model,
                seed=args.seed,
                ollama_url=args.ollama_url,
                debug=args.debug,
                save_llm=args.save_llm,
            )
        except Exception as e:
            if args.debug:
                ghsa_id = advisory.get("ghsa_id", "unknown")
                print(f"[{ghsa_id}] Unhandled error: {e}")
            return None
    
    # Progress tracking
    total_targets = len(advisories)
    completed = 0
    successful = 0
    progress_file = out_root / "progress.log"
    
    def log_progress():
        success_rate = (successful / completed * 100) if completed > 0 else 0
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"[{timestamp}] Processed {completed}/{total_targets} | Success rate: {success_rate:.1f}% ({successful} successful)\n"
        with open(progress_file, "a", encoding="utf-8") as f:
            f.write(msg)
        print(f"Progress: {completed}/{total_targets} ({success_rate:.1f}% success)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(work, advisory) for advisory in advisories]
        for f in concurrent.futures.as_completed(futs):
            result = f.result()
            completed += 1
            if result:
                successful += 1
            log_progress()

    print(f"Done. Results under {out_root}")

if __name__ == "__main__":
    main()