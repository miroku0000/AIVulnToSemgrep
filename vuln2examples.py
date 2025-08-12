#!/usr/bin/env python3
"""
vuln2examples.py (v1.4) — HTTP diff fallback

New:
- --http-diff-first : try downloading .patch from commit/PR URLs before cloning
- If git clone fails, automatically fall back to HTTP .patch when we have commit/PR links
- More explicit debug for git clone stderr

HTTP patch endpoints used:
  - Commit: https://github.com/<owner>/<repo>/commit/<sha>.patch
  - PR    : https://github.com/<owner>/<repo>/pull/<number>.patch

Usage example (to avoid git entirely when refs exist):
  python vuln2examples.py --out ./out --only GO-2025-3857 --debug --save-llm --workers 1 --http-diff-first
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

NUTANIX_VULN_LIST = "https://developers.golang.nutanix.com/vuln/list"
NUTANIX_VULN_ROOT = "https://developers.golang.nutanix.com/vuln/"
PKG_VULN_FMT = "https://pkg.go.dev/vuln/{go_id}"
GO_INDEX_VULNS = "https://vuln.go.dev/index/vulns.json"
GO_VULN_JSON_FMT = "https://vuln.go.dev/ID/{go_id}.json"
OLLAMA_URL_DEFAULT = "http://127.0.0.1:11434"
HEADERS = {"User-Agent": "vuln2examples/1.4 (+https://github.com/)"}

# ---- Small utils -------------------------------------------------------------


def run(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    p = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = p.communicate()
    return p.returncode, out, err


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(name, default)


def dedup_preserve(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ---- Simple logger -----------------------------------------------------------


def make_logger(report_dir: Path, enabled: bool):
    dbg_path = report_dir / "debug.txt"

    def log(msg: str):
        line = msg.rstrip() + "\n"
        if enabled:
            print(line, end="")
        try:
            with open(dbg_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    return log


# ---- HTTP helpers ------------------------------------------------------------


def gh_headers():
    h = dict(HEADERS)
    tok = get_env("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


@retry(
    wait=wait_exponential(multiplier=1, min=1, max=30),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(requests.RequestException),
)
def http_get(url, **kwargs):
    h = dict(HEADERS)
    h.update(kwargs.pop("headers", {}))
    r = requests.get(url, headers=h, timeout=30, **kwargs)
    r.raise_for_status()
    return r


# ---- Discovery ---------------------------------------------------------------


def discover_go_ids(limit: Optional[int] = None) -> List[str]:
    ids = []
    try:
        r = http_get(NUTANIX_VULN_LIST)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            text = (a.get_text() or "") + " " + a["href"]
            m = re.findall(r"GO-\d{4}-\d+", text)
            for goid in m:
                ids.append(goid)
    except Exception:
        pass
    if not ids:
        try:
            r = http_get(GO_INDEX_VULNS)
            data = r.json()
            for row in data:
                goid = row.get("id")
                if isinstance(goid, str) and re.fullmatch(r"GO-\d{4}-\d+", goid):
                    ids.append(goid)
        except Exception:
            ids = []
    return dedup_preserve(ids[:limit] if limit else ids)


# ---- HTML parsing helpers ----------------------------------------------------


def fetch_report_html(go_id: str) -> Optional[str]:
    try:
        r = http_get(f"{NUTANIX_VULN_ROOT}{go_id}")
        return r.text
    except Exception:
        return None


def fetch_pkg_html(go_id: str) -> Optional[str]:
    try:
        r = http_get(PKG_VULN_FMT.format(go_id=go_id))
        return r.text
    except Exception:
        return None


def extract_json_link_from_report(html: Optional[str], go_id: str) -> str:
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "vuln.go.dev/ID/GO-" in href and href.endswith(".json"):
                    return href
        except Exception:
            pass
    return GO_VULN_JSON_FMT.format(go_id=go_id)


def extract_refs_from_html(html: Optional[str]) -> List[str]:
    if not html:
        return []
    urls = []
    try:
        for m in re.finditer(
            r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:commit|pull)/[A-Za-z0-9_.-]+",
            html,
        ):
            urls.append(m.group(0))
    except Exception:
        pass
    return dedup_preserve(urls)


def extract_modules_from_text(text: str) -> List[str]:
    mods = []
    for m in re.finditer(
        r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", text or ""
    ):
        mods.append(f"github.com/{m.group(1)}/{m.group(2)}")
    return dedup_preserve(mods)


# ---- Canonical vuln JSON parsing --------------------------------------------


def fetch_go_vuln_json(json_url: str) -> Optional[dict]:
    try:
        r = http_get(json_url)
        return r.json()
    except Exception:
        return None


def affected_modules_and_fixes(vuln_json: dict) -> List[Tuple[str, List[str]]]:
    out = []
    for aff in vuln_json.get("affected", []):
        module_path = (aff.get("module") or {}).get("path") or ""
        fixed_versions = []
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed_versions.append(ev["fixed"])
        if module_path:
            out.append((module_path, dedup_preserve(fixed_versions)))
    return out


def fix_commit_candidates(vuln_json: dict) -> List[str]:
    urls = []
    for ref in vuln_json.get("references", []):
        url = ref.get("url", "")
        typ = (ref.get("type") or "").lower()
        if "fix" in typ or "/commit/" in url or "/pull/" in url or "/merge" in url:
            urls.append(url)
    return dedup_preserve(urls)


def parse_cve(vuln_json: dict) -> Optional[str]:
    for a in vuln_json.get("aliases", []) or []:
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            return a.upper()
    return None


def summarize(vuln_json: dict) -> str:
    return vuln_json.get("summary") or (vuln_json.get("details") or "")[:240]


# ---- Repo/helpers and HTTP diff helpers -------------------------------------


def extract_repo_from_module(module_path: str) -> Optional[str]:
    m = re.match(r"^github\.com/([^/]+)/([^/]+)", module_path.strip())
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def parse_commit_from_url(url: str) -> Optional[str]:
    m = re.search(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})", url)
    if m:
        return m.group(1)
    return None


def owner_repo_from_github_url(url: str) -> Optional[str]:
    m = re.search(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return None


def pr_number_from_url(url: str) -> Optional[str]:
    m = re.search(r"github\.com/[^/]+/[^/]+/pull/(\d+)", url)
    return m.group(1) if m else None


def ensure_repo_cached(cache_dir: Path, owner_repo: str, log) -> Path:
    repo_dir = cache_dir / owner_repo.replace("/", "_")
    if repo_dir.exists() and (repo_dir / ".git").exists():
        log(f"  - Using cached repo and fetching tags: {owner_repo}")
        code, out, err = run(
            ["git", "fetch", "--all", "--tags", "--prune"], cwd=repo_dir
        )
        if code != 0:
            log(f"    WARN: git fetch failed: {err or out}")
        return repo_dir
    ensure_dir(repo_dir.parent)
    log(f"  - Cloning repo: {owner_repo}")
    code, out, err = run(
        ["git", "clone", f"https://github.com/{owner_repo}.git", str(repo_dir)]
    )
    if code != 0:
        raise RuntimeError(f"git clone failed: {owner_repo}: {err or out}")
    run(["git", "fetch", "--tags"], cwd=repo_dir)
    return repo_dir


def fetch_commit_patch(owner_repo: str, sha: str, log) -> Optional[str]:
    url = f"https://github.com/{owner_repo}/commit/{sha}.patch"
    try:
        r = http_get(url, headers={"Accept": "text/x-patch"})
        txt = r.text.strip()
        if txt:
            log(f"    - Fetched commit patch via HTTP (len={len(txt)})")
            return txt
    except Exception as e:
        log(f"    WARN: HTTP commit patch fetch failed: {e}")
    return None


def fetch_pr_patch(owner_repo: str, pr_number: str, log) -> Optional[str]:
    url = f"https://github.com/{owner_repo}/pull/{pr_number}.patch"
    try:
        r = http_get(url, headers={"Accept": "text/x-patch"})
        txt = r.text.strip()
        if txt:
            log(f"    - Fetched PR patch via HTTP (len={len(txt)})")
            return txt
    except Exception as e:
        log(f"    WARN: HTTP PR patch fetch failed: {e}")
    return None


def semver_list_from_git(repo_dir: Path) -> List[str]:
    code, out, _ = run(["git", "tag", "--list"], cwd=repo_dir)
    if code != 0:
        return []
    tags = [t.strip() for t in out.splitlines() if t.strip()]
    candidates = [t for t in tags if re.match(r"^v\d+(\.\d+){0,2}$", t)]

    def vkey(t):
        try:
            return version.parse(t.lstrip("v"))
        except Exception:
            return version.parse("0")

    return sorted(candidates, key=vkey)


def pick_prev_tag(tags: List[str], fixed_tag: str) -> Optional[str]:
    if fixed_tag not in tags:
        return None
    idx = tags.index(fixed_tag)
    return tags[idx - 1] if idx > 0 else None


def find_commit_by_cve(
    repo_dir: Path, go_id: str, cve: Optional[str], log
) -> Optional[str]:
    patterns = [go_id]
    if cve:
        patterns.append(cve)
    for pat in patterns:
        code, out, _ = run(
            ["git", "log", "--pretty=%H %s", f"--grep={pat}"], cwd=repo_dir
        )
        if code == 0 and out.strip():
            sha = out.splitlines()[0].split()[0]
            log(f"  - Found commit by grep '{pat}': {sha}")
            return sha
    return None


def resolve_tags_for_module(repo_dir: Path, module_path: str) -> List[str]:
    return semver_list_from_git(repo_dir)


def diff_for_fix(
    owner_repo: Optional[str],
    repo_dir: Optional[Path],
    fixed_version: Optional[str],
    commit_sha: Optional[str],
    pr_number: Optional[str],
    log,
    http_first: bool,
) -> Tuple[str, str]:
    """
    Try to obtain a diff via (in order):
    1) HTTP commit patch (if http_first and commit present)
    2) HTTP PR patch (if http_first and PR present)
    3) git show commit
    4) git diff prev..fixed_tag
    5) If git steps fail but we have commit/PR, fall back to HTTP patch anyway
    """
    # HTTP-first
    if http_first and owner_repo:
        if commit_sha:
            patch = fetch_commit_patch(owner_repo, commit_sha, log)
            if patch:
                return patch, f"http-commit:{commit_sha}"
        if pr_number:
            patch = fetch_pr_patch(owner_repo, pr_number, log)
            if patch:
                return patch, f"http-pr:{pr_number}"

    # git-based
    if repo_dir and commit_sha:
        log(f"  - Using commit: {commit_sha}")
        code, out, err = run(
            ["git", "show", "--no-color", "--unified=0", commit_sha], cwd=repo_dir
        )
        if code == 0 and out.strip():
            log(f"    diff: commit vs parent (len={len(out)})")
            return out, f"commit:{commit_sha}"
        else:
            log(f"    WARN: git show failed: {err or 'no output'}")

    if repo_dir and fixed_version:
        tags = resolve_tags_for_module(repo_dir, "")
        fixed_tag = (
            f"v{fixed_version}" if not fixed_version.startswith("v") else fixed_version
        )
        log(
            f"  - Fixed version from JSON: {fixed_version} (tag candidate: {fixed_tag})"
        )
        if fixed_tag in tags:
            prev = pick_prev_tag(tags, fixed_tag)
            if prev:
                code, out, err = run(
                    [
                        "git",
                        "diff",
                        "--no-color",
                        "--unified=0",
                        f"{prev}..{fixed_tag}",
                    ],
                    cwd=repo_dir,
                )
                if code == 0 and out.strip():
                    log(f"    diff: tags {prev}..{fixed_tag} (len={len(out)})")
                    return out, f"tags:{prev}..{fixed_tag}"
                else:
                    log(f"    WARN: git diff failed: {err or 'no output'}")
        else:
            log("    WARN: fixed tag not present in repo tags")

    # HTTP fallback if we have owner_repo + commit/pr
    if owner_repo:
        if commit_sha:
            patch = fetch_commit_patch(owner_repo, commit_sha, log)
            if patch:
                return patch, f"http-commit:{commit_sha}"
        if pr_number:
            patch = fetch_pr_patch(owner_repo, pr_number, log)
            if patch:
                return patch, f"http-pr:{pr_number}"

    log("  - No diff produced")
    return "", "none"


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
    """
    Extract JSON from LLM response with robust preprocessing to handle formatting issues.
    """
    import re
    
    # Save raw response for analysis
    if hasattr(extract_json_with_robust_preprocessing, '_save_failures'):
        extract_json_with_robust_preprocessing._save_failures.append(response)
    
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
        
        # Fix backticks in JSON string values - more robust patterns
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
        
        # Fix incomplete JSON - missing quotes around code
        response = re.sub(
            r'("[^"]*"):\s*([^",{}]+?)(\s*[,}])',
            lambda m: f'{m.group(1)}: "{escape_for_json(m.group(2).strip())}"{m.group(3)}',
            response
        )
        
        # Fix trailing commas
        response = re.sub(r',(\s*[}\]])', r'\1', response)
        
        # Fix missing commas between JSON properties
        response = re.sub(r'"\s*\n\s*"', '",\n  "', response)
        
        # Fix missing closing braces
        if not response.rstrip().endswith('}'):
            open_braces = response.count('{')
            close_braces = response.count('}')
            if open_braces > close_braces:
                response += '}' * (open_braces - close_braces)
        
        return response
    
    # Strategy 1: Preprocess and parse normally
    try:
        preprocessed = preprocess_llm_json(response)
        return json.loads(preprocessed)
    except (json.JSONDecodeError, Exception) as e:
        # Save the parsing error for analysis
        if hasattr(extract_json_with_robust_preprocessing, '_save_failures'):
            extract_json_with_robust_preprocessing._error_details.append(str(e))
    
    # Strategy 2: More aggressive regex extraction
    result = {}
    
    # Extract rationale with multiple patterns
    rationale_match = re.search(r'"rationale":\s*"([^"]*)"', response)
    if not rationale_match:
        rationale_match = re.search(r'rationale["\s:]*([^",\n]+)', response, re.IGNORECASE)
    if rationale_match:
        result['rationale'] = rationale_match.group(1).strip()
    
    # Extract code examples with comprehensive patterns
    def extract_code_value(field_name: str) -> Optional[str]:
        patterns = [
            rf'"{field_name}":\s*"([^"]*)"',  # Quoted string
            rf'"{field_name}":\s*```[^`]*?([^`]*)```',  # Triple backticks with lang
            rf'"{field_name}":\s*```([^`]*)```',  # Triple backticks
            rf'"{field_name}":\s*`([^`]*)`',  # Single backticks
            rf'{field_name}["\s:]*([^",\n{{}}]+)',  # Unquoted value
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    bad_code = extract_code_value("bad_example")
    good_code = extract_code_value("good_example")
    
    if bad_code:
        result['bad_example'] = bad_code
    if good_code:
        result['good_example'] = good_code
    
    # Strategy 3: Line-by-line heuristic parsing for very broken responses
    if not result.get('bad_example') or not result.get('good_example'):
        lines = response.split('\n')
        current_section = None
        current_code = []
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['bad_example', 'bad example', 'vulnerable']):
                if current_section and current_code:
                    if current_section == 'bad' and not result.get('bad_example'):
                        result['bad_example'] = '\n'.join(current_code)
                    elif current_section == 'good' and not result.get('good_example'):
                        result['good_example'] = '\n'.join(current_code)
                current_section = 'bad'
                current_code = []
                # Check if code is on the same line
                code_match = re.search(r'[`"](.*?)[`"]', line)
                if code_match:
                    current_code.append(code_match.group(1))
            elif any(keyword in line.lower() for keyword in ['good_example', 'good example', 'secure', 'fixed']):
                if current_section == 'bad' and current_code and not result.get('bad_example'):
                    result['bad_example'] = '\n'.join(current_code)
                current_section = 'good'
                current_code = []
                code_match = re.search(r'[`"](.*?)[`"]', line)
                if code_match:
                    current_code.append(code_match.group(1))
            elif current_section and line and not line.startswith('"') and not line.startswith('}'):
                # Remove common prefixes
                clean_line = re.sub(r'^[`"]*', '', line)
                clean_line = re.sub(r'[`"]*$', '', clean_line)
                if clean_line and 'func' in clean_line:  # Looks like Go code
                    current_code.append(clean_line)
        
        # Save final section
        if current_section == 'good' and current_code and not result.get('good_example'):
            result['good_example'] = '\n'.join(current_code)
        elif current_section == 'bad' and current_code and not result.get('bad_example'):
            result['bad_example'] = '\n'.join(current_code)
    
    return result if result else None


FIX_JSON_SCHEMA_HINT = """CRITICAL: You must respond with VALID JSON ONLY. Do not add any text before or after the JSON.

Required JSON schema:
{
  "fix_files": [
    {"path": "string", "line_ranges": [[start_line:int, end_line:int]]}
  ],
  "rationale": "string",
  "bad_example": "```go\\n...\\n```",
  "good_example": "```go\\n...\\n```"
}

IMPORTANT JSON RULES:
- Start your response with { and end with }
- Use double quotes for all strings
- Escape newlines as \\n in JSON strings
- Do NOT use backticks outside of the JSON string values
- Do NOT add explanatory text outside the JSON
- Your entire response must be parseable as valid JSON"""


def build_llm_prompt(
    go_id: str, cve: Optional[str], module: str, summary: str, diff_text: str
) -> str:
    trimmed_diff = diff_text
    if len(trimmed_diff) > 150_000:
        trimmed_diff = trimmed_diff[:150_000] + "\n... [TRUNCATED]"
    return f"""
You are a security code-diff analyst. Identify the exact lines that fixed the vulnerability and craft minimal Go code examples.

Vulnerability:
- GO ID: {go_id}
- CVE: {cve or "unknown"}
- Module: {module}
- Summary: {summary}

Diff (unified, minimal context). Lines prefixed with '+' are added in the FIX:
---
{trimmed_diff}
---

Instructions:
1) From the diff, identify the smallest set of changed NEW lines that directly constitute the security fix (e.g., added validation, changed condition, sanitized input).
2) Output JSON exactly as specified below. Make the examples minimal but compilable Go snippets isolating the core issue.
3) The bad example should demonstrate the vulnerable behavior; the good example should demonstrate the fix (using the same function/idea).
4) If the diff seems unrelated or insufficient, still provide your best-guess minimal examples from the described vulnerability, and explain your assumption in 'rationale'.

{FIX_JSON_SCHEMA_HINT}
""".strip()


# ---- Work unit ---------------------------------------------------------------


@dataclasses.dataclass
class VulnTask:
    go_id: str
    cve: Optional[str]
    modules: List[str]
    fixed_versions: Dict[str, List[str]]
    reference_urls: List[str]
    repo_map: Dict[str, str]


def process_vuln(
    go_id: str,
    out_root: Path,
    flat_output: bool,
    repo_cache: Path,
    model: str,
    seed: Optional[int],
    ollama_url: str,
    debug: bool,
    save_llm: bool,
    http_diff_first: bool,
    only_modules: Optional[List[str]] = None,
) -> Optional[Path]:
    report_dir = out_root / go_id
    
    # Check if already processed (resume functionality)
    if report_dir.exists():
        debug_file = report_dir / "debug.txt"
        if debug_file.exists() and "Done; results saved" in debug_file.read_text(encoding="utf-8", errors="ignore"):
            if debug:
                print(f"[{go_id}] Already processed, skipping")
            return report_dir
    
    ensure_dir(report_dir)
    log = make_logger(report_dir, enabled=debug)

    log(f"[{go_id}] Start processing")
    html = fetch_report_html(go_id)
    json_link = extract_json_link_from_report(html, go_id)
    log(f"  - JSON link: {json_link} (html={'yes' if html else 'no'})")

    vuln_json = fetch_go_vuln_json(json_link) or {}
    if not vuln_json:
        log("  - ERROR: Could not fetch or parse vuln JSON")
        return None

    # Modules & refs
    modules_fix = affected_modules_and_fixes(vuln_json)
    modules = [m for m, _ in modules_fix]
    fixed_versions = {m: v for m, v in modules_fix}
    refs = fix_commit_candidates(vuln_json)

    # From HTML pages
    nt_refs = extract_refs_from_html(html)
    if nt_refs:
        log(f"  - Extra refs from Nutanix HTML: {len(nt_refs)}")
        refs.extend(nt_refs)
    pkg_html = fetch_pkg_html(go_id)
    if pkg_html:
        pkg_refs = extract_refs_from_html(pkg_html)
        if pkg_refs:
            log(f"  - Extra refs from pkg.go.dev: {len(pkg_refs)}")
            refs.extend(pkg_refs)
    refs = dedup_preserve(refs)

    # Merge inferred modules
    text = (vuln_json.get("summary") or "") + "\n" + (vuln_json.get("details") or "")
    inferred_text = extract_modules_from_text(text)
    if inferred_text:
        log(f"  - Inferred modules from text: {inferred_text}")

    inferred_refs = []
    for u in refs:
        orr = owner_repo_from_github_url(u)
        if orr:
            inferred_refs.append(f"github.com/{orr}")
    inferred_refs = dedup_preserve(inferred_refs)
    if inferred_refs:
        log(f"  - Inferred modules from refs: {inferred_refs}")

    modules = dedup_preserve(modules + inferred_text + inferred_refs)
    for m in modules:
        fixed_versions.setdefault(m, [])

    repo_map = {m: extract_repo_from_module(m) for m in modules}
    cve = parse_cve(vuln_json)
    summary_text = summarize(vuln_json)

    write_json(
        report_dir / "metadata.json",
        {
            "go_id": go_id,
            "json_link": json_link,
            "vuln_json": vuln_json,
            "modules": modules,
            "fixed_versions": fixed_versions,
            "reference_urls": refs,
            "repo_map": repo_map,
        },
    )

    log(f"  - Modules: {modules or '[]'}")
    log(f"  - Repo map: {repo_map or '{}'}")
    log(f"  - Fixed versions: {fixed_versions or '{}'}")
    log(f"  - References: {refs or '[]'}")
    log(f"  - CVE: {cve or 'n/a'}")
    log(f"  - Summary: {summary_text[:120]}{'...' if len(summary_text)>120 else ''}")

    if only_modules:
        modules = [m for m in modules if m in only_modules]
        log(f"  - Filtered modules: {modules or '[]'}")
        if not modules:
            log("  - No modules after filtering; stopping")
            return None

    all_results = []
    for module in modules:
        log(f"  * Module: {module}")
        owner_repo = repo_map.get(module)
        if not owner_repo:
            log("    - SKIP: module not on GitHub (no owner/repo)")
            continue

        # Extract commit and PR candidates from refs
        commit_sha = None
        pr_number = None
        for u in refs:
            orr = owner_repo_from_github_url(u)
            if orr and orr.lower() == owner_repo.lower():
                if not commit_sha:
                    commit_sha = parse_commit_from_url(u) or commit_sha
                if not pr_number:
                    pr_number = pr_number_from_url(u) or pr_number

        # Try git clone (unless http-first will suffice later)
        repo_dir = None
        try:
            if not http_diff_first:
                repo_dir = ensure_repo_cached(repo_cache, owner_repo, log)
        except Exception as e:
            log(f"    - ERROR: clone/fetch failed for {owner_repo}: {e}")

        # Determine fixed version for this module (if any)
        fixed_ver = (
            fixed_versions.get(module, [None])[0]
            if fixed_versions.get(module)
            else None
        )
        if fixed_ver:
            log(f"    - Fixed version candidate: {fixed_ver}")
        else:
            log("    - No fixed version specified in JSON")

        # Get diff (HTTP-first if requested; else git-first with HTTP fallback)
        diff_text, diff_desc = diff_for_fix(
            owner_repo,
            repo_dir,
            fixed_ver,
            commit_sha,
            pr_number,
            log,
            http_first=http_diff_first,
        )
        (report_dir / "raw_diff.patch").write_text(diff_text or "", encoding="utf-8")
        log(f"    - Diff descriptor: {diff_desc}")

        if not diff_text:
            log("    - No diff available; skipping LLM for this module")
            continue

        prompt = build_llm_prompt(go_id, cve, module, summary_text, diff_text)
        try:
            llm_resp = ollama_generate(
                prompt, model=model, url=ollama_url, seed=seed, max_tokens=2048
            )
            if save_llm:
                (report_dir / "llm_raw.txt").write_text(llm_resp, encoding="utf-8")
            
            # Initialize failure tracking for this run
            if not hasattr(extract_json_with_robust_preprocessing, '_save_failures'):
                extract_json_with_robust_preprocessing._save_failures = []
                extract_json_with_robust_preprocessing._error_details = []
            
            # Use robust JSON preprocessing to handle LLM formatting issues
            data = extract_json_with_robust_preprocessing(llm_resp)
            
            # If first attempt failed, try a retry with simplified prompt
            if not data or not data.get("bad_example") or not data.get("good_example"):
                log("    - First JSON attempt failed, trying retry with simplified prompt")
                retry_prompt = f"""The previous response was not valid JSON. Please provide ONLY valid JSON using this exact schema:

{FIX_JSON_SCHEMA_HINT}

Based on this vulnerability analysis:
- GO ID: {go_id}
- Module: {module}
- Summary: {summary_text}

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
                        llm_resp = retry_resp  # Use retry response for success case
                except Exception as e:
                    log(f"    - Retry also failed: {e}")
            
            if not data or not data.get("bad_example") or not data.get("good_example"):
                # Save the failed response for analysis
                failed_response_file = report_dir / f"failed_llm_response_{go_id}.txt"
                failed_response_file.write_text(llm_resp, encoding="utf-8")
                log(f"    - ERROR: LLM did not return parsable JSON; raw response saved to {failed_response_file.name}")
                continue
        except Exception as e:
            log(f"    - ERROR: LLM call/parse failed: {e}")
            continue

        bad_code = data.get("bad_example", "")
        good_code = data.get("good_example", "")

        def extract_code(md: str) -> str:
            m = re.search(r"```(?:go)?\s*(.*?)```", md, re.DOTALL | re.IGNORECASE)
            return (m.group(1) if m else md).strip()

        bad_src = extract_code(bad_code)
        good_src = extract_code(good_code)

        if not bad_src or not good_src:
            log("    - WARN: LLM examples missing or empty")
        else:
            log(
                f"    - LLM examples extracted (bad={len(bad_src)} chars, good={len(good_src)} chars)"
            )

        if flat_output:
            bad_path = out_root / f"{go_id}_bad.go"
            good_path = out_root / f"{go_id}_good.go"
        else:
            bad_path = report_dir / f"{go_id}_bad.go"
            good_path = report_dir / f"{go_id}_good.go"

        if bad_src:
            bad_path.write_text(bad_src, encoding="utf-8")
            log(f"    - Wrote {bad_path}")
        if good_src:
            good_path.write_text(good_src, encoding="utf-8")
            log(f"    - Wrote {good_path}")

        all_results.append(
            {
                "module": module,
                "repo": owner_repo,
                "diff_descriptor": diff_desc,
                "bad_example_file": (
                    str(bad_path.relative_to(out_root)) if bad_src else None
                ),
                "good_example_file": (
                    str(good_path.relative_to(out_root)) if good_src else None
                ),
                "rationale": data.get("rationale", ""),
                "fix_files": data.get("fix_files", []),
            }
        )

    write_json(
        report_dir / "report.json",
        {
            "go_id": go_id,
            "summary": summarize(vuln_json),
            "cve": parse_cve(vuln_json),
            "results": all_results,
            "source": "developers.golang.nutanix.com / vuln.go.dev / pkg.go.dev",
        },
    )
    log(f"[{go_id}] Done; results saved to {report_dir}")
    return report_dir


# ---- Filters & CLI -----------------------------------------------------------


def parse_id_patterns(s: Optional[str]) -> Optional[List[str]]:
    if not s:
        return None
    return [x.strip() for x in s.split(",") if x.strip()]


def id_in_patterns(go_id: str, patterns: Optional[List[str]]) -> bool:
    if not patterns:
        return True
    for pat in patterns:
        re_pat = re.escape(pat).replace("\\*", ".*")
        if re.fullmatch(re_pat, go_id):
            return True
    return False


def extract_literal_go_ids(s: Optional[str]) -> List[str]:
    if not s:
        return []
    out = []
    for tok in [x.strip() for x in s.split(",") if x.strip()]:
        if re.fullmatch(r"GO-\d{4}-\d+", tok):
            out.append(tok)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Generate minimal examples from Go vulnerabilities via Ollama (v1.4 HTTP diff fallback)."
    )
    ap.add_argument("--out", required=True, help="Output directory.")
    ap.add_argument(
        "--repo-cache", default="./_repo_cache", help="Cache for cloned Git repos."
    )
    ap.add_argument("--model", default="llama3.1", help="Ollama model name.")
    ap.add_argument("--ollama-url", default=OLLAMA_URL_DEFAULT, help="Ollama base URL.")
    ap.add_argument(
        "--seed", type=int, default=None, help="LLM seed for reproducibility."
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of vulnerabilities discovered from the list page.",
    )
    ap.add_argument(
        "--only",
        default=None,
        help="Only these GO IDs (comma-separated, supports '*'; literal GO-IDs always added).",
    )
    ap.add_argument(
        "--skip",
        default=None,
        help="Skip these GO IDs (comma-separated, supports '*').",
    )
    ap.add_argument(
        "--include",
        default=None,
        help="Process only GO IDs matching these patterns (comma-separated, supports '*').",
    )
    ap.add_argument("--workers", type=int, default=3, help="Parallel workers.")
    ap.add_argument(
        "--flat-output",
        action="store_true",
        help="If set, write *_bad.go and *_good.go directly under --out (reports stay in per-ID folders).",
    )
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Verbose logging and per-vuln debug.txt files.",
    )
    ap.add_argument(
        "--save-llm",
        action="store_true",
        help="Save raw LLM response to llm_raw.txt for each vuln.",
    )
    ap.add_argument(
        "--http-diff-first",
        action="store_true",
        help="Prefer downloading .patch from commit/PR URLs before cloning with git.",
    )
    args = ap.parse_args()

    out_root = Path(args.out).resolve()
    repo_cache = Path(args.repo_cache).resolve()
    ensure_dir(out_root)
    ensure_dir(repo_cache)

    discovered_ids = discover_go_ids(limit=args.limit)
    if not discovered_ids:
        print("No GO IDs discovered. Check network access. Exiting.")
        sys.exit(1)

    include_pats = parse_id_patterns(args.include)
    skip_pats = parse_id_patterns(args.skip)

    def should_process(go_id: str) -> bool:
        if include_pats and not id_in_patterns(go_id, include_pats):
            return False
        if skip_pats and id_in_patterns(go_id, skip_pats):
            return False
        return True

    targets = [go_id for go_id in discovered_ids if should_process(go_id)]

    literal_ids = set(
        extract_literal_go_ids(args.only) + extract_literal_go_ids(args.include)
    )
    targets = list(dict.fromkeys(targets + list(literal_ids)))

    if not targets:
        print("No vulnerabilities matched your filters; exiting.")
        sys.exit(0)

    only_pats = parse_id_patterns(args.only)
    if only_pats:
        targets = [
            t for t in targets if id_in_patterns(t, only_pats) or t in literal_ids
        ]

    if args.debug:
        print(f"Targets: {targets}")

    def work(go_id: str):
        try:
            return process_vuln(
                go_id=go_id,
                out_root=out_root,
                flat_output=args.flat_output,
                repo_cache=repo_cache,
                model=args.model,
                seed=args.seed,
                ollama_url=args.ollama_url,
                debug=args.debug,
                save_llm=args.save_llm,
                http_diff_first=args.http_diff_first,
            )
        except Exception as e:
            if args.debug:
                print(f"[{go_id}] Unhandled error: {e}")
            return None

    # Progress tracking
    total_targets = len(targets)
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
        futs = [ex.submit(work, gid) for gid in targets]
        for f in concurrent.futures.as_completed(futs):
            result = f.result()
            completed += 1
            if result:  # process_vuln returns the report_dir if successful
                successful += 1
            log_progress()

    print(f"Done. Results under {out_root}")


if __name__ == "__main__":
    main()
