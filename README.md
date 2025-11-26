# mething-around
Coding and things
#!/usr/bin/env python3
import re
import sys
import json
from pathlib import Path

# Configure scopes you own/administer
REPO_ROOTS = [
    # Add paths to locally cloned repos you own
    "/path/to/your/org/repo1",
    "/path/to/your/org/repo2",
]

# Keywords/topics to flag (expand thoughtfully, avoid overbroad/friction)
KEYWORDS = [
    # Frameworks/libraries
    r"\bflask\b", r"\bflask[_-]?api\b", r"\bsqlalchemy\b",

    # Sciences/topics (use context-aware review, these are broad!)
    r"\bphysiology\b", r"\bbiology\b", r"\bchemistry\b", r"\bchemical(s)?\b",
    r"\bperiodic table\b", r"\bphysics\b", r"\bquantum\b", r"\brobotics\b",
    r"\bmechanism(s)?\b",

    # Influence/power (highly context-dependent; include only if needed)
    r"\bhuman influence\b", r"\bpower\b",

    # Fictional/educational terms (be cautious with false positives)
    r"\bmagic\b", r"\bfiction(al)?\b", r"\beducation(al)?\b",
]

# Dependency indicators (Python)
DEP_FILES = [
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.cfg",
    "setup.py",
]

# File patterns to include; exclude binaries and large assets
INCLUDE_EXT = {
    ".py", ".md", ".txt", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".json",
    ".ipynb",
}
EXCLUDE_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"}

kw_patterns = [re.compile(pat, re.IGNORECASE) for pat in KEYWORDS]

def scan_file(path: Path):
    issues = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return issues
    # Keyword matches
    for pat in kw_patterns:
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = text[max(0, m.start()-60):m.end()+60].replace("\n", " ")
            issues.append({
                "type": "keyword_match",
                "pattern": pat.pattern,
                "line": line_no,
                "snippet": snippet.strip(),
            })
    return issues

def scan_dependencies(repo_path: Path):
    findings = []
    for dep_file in DEP_FILES:
        p = repo_path / dep_file
        if p.exists():
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            deps = []
            # Simple heuristics; for robust parsing, use toml or pipfile parsers
            if dep_file == "requirements.txt":
                deps = [l.split("==")[0].strip() for l in content.splitlines() if l and not l.startswith("#")]
            elif dep_file in ("pyproject.toml", "Pipfile", "setup.cfg", "setup.py"):
                # Lightweight grep for common deps
                for name in ("flask", "flask-api", "sqlalchemy"):
                    if re.search(rf"\b{name}\b", content, re.IGNORECASE):
                        deps.append(name)
            if deps:
                findings.append({
                    "type": "dependency",
                    "file": dep_file,
                    "deps": sorted(set(deps)),
                })
    return findings

def should_scan(path: Path):
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return False
    if path.is_dir():
        return True
    if path.suffix in INCLUDE_EXT or path.name in DEP_FILES:
        return True
    return False

def scan_repo(repo_path: Path):
    report = {"repo": str(repo_path), "files": []}
    for p in repo_path.rglob("*"):
        if not should_scan(p): 
            continue
        if p.is_file():
            file_entry = {"path": str(p), "issues": []}
            file_entry["issues"].extend(scan_file(p))
            report["files"].append(file_entry)
    # Add dependency summaries
    dep_findings = scan_dependencies(repo_path)
    report["dependencies"] = dep_findings
    return report

def main():
    results = []
    for root in REPO_ROOTS:
        repo = Path(root)
        if not repo.exists():
            print(f"WARNING: repo path not found: {repo}", file=sys.stderr)
            continue
        results.append(scan_repo(repo))
    print(json.dumps({"results": results}, indent=2))
    # Optional: exit non-zero if any issues found (for CI gate)
    any_issues = any(len(f["issues"]) > 0 or r["dependencies"] for r in results for f in r["files"])
    sys.exit(1 if any_issues else 0)

if __name__ == "__main__":
    main()

