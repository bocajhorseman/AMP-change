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
# .github/workflows/hardened.yml
name: Hardened CI
on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]

permissions:
  contents: read
  actions: read
  checks: write
  # No write to packages, deployments, or environments by default

# Only run on GitHub-hosted runners
# Optionally lock to self-hosted with strict network rules
jobs:
  static-checks:
    runs-on: ubuntu-latest
    env:
      # Never expose secrets to PRs from forks
      CI: true
    steps:
      - name: Checkout (no token write)
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Block network calls
        run: |
          echo "127.0.0.1 api.openai.com" | sudo tee -a /etc/hosts
          echo "127.0.0.1 pypi.org" | sudo tee -a /etc/hosts
          echo "127.0.0.1 files.pythonhosted.org" | sudo tee -a /etc/hosts

      - name: Dependency keywords gate
        run: |
          set -e
          patterns='flask|flask-api|sqlalchemy'
          files=$(git ls-files | grep -E 'requirements\.txt|pyproject\.toml|Pipfile|setup\.(py|cfg)')
          if [ -n "$files" ]; then
            if grep -Eiq "$patterns" $files; then
              echo "Found gated dependencies. Manual review required."
              exit 1
            fi
          fi

      - name: Keyword scan gate
        run: |
          set -e
          grep -Eriq '\b(flask|flask[_-]?api|sqlalchemy)\b' . && { echo "Framework keywords detected"; exit 1; } || true

  # Any job that needs secrets must go through an environment with approvals
  approved-deploy:
    needs: static-checks
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://example.invalid
    steps:
      - name: Stop unless environment approved
        run: echo "This job only runs after environment approval."
# .github/workflows/require-approval.yml
name: Require approval for workflows that use secrets
on:
  workflow_dispatch:
  pull_request:

permissions:
  contents: read

jobs:
  approval_gate:
    runs-on: ubuntu-latest
    steps:
      - name: Check if run is from a fork
        run: |
          if [ "${{ github.event.pull_request.head.repo.fork }}" = "true" ]; then
            echo "Fork detected: secrets and deployments are blocked."
            exit 1
          fi
      - name: Manual approval required
        run: |
          echo "Request approval via environment protections or a CODEOWNERS review."
          exit 1
# .github/CODEOWNERS
# All workflows require platform team review
.github/workflows/*   @org/platform-team

# Dependency manifests require backend team review
requirements.txt      @org/backend-team
pyproject.toml        @org/backend-team
Pipfile               @org/backend-team
setup.py              @org/backend-team

# Any Flask/SQLAlchemy-related code path requires security review
**/*flask*            @org/security-team
**/*sqlalchemy*       @org/security-team
# .pre-commit-config.yaml snippet
repos:
  - repo: local
    hooks:
      - id: block-executables
        name: Block executable files
        entry: bash -c 'git ls-files -s | awk "{print \$1}" | grep -qE "^100755$" && { echo \"Executable files detected\"; exit 1; } || exit 0'
        language: system
# IDEs/editors
.vscode/
.idea/
*.iml
*.sublime-project
*.sublime-workspace
.vim/
.vimrc
.emacs.d/
.emacs
.spacemacs
*.code-workspace

# EditorConfig (optional, if you don't want repo-level editor rules)
.editorconfig

# Language servers and tooling caches
.pyright/
.mypy_cache/
.pytype/
.cache/
# .github/workflows/block-editor-configs.yml
name: Block editor configs
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  check-editor-files:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout (no write)
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Detect editor configs
        run: |
          set -euo pipefail
          blocked_patterns=(
            '^\.vscode/'
            '^\.idea/'
            '\.sublime-(project|workspace)$'
            '^\.editorconfig$'
            '^\.vimrc$'
            '^\.emacs$'
            '^\.emacs\.d/'
            '\.code-workspace$'
          )
          changed=$(git diff --name-only origin/${{ github.base_ref }}...HEAD || true)
          violations=0
          for pat in "${blocked_patterns[@]}"; do
            echo "$changed" | grep -E "$pat" && violations=1 || true
          done
          if [ "$violations" -eq 1 ]; then
            echo "Editor-specific configuration files detected. Please remove them to keep editors unaffected."
            exit 1
          fi
          echo "No editor config files detected."
# .github/CODEOWNERS
# Any editor/IDE config must be reviewed (and generally rejected)
.vscode/*     @org/platform-team
.idea/*       @org/platform-team
.editorconfig @org/platform-team
*.code-workspace @org/platform-team
*.sublime-project @org/platform-team
*.sublime-workspace @org/platform-team
