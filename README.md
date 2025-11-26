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
# .github/workflows/org-strict-isolation.yml
name: Org strict isolation
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [ main, master ]

permissions:
  contents: read
  packages: read
  actions: read
  checks: write
  # No write permissions to releases, packages, deployments

jobs:
  isolation:
    runs-on: ubuntu-latest
    env:
      CI: true
    steps:
      - name: Checkout (no write, no token persistence)
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Block network egress
        run: |
          sudo iptables -P OUTPUT DROP
          sudo iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT
          echo "Outbound network disabled except localhost."

      - name: Block artifacts, releases, and packages
        run: |
          # Prevent workflows from creating artifacts or releases
          echo "Artifacts and releases are blocked in isolation workflow."
          # Fail if release-related files changed
          changed=$(git diff --name-only origin/${{ github.ref_name }}...HEAD || true)
          if echo "$changed" | grep -Eiq '^\.github/workflows/.*(release|publish).*\.yml$'; then
            echo "Publishing workflow changes detected. Requires approval."
            exit 1
          fi

      - name: Enforce dependency allowlist
        run: |
          set -euo pipefail
          allow='^(requests|numpy|pandas|pytest|typing-extensions)$'
          manifests=$(git ls-files | grep -E '(^requirements\.txt$|^pyproject\.toml$|^Pipfile$|^setup\.(py|cfg)$)' || true)
          violations=0
          if [ -n "$manifests" ]; then
            while read -r f; do
              if [ "$(basename "$f")" = "requirements.txt" ]; then
                pkgs=$(grep -E '^[a-zA-Z0-9_.-]+' "$f" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1)
                for p in $pkgs; do
                  echo "$p" | grep -Eq "$allow" || { echo "Non-allowlisted dependency: $p in $f"; violations=1; }
                done
              else
                # Lightweight grep for package names; adjust for your ecosystem
                for p in flask flask-api sqlalchemy grpc openai; do
                  grep -Eiq "\b$p\b" "$f" && { echo "Gated dependency: $p in $f"; violations=1; }
                done
              fi
            done <<< "$manifests"
          fi
          if [ "$violations" -ne 0 ]; then
            echo "Dependency allowlist violations found."
            exit 1
          fi

      - name: Block editor/IDE configs
        run: |
          set -e
          blocked='^(\.vscode/|\.idea/|\.editorconfig|.*\.code-workspace|.*\.sublime-(project|workspace)|\.vimrc|\.emacs|\.emacs\.d/)'
          files=$(git ls-files)
          echo "$files" | grep -Eiq "$blocked" && { echo "Editor/IDE config files are not allowed."; exit 1; } || true

      - name: Block executable scripts by default
        run: |
          set -e
          git ls-files -s | awk '{print $1" "$4}' | grep -E '^100755 ' && { echo "Executable files detected. Mark non-executable or seek approval."; exit 1; } || true

      - name: Require CODEOWNERS coverage
        run: |
          test -f .github/CODEOWNERS || { echo "Missing .github/CODEOWNERS"; exit 1; }
          echo "CODEOWNERS present."
# .github/workflows/block-editor-configs.yml
name: Block editor/IDE configs
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  checks: write

jobs:
  check-editor-files:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Detect editor/IDE configuration files
        run: |
          set -euo pipefail
          base="${{ github.base_ref }}"
          head="${{ github.head_ref }}"
          # Fallback for push-to-branch PRs
          [ -z "$base" ] && base="origin/${{ github.event.pull_request.base.ref }}"
          changed=$(git diff --name-only "$base"...HEAD || true)

          patterns='^(\.vscode/|\.idea/|\.editorconfig$|\.vimrc$|\.emacs$|\.emacs\.d/|.*\.code-workspace$|.*\.sublime-(project|workspace)$)'
          if echo "$changed" | grep -Eiq "$patterns"; then
            echo "Editor/IDE configuration files detected in PR. Please remove them to keep the repo editor-neutral."
            exit 1
          fi

      - name: Detect formatter/linter configs (optional strict mode)
        run: |
          set -e
          strict='^(\.prettierrc|\.prettier\.config\.js|\.eslintrc(\.json|\.js)?|\.flake8|\.pylintrc|\.clang-format|\.clang-tidy|\.editorconfig)$'
          files=$(git diff --name-only "${{ github.base_ref }}"...HEAD || true)
          echo "$files" | grep -Eiq "$strict" && { echo "Project-level formatting/lint configs are blocked by policy."; exit 1; } || true
# IDEs/editors
.vscode/
.idea/
*.iml
*.code-workspace
*.sublime-project
*.sublime-workspace
.vim/
.vimrc
.emacs
.emacs.d/

# Optional: keep repo fully editor-neutral
.editorconfig

# Language server and tool caches
.pyright/
.mypy_cache/
.pytype/
.cache/
# .github/CODEOWNERS
.vscode/*             @org/platform-team
.idea/*               @org/platform-team
.editorconfig         @org/platform-team
*.code-workspace      @org/platform-team
*.sublime-project     @org/platform-team
*.sublime-workspace   @org/platform-team
.vimrc                @org/platform-team
.emacs                @org/platform-team
.emacs.d/*            @org/platform-team
# .github/workflows/block-all-editors.yml
name: Block editor/IDE configs (strict)
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  checks: write

jobs:
  block-editors:
    runs-on: ubuntu-latest
    env:
      STRICT_ALLOWLIST: "true"  # flip to "false" for less aggressive mode
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Detect changed files
        id: diff
        run: |
          set -euo pipefail
          base="${{ github.base_ref || github.event.pull_request.base.ref }}"
          changed=$(git diff --name-only "origin/$base"...HEAD || true)
          printf "%s\n" "$changed" > changed.txt
          echo "changed<<EOF" >> $GITHUB_OUTPUT
          cat changed.txt >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Block known editor/IDE files
        run: |
          set -euo pipefail
          changed="$(echo "${{ steps.diff.outputs.changed }}")"
          deny_patterns='
            ^\.vscode/
            ^\.idea/
            \.iml$
            ^nbproject/
            ^\.settings/
            ^\.project$
            ^\.classpath$
            \.sublime-(project|workspace)$
            ^\.vim/|^\.nvim/|^\.neovim/|^\.vimrc$|^init\.vim$
            ^\.emacs$|^\.emacs\.d/
            \.code-workspace$
            \.ipr$|\.iws$
            \.sln$|\.vcxproj$|\.csproj$|Directory\.Build\.props$|Directory\.Build\.targets$
            \.xcodeproj($|/)|\.xcworkspace($|/)
            ^\.android/|^AndroidManifest\.xml$|^gradle\.properties$
            ^\.kak/|^kakrc$|^helix/|^\.config/helix/
            ^\.atom/|\.atom-project\.json$
            ^\.monodevelop/
            ^\.metadata/  # Eclipse workspace
            ^\.netbeans/
          '
          violations=0
          echo "$changed" | grep -Eiq "$(echo "$deny_patterns" | tr '\n' '|' | sed 's/|$//')" && violations=1 || true
          if [ "$violations" -eq 1 ]; then
            echo "Editor/IDE configuration or project files detected. These are not allowed in this repo."
            exit 1
          fi
          echo "No known editor/IDE files detected."

      - name: Heuristic block for generic project/workspace files
        run: |
          set -euo pipefail
          changed="$(echo "${{ steps.diff.outputs.changed }}")"
          heuristic='(workspace|project|solution|settings|profiles)\.(json|yaml|yml|xml|plist)$'
          echo "$changed" | grep -Eiq "$heuristic" && { echo "Generic workspace/project/settings files detected."; exit 1; } || true

      - name: Strict allowlist (optional)
        if: env.STRICT_ALLOWLIST == 'true'
        run: |
          set -euo pipefail
          # Only allow source, docs, and minimal config files
          allow='
            ^(src/|lib/|tests/|examples/|docs/|\.github/)
            \.(py|js|ts|tsx|jsx|go|rs|java|kt|c|h|cpp|hpp|cxx|rb|php|sh|bash|zsh|ps1|sql|html|css|scss|md|rst|toml|ini|cfg|conf|json|yaml|yml|txt)$
            ^(Makefile|Dockerfile|\.dockerignore|\.gitignore|\.gitattributes|LICENSE|README\.md|CONTRIBUTING\.md)$
            ^(requirements\.txt|Pipfile|pyproject\.toml|setup\.(py|cfg)|package\.json|pnpm-lock\.yaml|yarn\.lock|go\.mod|Cargo\.toml|Gemfile|composer\.json)$
          '
          violations=0
          while read -r f; do
            [ -z "$f" ] && continue
            echo "$f" | grep -Eiq "$(echo "$allow" | tr '\n' '|' | sed 's/|$//')" || { echo "File not on allowlist: $f"; violations=1; }
          done < changed.txt
          if [ "$violations" -eq 1 ]; then
            echo "Files outside the strict allowlist detected. Please remove or request an exception."
            exit 1
          fi
          echo "Strict allowlist satisfied."
# Block common and emerging editor/IDE artifacts
.vscode/
.idea/
*.iml
nbproject/
.settings/
.project
.classpath
*.sublime-project
*.sublime-workspace
.vim/
.vimrc
.nvim/
init.vim
.emacs
.emacs.d/
*.code-workspace
*.ipr
*.iws
*.sln
*.vcxproj
*.csproj
*.xcodeproj/
*.xcworkspace/
.atom/
.atom-project.json
.monodevelop/
.metadata/
.netbeans/
.kak/
kakrc
helix/
.config/helix/
.android/
# Generic “workspace/project/settings” patterns
**/*workspace.*
**/*project.*
**/*solution.*
**/*settings.*
**/*profiles.*
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: forbid-editor-artifacts
        name: Forbid editor/IDE artifacts
        language: system
        entry: bash -c '
          git diff --cached --name-only |
          grep -E "^(\.vscode/|\.idea/|nbproject/|\.settings/|\.project$|\.classpath$|.*\.sublime-(project|workspace)$|\.vimrc$|\.emacs$|\.emacs\.d/|.*\.code-workspace$|.*\.(ipr|iws|sln|vcxproj|csproj)$|.*\.xcodeproj/|.*\.xcworkspace/|\.atom/|\.monodevelop/|\.metadata/|\.netbeans/|\.kak/|helix/|\.config/helix/)$" &&
          { echo "Editor/IDE artifacts are not allowed."; exit 1; } || exit 0
        '
      - id: forbid-generic-workspace-files
        name: Forbid generic workspace/project/settings files
        language: system
        entry: bash -c '
          git diff --cached --name-only |
          grep -E "(workspace|project|solution|settings|profiles)\.(json|yaml|yml|xml|plist)$" &&
          { echo "Generic workspace/project/settings files are blocked."; exit 1; } || exit 0
        '
# .github/workflows/prevent-self-writes.yml
name: Prevent self-writes
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [ main, master, develop ]

# Make the GITHUB_TOKEN read-only by default
permissions:
  contents: read
  actions: read
  checks: write
  deployments: read
  packages: read
  pull-requests: read

jobs:
  deny-writes:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout (no token write)
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Enforce no write permissions at runtime
        run: |
          set -euo pipefail
          # Block attempts to set higher permissions dynamically
          perm_file=$(grep -ril "^permissions:" .github/workflows || true)
          if [ -n "$perm_file" ]; then
            if grep -Eiq "contents:\s*write|pull-requests:\s*write|packages:\s*write|deployments:\s*write" $perm_file; then
              echo "Write permissions detected in workflows ($perm_file). Not allowed."
              exit 1
            fi
          fi

      - name: Block self-write commands/actions
        run: |
          set -euo pipefail
          changed_workflows=$(git diff --name-only origin/${{ github.ref_name }}...HEAD | grep -E '^\.github/workflows/.*\.yml$' || true)
          files=${changed_workflows:-$(git ls-files '.github/workflows/*.yml' || true)}
          patterns='
            git\s+commit
            git\s+push
            git\s+tag
            gh\s+pr
            gh\s+release
            gh\s+repo
            create-pull-request@   # peter-evans/create-pull-request
            actions-ecosystem/action-create-release@
            softprops/action-gh-release@
            ncipollo/release-action@
          '
          if [ -n "$files" ]; then
            if grep -Eiq "$(echo "$patterns" | tr '\n' '|' | sed 's/|$//')" $files; then
              echo "Write-like commands/actions detected in workflows. Not allowed."
              exit 1
            fi
          fi

      - name: Remove any credentials from git remotes
        run: |
          set -euo pipefail
          git remote -v
          # Ensure remote URL has no embedded token and is HTTPS read-only
          origin_url=$(git remote get-url origin)
          echo "$origin_url" | grep -Eiq '@|token' && { echo "Credentialed remote detected."; exit 1; } || true

      - name: Detect working tree mutations during CI
        run: |
          set -euo pipefail
          # If any prior step modified the tree, fail.
          status=$(git status --porcelain)
          if [ -n "$status" ]; then
            echo "Working tree modified during CI (self-write attempt)."
            echo "$status"
            exit 1
          fi

  block-bot-authors:
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/heads/')
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Fail on bot-authored commits (unless explicitly allowed)
        run: |
          set -euo pipefail
          authors=$(git log -n 10 --pretty='%an <%ae>')
          if echo "$authors" | grep -Eiq 'github-actions

\[bot\]

|bot@users\.noreply\.github\.com|

\[bot\]

|dependabot

\[bot\]

'; then
            echo "Bot-authored commits detected. Blocked by policy."
            exit 1
          fi
- uses: actions/checkout@v4
  with:
    persist-credentials: false
    fetch-depth: 0

- name: Prevent pushes from CI
  run: |
    set -e
    # Remove origin write access (if any step tries to push, it will fail)
    git config --global --unset credential.helper || true
    git remote set-url origin https://github.com/${{ github.repository }}.git
# .github/CODEOWNERS
.github/workflows/*    @org/platform-team
.github/*release*      @org/platform-team
# .github/workflows/immutable-guard.yml
name: Immutable guard
on:
  pull_request:
    types: [opened, synchronize, reopened]
  push:
    branches: [ main, master, develop ]

permissions:
  contents: read
  actions: read
  checks: write
  deployments: read
  packages: read
  pull-requests: read

jobs:
  deny-mutations:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout (no token write)
        uses: actions/checkout@v4
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Block write permissions in workflows
        run: |
          set -euo pipefail
          files=$(git ls-files ".github/workflows/*.yml" || true)
          [ -z "$files" ] && exit 0
          if grep -Eiq "contents:\s*write|pull-requests:\s*write|packages:\s*write|deployments:\s*write" $files; then
            echo "Write permissions detected in workflows. Not allowed."
            exit 1
          fi

      - name: Block write-like actions and commands
        run: |
          set -euo pipefail
          files=$(git ls-files ".github/workflows/*.yml" || true)
          patterns='git\s+commit|git\s+push|git\s+tag|gh\s+pr|gh\s+release|create-pull-request@|release-action@|action-gh-release@'
          [ -z "$files" ] || grep -Eiq "$patterns" $files && { echo "Self-write/publish automation detected."; exit 1; } || true

      - name: Harden git remote and credentials
        run: |
          set -euo pipefail
          git config --global --unset credential.helper || true
          git remote set-url origin https://github.com/${{ github.repository }}.git
          origin_url=$(git remote get-url origin)
          echo "$origin_url" | grep -Eiq '@|token' && { echo "Credentialed remote detected."; exit 1; } || true

      - name: Detect working tree mutations during CI
        run: |
          set -euo pipefail
          status=$(git status --porcelain)
          if [ -n "$status" ]; then
            echo "Working tree modified during CI (mutation attempt)."
            echo "$status"
            exit 1
          fi

  freeze-mode:
    runs-on: ubuntu-latest
    steps:
      - name: Enforce freeze (deny all merges unless emergency label present)
        run: |
          set -euo pipefail
          # Fail PRs unless explicitly labeled "unfreeze-approved"
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            labels=$(printf "%s\n" "${{ join(github.event.pull_request.labels.*.name, ',') }}")
            echo "$labels" | grep -Eiq "(^|,)unfreeze-approved(,|$)" && exit 0
            echo "Repo is in freeze mode. Add 'unfreeze-approved' label after owner review to proceed."
            exit 1
          fi
# .github/CODEOWNERS
# Lock down workflows, manifests, and security-critical files
.github/workflows/*   @org/platform-team
requirements.txt      @org/platform-team
pyproject.toml        @org/platform-team
Pipfile               @org/platform-team
setup.py              @org/platform-team

# Block editor/IDE configs
.vscode/*             @org/platform-team
.idea/*               @org/platform-team
.editorconfig         @org/platform-team
*.code-workspace      @org/platform-team
*.sublime-project     @org/platform-team
*.sublime-workspace   @org/platform-team
# .github/workflows/block-editor-and-risky.yml
name: Block editor configs and risky changes
on: [pull_request]

permissions:
  contents: read
  checks: write

jobs:
  block-editor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Detect editor/IDE configs
        run: |
          set -e
          changed=$(git diff --name-only origin/${{ github.base_ref }}...HEAD || true)
          patterns='^(\.vscode/|\.idea/|\.editorconfig$|.*\.code-workspace$|.*\.sublime-(project|workspace)$|\.vimrc$|\.emacs$|\.emacs\.d/)'
          echo "$changed" | grep -Eiq "$patterns" && { echo "Editor/IDE files are not allowed."; exit 1; } || true

  block-risky:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Deny dependency and publish changes
        run: |
          set -e
          # Fail if publishing workflows or dependency manifests change
          changed=$(git diff --name-only origin/${{ github.base_ref }}...HEAD || true)
          echo "$changed" | grep -Eiq '^\.github/workflows/.*(release|publish).*\.yml$' && { echo "Publish workflow changes blocked."; exit 1; } || true
          echo "$changed" | grep -Eiq '^(requirements\.txt|pyproject\.toml|Pipfile|setup\.(py|cfg))$' && { echo "Dependency manifest changes blocked."; exit 1; } || true
