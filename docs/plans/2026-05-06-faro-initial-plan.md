# Faro — Hermes Skill/Plugin Security Pipeline

> **For Hermes:** Implement task-by-task; each task is self-contained.

**Goal:** Prevent unsafe skills/plugins from being activated on Hermes by enforcing
a staging → audit → approve pipeline with automated security scanning.

**Architecture Decision:**
Pure Python CLI + pre_llm_call hook. No Hermes source-code changes. Skills land in
`~/.hermes/skills-staging/` first, get scanned, then approved → moved to
`~/.hermes/skills/`. Same pattern for plugins (`~/.hermes/plugins-staging/`).

**Why not modify Hermes source:**
User iron rule — no source-code changes. Everything is external tooling.

**Preconditions:**
- [x] GitHub repo created: `Project-Tharsis/faro`
- [x] Local directory: `~/faro`
- [x] Python 3.12+ available
- [ ] `~/faro` installed as editable package on the VM

**Tech Stack:** Python 3.12, stdlib-first (subprocess, pathlib, json, re, sqlite3),
optional click for CLI, pytest for tests.

---

## Architecture

```
                    ┌─────────────────────────┐
                    │   hermes-skill-install   │
                    │   (or manual clone)      │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  STAGING                 │
                    │  ~/.hermes/skills-staging│  ← Faro watches this
                    │  ~/.hermes/plugins-staging│
                    └───────────┬─────────────┘
                                │
                        faro scan --staged
                                │
                    ┌───────────▼─────────────┐
                    │  SCANNER ENGINE          │
                    │  src/faro/scanner.py     │
                    │                          │
                    │  • Executable scripts    │
                    │  • Dangerous patterns    │
                    │  • Credential leaks      │
                    │  • External endpoints     │
                    │  • Cookie/keychain access │
                    │  • Config file writes     │
                    │  • Subprocess calls       │
                    │  • Binary files           │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  REPORT                  │
                    │  JSON + human-readable   │
                    │  Risk: critical/high/    │
                    │         medium/low/none  │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  APPROVE (manual)        │
                    │  faro approve <skill>    │
                    │  → move staging → active │
                    │                          │
                    │  faro reject <skill>     │
                    │  → delete from staging   │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  ACTIVE                  │
                    │  ~/.hermes/skills/       │
                    │  ~/.hermes/plugins/      │
                    └─────────────────────────┘
```

### pre_llm_call Hook (Phase 3)

```python
# ~/.hermes/scripts/faro_gate.py
# Runs before each LLM call. Checks if ~/.hermes/skills-staging/
# has unapproved items and warns the agent.
```

**Config (`~/.hermes/config.yaml`):**
```yaml
hooks:
  pre_llm_call:
    - command: "~/faro/src/faro/hook.py"
```

---

## File Tree

```
faro/
├── README.md
├── pyproject.toml
├── src/
│   └── faro/
│       ├── __init__.py
│       ├── scanner.py          # Core scan engine
│       ├── patterns.py         # Danger patterns library
│       ├── reporter.py         # Report generation (JSON + text)
│       ├── staged.py           # Staging manager (list/approve/reject/prune)
│       ├── hook.py             # pre_llm_call hook entry point
│       └── cli.py              # CLI: faro scan|approve|reject|list|prune
├── tests/
│   ├── test_scanner.py
│   ├── test_patterns.py
│   ├── test_staged.py
│   └── fixtures/
│       ├── safe_skill/
│       ├── dangerous_skill/
│       └── cookie_thief_skill/
└── docs/
    └── plans/
        └── 2026-05-06-faro-initial-plan.md
```

---

## Tasks

### Task 1: Project skeleton — pyproject.toml + __init__.py

**Objective:** Create the installable Python package structure.

**Files:**
- Create: `~/faro/pyproject.toml`
- Create: `~/faro/src/faro/__init__.py`

**Step 1: Write pyproject.toml**
```toml
[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "faro"
version = "0.1.0"
description = "Hermes Skill/Plugin security pipeline — staging, audit, approve"
requires-python = ">=3.12"
dependencies = []

[project.scripts]
faro = "faro.cli:main"

[tool.setuptools.package-dir]
"" = "src"

[tool.setuptools.packages.find]
where = ["src"]
```

**Step 2: Write __init__.py**
```python
"""faro — Hermes Skill/Plugin security pipeline."""
__version__ = "0.1.0"
```

**Step 3: Install editable**
```bash
cd ~/faro && pip install -e .
faro --help  # Should show CLI (fail until Task 7)
```

**Step 4: Commit**
```bash
git add pyproject.toml src/faro/__init__.py
git commit -m "feat: project skeleton — pyproject.toml + package init"
```

---

### Task 2: Danger patterns library

**Objective:** Define all security patterns as a data-driven registry.

**File:** Create `~/faro/src/faro/patterns.py`

**Content:**
```python
"""Security scan patterns — data-driven, no code in pattern definitions."""

from dataclasses import dataclass, field
from typing import Callable, Optional
import re

@dataclass
class ScanPattern:
    """A single security scan rule."""
    id: str                          # e.g. "danger-eval"
    category: str                    # "dangerous_call", "credential_leak", "file_access", "network"
    severity: str                    # "critical", "high", "medium", "low"
    description: str                 # Human-readable
    regex: Optional[str] = None      # Raw regex pattern
    file_glob: str = "*.py"          # Which files to scan
    check_fn: Optional[Callable] = None  # For non-regex checks

# ===== PATTERN REGISTRY =====

PATTERNS: list[ScanPattern] = [
    # ── Dangerous function calls ──
    ScanPattern(
        id="danger-eval",
        category="dangerous_call",
        severity="critical",
        description="eval() — arbitrary code execution",
        regex=r'\beval\s*\(',
    ),
    ScanPattern(
        id="danger-exec",
        category="dangerous_call",
        severity="critical",
        description="exec() — arbitrary code execution",
        regex=r'\bexec\s*\(',
    ),
    ScanPattern(
        id="danger-subprocess",
        category="dangerous_call",
        severity="high",
        description="subprocess — external process execution",
        regex=r'\bsubprocess\.',
    ),
    ScanPattern(
        id="danger-os-system",
        category="dangerous_call",
        severity="high",
        description="os.system — shell command execution",
        regex=r'\bos\.system\b',
    ),
    ScanPattern(
        id="danger-os-popen",
        category="dangerous_call",
        severity="high",
        description="os.popen — pipe to shell",
        regex=r'\bos\.popen\b',
    ),
    ScanPattern(
        id="danger-ctypes",
        category="dangerous_call",
        severity="high",
        description="ctypes — native code loading",
        regex=r'\bimport\s+ctypes\b',
    ),
    ScanPattern(
        id="danger-compile",
        category="dangerous_call",
        severity="high",
        description="compile() — dynamic code compilation",
        regex=r'\bcompile\s*\(',
    ),

    # ── Credential / sensitive data access ──
    ScanPattern(
        id="cred-cookie-access",
        category="credential_leak",
        severity="critical",
        description="Browser cookie DB access (cookies.sqlite, Keychain, Chrome Cookies)",
        regex=r'cookies\.sqlite|Chrome Safe Storage|security find-generic-password',
        file_glob="*.{py,sh}",
    ),
    ScanPattern(
        id="cred-keychain",
        category="credential_leak",
        severity="critical",
        description="macOS Keychain access",
        regex=r'security\s+find-generic-password|security\s+find-internet-password',
        file_glob="*.{py,sh}",
    ),
    ScanPattern(
        id="cred-env-read",
        category="credential_leak",
        severity="medium",
        description="Reads .env files (potential credential exposure)",
        regex=r'load_dotenv|\.env.*open|CONFIG_FILE.*\.env',
        file_glob="*.py",
    ),
    ScanPattern(
        id="cred-hardcoded-key",
        category="credential_leak",
        severity="critical",
        description="Hardcoded API key pattern (sk-..., ghp_..., etc.)",
        regex=r'(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})',
        file_glob="*.{py,sh,md,yaml,yml,json}",
    ),
    ScanPattern(
        id="cred-jwt-decode",
        category="credential_leak",
        severity="high",
        description="JWT token decoding (may extract session tokens)",
        regex=r'jwt.*decode|_decode_jwt|jwt\.decode',
        file_glob="*.py",
    ),

    # ── Config file modification ──
    ScanPattern(
        id="config-write",
        category="file_access",
        severity="critical",
        description="Writes to Hermes config.yaml (can override agent behavior)",
        regex=r'config\.yaml.*write|yaml\.dump.*config|CONFIG_PATH.*open.*w',
        file_glob="*.py",
    ),
    ScanPattern(
        id="config-read",
        category="file_access",
        severity="high",
        description="Reads Hermes config.yaml (accesses API keys, model config)",
        regex=r'config\.yaml.*read|yaml\.safe_load.*config|CONFIG_PATH.*open',
        file_glob="*.py",
    ),

    # ── Network / external communication ──
    ScanPattern(
        id="network-socket",
        category="network",
        severity="medium",
        description="Raw socket access",
        regex=r'\bsocket\.',
        file_glob="*.py",
    ),
    ScanPattern(
        id="network-requests",
        category="network",
        severity="low",
        description="HTTP requests (normal for API skills)",
        regex=r'\brequests\.(get|post|put|delete|patch)\b',
        file_glob="*.py",
    ),
    ScanPattern(
        id="network-urllib",
        category="network",
        severity="low",
        description="urllib HTTP calls (normal for API skills)",
        regex=r'\burllib\.request\.',
        file_glob="*.py",
    ),

    # ── System / persistence ──
    ScanPattern(
        id="sys-cron-register",
        category="file_access",
        severity="high",
        description="Registers cron/systemd/launchd (system persistence)",
        regex=r'crontab|cron.*install|systemctl.*enable|launchctl.*load',
        file_glob="*.{py,sh}",
    ),
    ScanPattern(
        id="sys-pip-install",
        category="dangerous_call",
        severity="medium",
        description="pip install in setup scripts (can install arbitrary packages)",
        regex=r'pip\s+install|pip3\s+install',
        file_glob="*.sh",
    ),
]

# Convenience lookups
PATTERNS_BY_ID = {p.id: p for p in PATTERNS}
PATTERNS_BY_CATEGORY: dict[str, list[ScanPattern]] = {}
for p in PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(p.category, []).append(p)
PATTERNS_BY_SEVERITY: dict[str, list[ScanPattern]] = {}
for p in PATTERNS:
    PATTERNS_BY_SEVERITY.setdefault(p.severity, []).append(p)
```

**Verification:**
```bash
cd ~/faro && python -c "from faro.patterns import PATTERNS; print(f'{len(PATTERNS)} patterns loaded')"
# Expected: 17 patterns loaded
```

**Commit:**
```bash
git add src/faro/patterns.py
git commit -m "feat: danger patterns library — 17 security rules"
```

---

### Task 3: Scanner engine

**Objective:** Core scanner that walks a directory, applies patterns, returns findings.

**File:** Create `~/faro/src/faro/scanner.py`

**Content:**
```python
"""Core security scanner for skill/plugin directories."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import re

from faro.patterns import ScanPattern, PATTERNS


@dataclass
class Finding:
    """A single security finding."""
    pattern_id: str
    severity: str          # critical, high, medium, low, info
    category: str
    description: str
    file: str              # Relative path
    line: int
    snippet: str           # The matching line (truncated)
    match: str             # The exact regex match

@dataclass
class ScanResult:
    """Complete scan result for one skill/plugin."""
    path: str
    name: str
    skill_type: str        # "skill" or "plugin"
    total_files: int = 0
    script_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    risk_level: str = "none"  # critical, high, medium, low, none

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")


def _find_executable_scripts(root: Path) -> list[Path]:
    """Find all executable scripts in a directory (Python, Shell, JS, TS, Ruby, Perl)."""
    scripts = []
    for ext in [".py", ".sh", ".js", ".ts", ".rb", ".pl"]:
        scripts.extend(root.rglob(f"*{ext}"))
    # Exclude __pycache__, node_modules, .git
    scripts = [s for s in scripts if "__pycache__" not in str(s)
               and "node_modules" not in str(s)
               and ".git" not in str(s)]
    return scripts


def _find_all_files(root: Path) -> list[Path]:
    """Find all text files in a directory (for credential scans)."""
    text_exts = {".py", ".sh", ".js", ".ts", ".md", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".txt"}
    files = []
    for ext in text_exts:
        files.extend(root.rglob(f"*{ext}"))
    files = [f for f in files if "__pycache__" not in str(f)
             and "node_modules" not in str(f)
             and ".git" not in str(f)]
    return files


def _check_binary_files(root: Path) -> list[Finding]:
    """Scan for binary/compiled files (.so, .o, .pyc, .exe, .dll, .bin)."""
    findings = []
    for ext in [".so", ".o", ".exe", ".dll", ".bin", ".pyd"]:
        for f in root.rglob(f"*{ext}"):
            findings.append(Finding(
                pattern_id="binary-file",
                severity="high",
                category="file_access",
                description=f"Binary/compiled file detected: {f.name}",
                file=str(f.relative_to(root)),
                line=0,
                snippet=f.name,
                match=f.name,
            ))
    return findings


def _check_hidden_env_files(root: Path) -> list[Finding]:
    """Scan for .env files (should never be in skills)."""
    findings = []
    for f in root.rglob(".env"):
        findings.append(Finding(
            pattern_id="env-file-in-skill",
            severity="critical",
            category="credential_leak",
            description=".env file found in skill directory — potential credential leak",
            file=str(f.relative_to(root)),
            line=0,
            snippet=".env file present",
            match=".env",
        ))
    return findings


def scan_directory(path: str) -> ScanResult:
    """Full security scan of a skill or plugin directory.

    Args:
        path: Absolute or relative path to the skill/plugin directory.

    Returns:
        ScanResult with all findings and risk assessment.
    """
    root = Path(path).resolve()
    name = root.name
    skill_type = "plugin" if "plugin" in str(root).lower() else "skill"

    result = ScanResult(path=str(root), name=name, skill_type=skill_type)

    # Phase 1: Find all files
    all_files = _find_all_files(root)
    scripts = _find_executable_scripts(root)
    result.total_files = len(all_files) + len(scripts)  # dedup later if needed
    result.script_files = len(scripts)

    # Phase 2: Binary/compiled file check
    result.findings.extend(_check_binary_files(root))

    # Phase 3: .env file check
    result.findings.extend(_check_hidden_env_files(root))

    # Phase 4: Pattern-based scan on all text files
    for pattern in PATTERNS:
        # Select appropriate files based on file_glob
        for file_path in all_files:
            # Simple glob matching
            if not _file_matches_glob(file_path, pattern.file_glob):
                continue
            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue
            for lineno, line in enumerate(content.split("\n"), 1):
                matches = list(re.finditer(pattern.regex or "", line))
                for m in matches:
                    result.findings.append(Finding(
                        pattern_id=pattern.id,
                        severity=pattern.severity,
                        category=pattern.category,
                        description=pattern.description,
                        file=str(file_path.relative_to(root)),
                        line=lineno,
                        snippet=line.strip()[:120],
                        match=m.group(0),
                    ))

    # Phase 5: Determine overall risk level
    if result.critical_count > 0:
        result.risk_level = "critical"
    elif result.high_count > 0:
        result.risk_level = "high"
    elif result.medium_count > 0:
        result.risk_level = "medium"
    elif result.findings:
        result.risk_level = "low"

    return result


def _file_matches_glob(file_path: Path, glob_pattern: str) -> bool:
    """Simple glob matching for file extensions."""
    if not glob_pattern:
        return True
    # Only support simple *.ext patterns for now
    suffix = glob_pattern.replace("*", "")
    return file_path.suffix in suffix.replace(".", "").split() or file_path.name.endswith(suffix)


def scan_staging(skills_staging: str = None, plugins_staging: str = None) -> list[ScanResult]:
    """Scan all staged skills and plugins.

    Default paths: ~/.hermes/skills-staging/ and ~/.hermes/plugins-staging/
    """
    from pathlib import Path
    home = Path.home()

    if skills_staging is None:
        skills_staging = home / ".hermes" / "skills-staging"
    else:
        skills_staging = Path(skills_staging)

    if plugins_staging is None:
        plugins_staging = home / ".hermes" / "plugins-staging"
    else:
        plugins_staging = Path(plugins_staging)

    results = []

    for staging_dir in [skills_staging, plugins_staging]:
        if not staging_dir.exists():
            continue
        for item in staging_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                results.append(scan_directory(str(item)))

    return results
```

**Verify:**
```bash
cd ~/faro && python -c "
from faro.scanner import scan_directory, ScanResult
# Test on a simple empty dir
import tempfile, os
d = tempfile.mkdtemp()
result = scan_directory(d)
print(f'Files: {result.total_files}, Risk: {result.risk_level}, Findings: {len(result.findings)}')
# Expected: Files: 0, Risk: none, Findings: 0
"
```

**Commit:**
```bash
git add src/faro/scanner.py
git commit -m "feat: core scanner engine — pattern-based security audit"
```

---

### Task 4: Reporter — JSON + human-readable output

**Objective:** Take ScanResult list → produce structured reports.

**File:** Create `~/faro/src/faro/reporter.py`

```python
"""Report generation from scan results."""

import json
from dataclasses import asdict
from typing import Optional
from faro.scanner import ScanResult, Finding


def to_json(results: list[ScanResult], pretty: bool = True) -> str:
    """Serialize scan results to JSON."""
    output = []
    for r in results:
        d = {
            "name": r.name,
            "path": r.path,
            "type": r.skill_type,
            "risk_level": r.risk_level,
            "total_files": r.total_files,
            "script_files": r.script_files,
            "findings_count": len(r.findings),
            "critical": r.critical_count,
            "high": r.high_count,
            "medium": r.medium_count,
            "findings": [asdict(f) for f in r.findings],
        }
        output.append(d)
    indent = 2 if pretty else None
    return json.dumps(output, indent=indent, ensure_ascii=False)


def to_text(results: list[ScanResult]) -> str:
    """Human-readable summary of scan results."""
    lines = []
    lines.append("=" * 60)
    lines.append("FARO SECURITY AUDIT REPORT")
    lines.append("=" * 60)

    for r in results:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}.get(r.risk_level, "⚪")
        lines.append(f"\n{icon} [{r.risk_level.upper()}] {r.name} ({r.skill_type})")
        lines.append(f"   Path: {r.path}")
        lines.append(f"   Files: {r.total_files} ({r.script_files} scripts)")
        lines.append(f"   Findings: {len(r.findings)} ({r.critical_count} critical, {r.high_count} high, {r.medium_count} medium)")

        if r.findings:
            # Group by severity
            for severity in ["critical", "high", "medium", "low"]:
                sev_findings = [f for f in r.findings if f.severity == severity]
                if not sev_findings:
                    continue
                lines.append(f"\n  [{severity.upper()}]")
                for f in sev_findings[:10]:  # Limit per severity
                    lines.append(f"    {f.file}:{f.line} — {f.description}")
                    if f.snippet and f.snippet != f.description:
                        lines.append(f"      > {f.snippet[:100]}")
                if len(sev_findings) > 10:
                    lines.append(f"    ... and {len(sev_findings) - 10} more")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def summary_line(result: ScanResult) -> str:
    """One-line summary for list views."""
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}.get(result.risk_level, "⚪")
    return f"{icon} {result.name:30s} [{result.risk_level:8s}] {result.critical_count}C/{result.high_count}H/{result.medium_count}M"
```

**Verify:**
```bash
cd ~/faro && python -c "
from faro.scanner import scan_directory
from faro.reporter import to_text, to_json
import tempfile
d = tempfile.mkdtemp()
r = scan_directory(d)
print(to_text([r])[:100])
print('---')
print(len(to_json([r])) > 0)
"
```

**Commit:**
```bash
git add src/faro/reporter.py
git commit -m "feat: reporter — JSON + human-readable scan output"
```

---

### Task 5: Staging manager

**Objective:** Manage staging directories — list, approve (move to active), reject (delete).

**File:** Create `~/faro/src/faro/staged.py`

```python
"""Staging directory manager — list, approve, reject."""

from pathlib import Path
import shutil
from typing import Optional
from faro.scanner import scan_directory, ScanResult


def _get_staging_dirs() -> tuple[Path, Path, Path, Path]:
    """Get staging and active directories."""
    home = Path.home()
    return (
        home / ".hermes" / "skills-staging",
        home / ".hermes" / "skills",
        home / ".hermes" / "plugins-staging",
        home / ".hermes" / "hermes-agent" / "plugins",
    )


def list_staged() -> list[dict]:
    """List all staged items with their scan results."""
    skills_staging, _, plugins_staging, _ = _get_staging_dirs()
    items = []

    for staging_dir, kind in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if not staging_dir.exists():
            continue
        for item in sorted(staging_dir.iterdir()):
            if item.is_dir() and not item.name.startswith("."):
                result = scan_directory(str(item))
                items.append({
                    "name": item.name,
                    "path": str(item),
                    "kind": kind,
                    "risk_level": result.risk_level,
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                })
    return items


def approve(name: str, kind: str = "skill", force: bool = False) -> Optional[str]:
    """Approve a staged item and move it to active.

    Args:
        name: Skill/plugin directory name
        kind: 'skill' or 'plugin'
        force: Skip scan check (dangerous — requires explicit flag)

    Returns:
        Destination path, or None on failure.
    """
    skills_staging, skills_active, plugins_staging, plugins_active = _get_staging_dirs()

    if kind == "skill":
        src = skills_staging / name
        dst = skills_active / name
    else:
        src = plugins_staging / name
        dst = plugins_active / name

    if not src.exists():
        print(f"❌ '{name}' not found in {kind}s staging")
        return None

    # Run scan
    result = scan_directory(str(src))

    if result.risk_level in ("critical", "high") and not force:
        print(f"🔴 '{name}' has {result.risk_level} risk ({result.critical_count}C/{result.high_count}H)")
        print(f"   Use --force to approve anyway, or review findings first.")
        return None

    # Move
    if dst.exists():
        print(f"⚠️  '{name}' already exists in active {kind}s. Overwrite? (use --force)")
        if not force:
            return None
        shutil.rmtree(dst)

    shutil.move(str(src), str(dst))
    print(f"✅ Approved: {kind}/{name} → active ({result.risk_level} risk, {len(result.findings)} findings)")
    return str(dst)


def reject(name: str, kind: str = "skill") -> bool:
    """Reject a staged item — permanently deletes from staging."""
    skills_staging, _, plugins_staging, _ = _get_staging_dirs()

    if kind == "skill":
        target = skills_staging / name
    else:
        target = plugins_staging / name

    if not target.exists():
        print(f"❌ '{name}' not found in {kind}s staging")
        return False

    shutil.rmtree(target)
    print(f"🗑️  Rejected: {kind}/{name} deleted from staging")
    return True


def purge_staging(kind: str = "all") -> int:
    """Remove ALL items from staging (dangerous). Returns count removed."""
    skills_staging, _, plugins_staging, _ = _get_staging_dirs()
    count = 0

    for staging_dir in [skills_staging, plugins_staging]:
        if kind not in ("all", "skill") and staging_dir == plugins_staging:
            continue
        if kind not in ("all", "plugin") and staging_dir == skills_staging:
            continue
        if not staging_dir.exists():
            continue
        for item in staging_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                shutil.rmtree(item)
                count += 1

    print(f"🗑️  Purged {count} items from staging")
    return count
```

**Verify:**
```bash
cd ~/faro && python -c "
from faro.staged import _get_staging_dirs
s1, s2, p1, p2 = _get_staging_dirs()
print(f'Skills staging: {s1}')
print(f'Skills active: {s2}')
print(f'Plugins staging: {p1}')
print(f'Plugins active: {p2}')
"
```

**Commit:**
```bash
git add src/faro/staged.py
git commit -m "feat: staging manager — list, approve, reject, purge"
```

---

### Task 6: CLI

**Objective:** `faro` CLI with scan, list, approve, reject, prune commands.

**File:** Create `~/faro/src/faro/cli.py`

```python
"""Faro CLI — Hermes Skill/Plugin security pipeline."""

import sys
from pathlib import Path
from faro.scanner import scan_directory, scan_staging
from faro.reporter import to_text, to_json, summary_line
from faro.staged import list_staged, approve, reject, purge_staging


def cmd_scan(args: list[str]):
    """Scan a skill/plugin or all staged items."""
    if not args or args[0] == "--staged":
        results = scan_staging()
        if not results:
            print("No staged items found.")
            return
        for r in results:
            print(summary_line(r))
        if "--json" in args:
            print(to_json(results))
        elif "--full" in args:
            print(to_text(results))
    else:
        path = args[0]
        result = scan_directory(path)
        if "--json" in args:
            print(to_json([result]))
        else:
            print(to_text([result]))
        sys.exit(1 if result.risk_level in ("critical", "high") else 0)


def cmd_list(args: list[str]):
    """List staged items."""
    items = list_staged()
    if not items:
        print("No staged items.")
        return
    for item in items:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}.get(item["risk_level"], "⚪")
        print(f"{icon} [{item['kind']:6s}] {item['name']:30s} {item['risk_level']:8s} ({item['critical']}C/{item['high']}H/{item['medium']}M)")


def cmd_approve(args: list[str]):
    """Approve a staged item."""
    if not args:
        print("Usage: faro approve <name> [--kind skill|plugin] [--force]")
        return
    name = args[0]
    kind = "skill"
    force = False
    if "--kind" in args:
        idx = args.index("--kind")
        kind = args[idx + 1] if idx + 1 < len(args) else "skill"
    if "--force" in args:
        force = True
    approve(name, kind=kind, force=force)


def cmd_reject(args: list[str]):
    """Reject a staged item."""
    if not args:
        print("Usage: faro reject <name> [--kind skill|plugin]")
        return
    name = args[0]
    kind = "skill"
    if "--kind" in args:
        idx = args.index("--kind")
        kind = args[idx + 1] if idx + 1 < len(args) else "skill"
    reject(name, kind=kind)


def cmd_prune(args: list[str]):
    """Purge all staging."""
    kind = "all"
    if args and args[0] in ("skill", "plugin", "all"):
        kind = args[0]
    purge_staging(kind=kind)


COMMANDS = {
    "scan": (cmd_scan, "Scan a skill/plugin or all staged items"),
    "list": (cmd_list, "List staged items with risk levels"),
    "approve": (cmd_approve, "Approve a staged item → move to active"),
    "reject": (cmd_reject, "Reject a staged item → delete"),
    "prune": (cmd_prune, "Purge all items from staging"),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("faro — Hermes Skill/Plugin Security Pipeline")
        print("\nUsage: faro <command> [args]\n")
        for name, (_, desc) in COMMANDS.items():
            print(f"  {name:10s}  {desc}")
        print("\nExamples:")
        print("  faro scan ~/.hermes/skills-staging/my-skill")
        print("  faro scan --staged --full")
        print("  faro list")
        print("  faro approve my-skill")
        print("  faro reject bad-plugin --kind plugin")
        return

    cmd_name = sys.argv[1]
    if cmd_name not in COMMANDS:
        print(f"Unknown command: {cmd_name}")
        print(f"Available: {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    handler, _ = COMMANDS[cmd_name]
    handler(sys.argv[2:])


if __name__ == "__main__":
    main()
```

**Install and verify:**
```bash
cd ~/faro && pip install -e .
faro --help
```

**Commit:**
```bash
git add src/faro/cli.py
git commit -m "feat: CLI — faro scan|list|approve|reject|prune"
```

---

### Task 7: pre_llm_call hook

**Objective:** Hook that warns about unapproved staged items before each LLM call.

**File:** Create `~/faro/src/faro/hook.py`

```python
#!/usr/bin/env python3
"""Faro pre_llm_call hook — warns agent about unapproved staged skills/plugins.

Sits in the Hermes hooks pipeline. Before each LLM call, checks staging
directories and injects a warning into the conversation context if
unapproved items are found.
"""

import json
import sys
from pathlib import Path


def check_staging() -> list[dict]:
    """Check staging dirs for unapproved items. Returns list of {name, kind, risk}."""
    home = Path.home()
    items = []

    for staging_dir, kind in [
        (home / ".hermes" / "skills-staging", "skill"),
        (home / ".hermes" / "plugins-staging", "plugin"),
    ]:
        if not staging_dir.exists():
            continue
        for item in staging_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                items.append({
                    "name": item.name,
                    "kind": kind,
                    "path": str(item),
                })

    return items


def main():
    """Entry point for pre_llm_call hook.

    Hermes passes the conversation context as JSON on stdin.
    We inject a warning if there are unapproved staged items.
    """
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # Not invoked by Hermes gateway — silent exit
        sys.exit(0)

    staged = check_staging()
    if not staged:
        sys.exit(0)

    # Only warn on feishu platform (where the user can see and act)
    platform = hook_input.get("extra", {}).get("platform", "")
    if platform != "feishu":
        sys.exit(0)

    # Build warning
    names = ", ".join(f"`{s['name']}`({s['kind']})" for s in staged)
    warning = (
        f"\n\n⚠️ **FARO SECURITY ALERT** — Unapproved staged items detected:\n"
        f"{names}\n\n"
        f"Do NOT load or execute these skills/plugins until they pass `faro scan`.\n"
        f"Run `faro list` to review, `faro approve <name>` to activate.\n"
    )

    # Inject into user message (last message in the conversation)
    messages = hook_input.get("messages", [])
    if messages:
        # Append to the last user message
        for msg in reversed(messages):
            if msg.get("role") == "user":
                if isinstance(msg.get("content"), str):
                    msg["content"] = msg["content"] + warning
                elif isinstance(msg.get("content"), list):
                    for block in msg["content"]:
                        if block.get("type") == "text":
                            block["text"] = block["text"] + warning
                            break
                break

    # Output modified context back
    json.dump(hook_input, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
```

**Verify (unit test only — actual hook testing needs Hermes gateway):**
```bash
cd ~/faro && python -c "
from faro.hook import check_staging
staged = check_staging()
print(f'Staged items: {len(staged)}')
"
```

**Install hook config:**
```bash
# Add to ~/.hermes/config.yaml if not present
# hooks:
#   pre_llm_call:
#     - command: \"python ~/faro/src/faro/hook.py\"
```

**Commit:**
```bash
git add src/faro/hook.py
git commit -m "feat: pre_llm_call hook — warns about unapproved staged items"
```

---

### Task 8: README + documentation

**Objective:** Complete project documentation.

**File:** Create `~/faro/README.md`

```markdown
# Faro — Hermes Skill/Plugin Security Pipeline

Staging → Audit → Approve pipeline for Hermes skills and plugins.

## Why

After finding a jailbreak skill (`godmode`) that silently modifies
`~/.hermes/config.yaml`, Hermes needed a security gate before skills
become active. Faro enforces: nothing becomes active without a scan.

## Install

```bash
cd ~/faro
pip install -e .
```

## Usage

```bash
# Install a skill into staging instead of active
mkdir -p ~/.hermes/skills-staging
cp -r some-skill ~/.hermes/skills-staging/

# Scan it
faro scan ~/.hermes/skills-staging/some-skill
faro scan --staged --full

# Review
faro list

# Approve (moves to active)
faro approve some-skill
faro approve risky-one --force

# Reject (deletes)
faro reject bad-skill
```

## Security Rules

17 automated checks across 5 categories:

| Category | Checks |
|----------|--------|
| Dangerous Calls | eval, exec, subprocess, os.system, ctypes, compile |
| Credential Leaks | Cookie DB access, Keychain, hardcoded API keys, JWT decode |
| File Access | Config.yaml read/write, .env in skill |
| Network | Raw sockets, HTTP requests |
| System | Cron/systemd registration, pip install in scripts |

## Risk Levels

| Level | Action |
|-------|--------|
| 🔴 critical | Blocked — requires `--force` |
| 🟠 high | Blocked — requires `--force` |
| 🟡 medium | Warning — can approve |
| 🟢 low | Info — can approve |
| ✅ none | Clean — auto-approvable |

## pre_llm_call Hook

Add to `~/.hermes/config.yaml`:

```yaml
hooks:
  pre_llm_call:
    - command: "python ~/faro/src/faro/hook.py"
hooks_auto_accept: true
```

Warns the agent (and you) when unapproved items sit in staging.

## License

MIT — Project Tharsis
```

**Commit:**
```bash
git add README.md
git commit -m "docs: README — install, usage, security rules reference"
```

---

### Task 9: Push to GitHub

**Objective:** Push all commits to `Project-Tharsis/faro`.

```bash
cd ~/faro
git push -u origin main
```

**Verify:**
```bash
gh repo view Project-Tharsis/faro --web
```

---

## Execution Order

1. Task 1 → skeleton (2 min)
2. Task 2 → patterns (5 min)
3. Task 3 → scanner (10 min)
4. Task 4 → reporter (5 min)
5. Task 5 → staged (5 min)
6. Task 6 → CLI (5 min)
7. Task 7 → hook (5 min)
8. Task 8 → README (3 min)
9. Task 9 → push (1 min)

**Total estimated: ~40 min**

---

## Post-Implementation

After all tasks complete:
1. Create staging directories: `mkdir -p ~/.hermes/{skills-staging,plugins-staging}`
2. Add hook to `~/.hermes/config.yaml`
3. Configure `hermes-skill-install` to land new skills in staging
4. Run `faro scan --staged` as part of daily cron audit
