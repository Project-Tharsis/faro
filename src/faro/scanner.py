"""Security scanner — scans agent asset directories for risks.

v0.5: secret redaction, policy pattern support, generic directory scanning.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from faro import get_home
from faro.patterns import ScanPattern, PATTERNS
from faro.manifest import _find_skill_dirs, _find_symlink_dirs


# ── Categories that get redacted output ─────────────────────────────

REDACT_CATEGORIES = {"credential_leak"}
REDACT_MARKER = "***REDACTED***"


def _redact(text: str) -> str:
    """Redact sensitive content. Replaces complete match with marker."""
    if not text:
        return text
    return REDACT_MARKER


@dataclass
class Finding:
    pattern_id: str
    severity: str
    category: str
    description: str
    file: str
    line: int
    snippet: str
    match: str
    # v0.5: redaction support
    match_redacted: bool = False
    remediation: str = ""

    def redact(self):
        """Redact match and snippet if this is a credential category."""
        if self.category in REDACT_CATEGORIES:
            self.match_redacted = True
            self.match = _redact(self.match)
            if self.snippet:
                self.snippet = _redact(self.snippet)


@dataclass
class ScanResult:
    path: str
    name: str
    skill_type: str = "skill"
    total_files: int = 0
    script_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    risk_level: str = "none"
    # v0.5: policy info
    policy_name: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")


_SCRIPT_EXTS = {".py", ".sh", ".js", ".ts", ".rb", ".pl"}
_TEXT_EXTS = _SCRIPT_EXTS | {".md", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".txt"}
_BINARY_EXTS = {".so", ".o", ".exe", ".dll", ".dylib", ".bin", ".pyd"}
_ARCHIVE_EXTS = {".zip", ".tar", ".tgz", ".tar.gz", ".whl", ".egg"}
_EXCLUDE_DIRS = {"__pycache__", "node_modules", ".git"}


def _find_files(root: Path, extensions: set[str], skip_symlinks: bool = True) -> list[Path]:
    files = []
    for ext in extensions:
        for f in root.rglob(f"*{ext}"):
            if any(ex in f.parts for ex in _EXCLUDE_DIRS):
                continue
            # v0.5: skip symlinks — prevents reading external targets
            if skip_symlinks and f.is_symlink():
                continue
            files.append(f)
    return files


def _check_symlinks(root: Path) -> list[Finding]:
    """Phase 1: detect symlinks BEFORE any file content is read.

    External symlinks = critical (path escape).
    Internal symlinks = medium (benign but flagged).
    Broken symlinks = high.

    IMPORTANT: This runs first so we never read symlink targets
    that point outside the asset directory.
    """
    findings = []
    for f in root.rglob("*"):
        if not f.is_symlink():
            continue
        rel = str(f.relative_to(root))
        try:
            target = f.resolve()
            if target.is_relative_to(root.resolve()):
                findings.append(Finding(
                    "symlink-internal", "medium", "file_access",
                    f"Internal symlink: {rel} -> {target}", rel, 0, f.name, f.name
                ))
            else:
                # External symlink: critical — do NOT read the target
                findings.append(Finding(
                    "symlink-escape", "critical", "file_access",
                    f"Symlink escape to external path: {rel}", rel, 0, f.name, f.name
                ))
        except OSError:
            findings.append(Finding(
                "symlink-broken", "high", "file_access",
                f"Broken symlink: {rel} (target does not exist)",
                rel, 0, f.name, f.name
            ))
    return findings


def _file_glob_match(file_path: Path, glob_pattern: str) -> bool:
    """Check if file matches a simple extension glob pattern."""
    if not glob_pattern:
        return True
    if glob_pattern == "*":
        return True
    if glob_pattern == "*.py":
        return file_path.suffix == ".py"
    # Handle extensionless patterns like "Makefile*"
    if glob_pattern.endswith("*") and "." not in glob_pattern[:-1]:
        base = glob_pattern[:-1]
        return file_path.name == base or file_path.name.startswith(base)
    # Parse extensions from "*.{ext1,ext2}" or "*.ext"
    inner = glob_pattern.replace("*", "")
    if inner.startswith(".{") and inner.endswith("}"):
        exts = inner[2:-1].split(",")
    else:
        exts = [inner]
    actual = file_path.suffix.lstrip(".")
    return actual in (e.lstrip(".") for e in exts)


def scan_directory(
    path: str,
    patterns: list[ScanPattern] = None,
    policy_name: str = "",
    require_marker: bool = True,
) -> ScanResult:
    """Scan a single directory for security risks.

    Args:
        require_marker: If True (default), unknown dirs fail-closed with error.
                        If False (--dirs mode), allow scanning any directory.
    """
    root = Path(path)
    # v0.5.1: detect symlink directory BEFORE resolve
    if root.is_symlink():
        result = ScanResult(path=str(root), name=root.name, skill_type="unknown",
                           policy_name=policy_name)
        result.risk_level = "error"
        result.findings.append(Finding(
            "symlink-dir-escape", "critical", "file_access",
            f"Symlink directory escape: {path}", str(root), 0, path, path
        ))
        return result
    root = root.resolve()
    active_patterns = patterns if patterns is not None else PATTERNS

    # Fail closed: path must exist
    if not root.exists():
        result = ScanResult(path=str(root), name=Path(path).name, skill_type="unknown",
                           policy_name=policy_name)
        result.risk_level = "error"
        result.findings.append(Finding(
            "scan-path-not-found", "critical", "scanner",
            f"Path not found: {path}", str(root), 0, "", ""
        ))
        return result

    # Marker detection
    name = root.name
    if (root / "SKILL.md").exists():
        skill_type = "skill"
    elif (root / "plugin.yaml").exists() or (root / "__init__.py").exists():
        skill_type = "plugin"
    elif require_marker:
        # Fail closed: no known marker found
        result = ScanResult(path=str(root), name=name, skill_type="unknown")
        result.risk_level = "error"
        result.findings.append(Finding(
            "scan-unknown-target", "critical", "scanner",
            f"No SKILL.md, plugin.yaml, or __init__.py found — unknown target",
            str(root), 0, "", ""
        ))
        return result
    else:
        skill_type = "generic"

    result = ScanResult(path=str(root), name=name, skill_type=skill_type,
                       policy_name=policy_name)

    # ══ PHASE 0: Symlink detection (BEFORE any file reading) ══
    result.findings.extend(_check_symlinks(root))

    all_files = _find_files(root, _TEXT_EXTS)
    scripts = _find_files(root, _SCRIPT_EXTS)
    result.total_files = len(all_files)
    result.script_files = len(scripts)

    # Binary file check (skip symlinks)
    for f in _find_files(root, _BINARY_EXTS):
        rel = str(f.relative_to(root))
        result.findings.append(Finding("binary-file", "high", "file_access",
            f"Binary file: {f.name}", rel, 0, f.name, f.name))

    # .env file check (skip symlinks)
    for f in root.rglob(".env"):
        if f.is_symlink():
            continue
        result.findings.append(Finding("env-file", "critical", "credential_leak",
            ".env file in asset", str(f.relative_to(root)), 0, ".env", ".env"))

    # Pattern scan
    NL = '\n'
    for pattern in active_patterns:
        for file_path in all_files:
            if not _file_glob_match(file_path, pattern.file_glob):
                continue
            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue
            for lineno, line in enumerate(content.split(NL), 1):
                for m in re.finditer(pattern.regex or "", line):
                    f = Finding(
                        pattern.id, pattern.severity, pattern.category,
                        pattern.description, str(file_path.relative_to(root)),
                        lineno, line.strip()[:120], m.group(0),
                        remediation=pattern.remediation,
                    )
                    f.redact()
                    result.findings.append(f)

    # Scan extensionless config files
    _EXTENSIONLESS_PATTERNS = ["Makefile", "Dockerfile", "Gemfile", "Rakefile"]
    for name in _EXTENSIONLESS_PATTERNS:
        f = root / name
        if f.is_file():
            rel = str(f.relative_to(root))
            try:
                content = f.read_text(errors="replace")
            except Exception:
                continue
            for pattern in active_patterns:
                if not _file_glob_match(f, pattern.file_glob):
                    continue
                for lineno, line in enumerate(content.split(NL), 1):
                    for m in re.finditer(pattern.regex or "", line):
                        finding = Finding(
                            pattern.id, pattern.severity, pattern.category,
                            pattern.description, rel,
                            lineno, line.strip()[:120], m.group(0),
                            remediation=pattern.remediation,
                        )
                        finding.redact()
                        result.findings.append(finding)

    # Archive file check
    for f in _find_files(root, _ARCHIVE_EXTS):
        rel = str(f.relative_to(root))
        result.findings.append(Finding("archive-file", "high", "file_access",
            f"Archive file: {f.name}", rel, 0, f.name, f.name))

    # Python AST scan
    try:
        from faro.python_ast import scan_python_ast
        for file_path in scripts:
            if file_path.suffix == ".py":
                ast_findings = scan_python_ast(file_path, root)
                for af in ast_findings:
                    af.redact()
                result.findings.extend(ast_findings)
    except ImportError:
        pass

    # v0.5.1: deduplicate sensitive_data_access (per matched term, first file only)
    # This category generates high noise — one asset referencing ClickHouse/Kafka/Redis
    # across many files can produce hundreds of identical findings.
    _NOISY_CATEGORIES = {"sensitive_data_access"}
    seen_terms: dict[str, set[str]] = {}
    deduped = []
    for f in result.findings:
        if f.category in _NOISY_CATEGORIES:
            key = f.pattern_id
            if key not in seen_terms:
                seen_terms[key] = set()
            term = f.match
            if term in seen_terms[key]:
                continue  # duplicate matched term
            seen_terms[key].add(term)
        deduped.append(f)
    result.findings = deduped

    # Risk level
    if result.findings:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        result.findings.sort(key=lambda f: sev_order.get(f.severity, 99))

    if result.critical_count > 0:
        result.risk_level = "critical"
    elif result.high_count > 0:
        result.risk_level = "high"
    elif result.medium_count > 0:
        result.risk_level = "medium"
    elif result.findings:
        result.risk_level = "low"
    return result


def scan_dirs(
    dirs: list[str],
    patterns: list[ScanPattern] = None,
    policy_name: str = "",
) -> list[ScanResult]:
    """Scan multiple directories (for --dirs flag). No marker required."""
    results = []
    for d in dirs:
        results.append(scan_directory(d, patterns=patterns, policy_name=policy_name, require_marker=False))
    return results


def scan_staging(
    skills_staging: str = None,
    plugins_staging: str = None,
    patterns: list[ScanPattern] = None,
    policy_name: str = "",
) -> list[ScanResult]:
    """Scan all items in staging directories."""
    home = get_home()
    skills_staging = Path(skills_staging) if skills_staging else home / ".hermes" / "skills-staging"
    plugins_staging = Path(plugins_staging) if plugins_staging else home / ".hermes" / "plugins-staging"
    results = []
    for staging_dir, kind in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if not staging_dir.exists():
            continue
        # v0.5.3: symlink dirs first (always critical/error)
        for symlink_dir in _find_symlink_dirs(staging_dir):
            results.append(scan_directory(str(symlink_dir), patterns=patterns, policy_name=policy_name))
        # Real skill/plugin dirs
        for item in _find_skill_dirs(staging_dir, kind=kind):
            results.append(scan_directory(str(item), patterns=patterns, policy_name=policy_name))
    return results
