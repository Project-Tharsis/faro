import re
from dataclasses import dataclass, field
from pathlib import Path
from faro import get_home
from faro.patterns import ScanPattern, PATTERNS
from faro.manifest import _find_skill_dirs


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


@dataclass
class ScanResult:
    path: str
    name: str
    skill_type: str = "skill"
    total_files: int = 0
    script_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    risk_level: str = "none"

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


def _find_files(root: Path, extensions: set[str]) -> list[Path]:
    files = []
    for ext in extensions:
        for f in root.rglob(f"*{ext}"):
            if not any(ex in f.parts for ex in _EXCLUDE_DIRS):
                files.append(f)
    return files


def scan_directory(path: str) -> ScanResult:
    root = Path(path).resolve()

    # Fail closed: path must exist
    if not root.exists():
        result = ScanResult(path=str(root), name=Path(path).name, skill_type="unknown")
        result.risk_level = "error"
        result.findings.append(Finding(
            "scan-path-not-found", "critical", "scanner",
            f"Path not found: {path}", str(root), 0, "", ""
        ))
        return result

    # Fail closed: path must have a known marker
    if not (root / "SKILL.md").exists() and not (root / "plugin.yaml").exists() and not (root / "__init__.py").exists():
        result = ScanResult(path=str(root), name=root.name, skill_type="unknown")
        result.risk_level = "error"
        result.findings.append(Finding(
            "scan-unknown-target", "critical", "scanner",
            f"No SKILL.md, plugin.yaml, or __init__.py found — unknown target",
            str(root), 0, "", ""
        ))
        return result

    name = root.name
    # Infer type from marker files, not path string
    if (root / "SKILL.md").exists():
        skill_type = "skill"
    elif (root / "plugin.yaml").exists() or (root / "__init__.py").exists():
        skill_type = "plugin"
    else:
        skill_type = "unknown"
    result = ScanResult(path=str(root), name=name, skill_type=skill_type)

    all_files = _find_files(root, _TEXT_EXTS)
    scripts = _find_files(root, _SCRIPT_EXTS)
    result.total_files = len(all_files)
    result.script_files = len(scripts)

    # Binary file check
    for f in _find_files(root, _BINARY_EXTS):
        rel = str(f.relative_to(root))
        result.findings.append(Finding("binary-file", "high", "file_access",
            f"Binary file: {f.name}", rel, 0, f.name, f.name))

    # .env file check
    for f in root.rglob(".env"):
        result.findings.append(Finding("env-file", "critical", "credential_leak",
            ".env file in skill", str(f.relative_to(root)), 0, ".env", ".env"))

    # Pattern scan
    for pattern in PATTERNS:
        for file_path in all_files:
            if not _file_glob_match(file_path, pattern.file_glob):
                continue
            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue
            for lineno, line in enumerate(content.split("\n"), 1):
                for m in re.finditer(pattern.regex or "", line):
                    result.findings.append(Finding(
                        pattern.id, pattern.severity, pattern.category,
                        pattern.description, str(file_path.relative_to(root)),
                        lineno, line.strip()[:120], m.group(0)))

    # Scan extensionless config files (Makefile, Dockerfile, etc.)
    _EXTENSIONLESS_PATTERNS = ["Makefile", "Dockerfile", "Gemfile", "Rakefile"]
    for name in _EXTENSIONLESS_PATTERNS:
        f = root / name
        if f.is_file():
            rel = str(f.relative_to(root))
            try:
                content = f.read_text(errors="replace")
            except Exception:
                continue
            for pattern in PATTERNS:
                if not _file_glob_match(f, pattern.file_glob):
                    continue
                for lineno, line in enumerate(content.split("\n"), 1):
                    for m in re.finditer(pattern.regex or "", line):
                        result.findings.append(Finding(
                            pattern.id, pattern.severity, pattern.category,
                            pattern.description, rel,
                            lineno, line.strip()[:120], m.group(0)))

    # Archive file check
    for f in _find_files(root, _ARCHIVE_EXTS):
        rel = str(f.relative_to(root))
        result.findings.append(Finding("archive-file", "high", "file_access",
            f"Archive file: {f.name}", rel, 0, f.name, f.name))

    # Symlink detection
    for f in root.rglob("*"):
        if f.is_symlink():
            rel = str(f.relative_to(root))
            try:
                target = f.resolve()
                if target.is_relative_to(root.resolve()):
                    result.findings.append(Finding(
                        "symlink-internal", "medium", "file_access",
                        f"Internal symlink: {rel} → {target}", rel, 0, f.name, f.name
                    ))
                else:
                    result.findings.append(Finding(
                        "symlink-escape", "critical", "file_access",
                        f"Symlink escape to external path: {rel} → {target}",
                        rel, 0, f.name, f.name
                    ))
            except OSError:
                result.findings.append(Finding(
                    "symlink-broken", "high", "file_access",
                    f"Broken symlink: {rel} (target does not exist)",
                    rel, 0, f.name, f.name
                ))

    # Python AST scan (after regex, for .py files)
    try:
        from faro.python_ast import scan_python_ast
        for file_path in scripts:
            if file_path.suffix == ".py":
                result.findings.extend(scan_python_ast(file_path, root))
    except ImportError:
        pass

    # Risk level
    if result.findings:
        # Sort by severity for consistency
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


def _file_glob_match(file_path: Path, glob_pattern: str) -> bool:
    """Check if file matches a simple extension glob pattern."""
    if not glob_pattern or glob_pattern == "*.py":
        return file_path.suffix == ".py"
    # Handle extensionless patterns like "Makefile*"
    if glob_pattern.endswith("*") and "." not in glob_pattern[:-1]:
        base = glob_pattern[:-1]  # e.g., "Makefile"
        return file_path.name == base or file_path.name.startswith(base)
    # Parse extensions from "*.{ext1,ext2}" or "*.ext"
    inner = glob_pattern.replace("*", "")
    if inner.startswith(".{") and inner.endswith("}"):
        exts = inner[2:-1].split(",")
    else:
        exts = [inner]
    # Normalize: strip leading dot from extensions
    actual = file_path.suffix.lstrip(".")
    return actual in (e.lstrip(".") for e in exts)


def scan_staging(skills_staging: str = None, plugins_staging: str = None) -> list[ScanResult]:
    home = get_home()
    skills_staging = Path(skills_staging) if skills_staging else home / ".hermes" / "skills-staging"
    plugins_staging = Path(plugins_staging) if plugins_staging else home / ".hermes" / "plugins-staging"
    results = []
    for staging_dir, kind in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if not staging_dir.exists():
            continue
        for item in _find_skill_dirs(staging_dir, kind=kind):
            results.append(scan_directory(str(item)))
    return results
