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
_BINARY_EXTS = {".so", ".o", ".exe", ".dll", ".bin", ".pyd"}
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

    # Risk level
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
