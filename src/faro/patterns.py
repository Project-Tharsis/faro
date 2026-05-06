"""Security scan patterns — data-driven, no code in pattern definitions."""

from dataclasses import dataclass
from typing import Optional
import re


@dataclass
class ScanPattern:
    """A single security scan rule."""
    id: str
    category: str
    severity: str
    description: str
    regex: Optional[str] = None
    file_glob: str = "*.py"


PATTERNS: list[ScanPattern] = [
    # ── Dangerous function calls ──
    ScanPattern("danger-eval", "dangerous_call", "critical",
                "eval() — arbitrary code execution", r'\beval\s*\('),
    ScanPattern("danger-exec", "dangerous_call", "critical",
                "exec() — arbitrary code execution", r'\bexec\s*\('),
    ScanPattern("danger-subprocess", "dangerous_call", "high",
                "subprocess — external process execution", r'\bsubprocess\.'),
    ScanPattern("danger-os-system", "dangerous_call", "high",
                "os.system — shell command execution", r'\bos\.system\b'),
    ScanPattern("danger-os-popen", "dangerous_call", "high",
                "os.popen — pipe to shell", r'\bos\.popen\b'),
    ScanPattern("danger-ctypes", "dangerous_call", "high",
                "ctypes — native code loading", r'\bimport\s+ctypes\b'),
    ScanPattern("danger-compile", "dangerous_call", "high",
                "compile() — dynamic code compilation", r'\bcompile\s*\('),

    # ── Credential / sensitive data access ──
    ScanPattern("cred-cookie-access", "credential_leak", "critical",
                "Browser cookie DB access",
                r'cookies\.sqlite|Chrome Safe Storage|security find-generic-password',
                "*.{py,sh}"),
    ScanPattern("cred-keychain", "credential_leak", "critical",
                "macOS Keychain access",
                r'security\s+find-generic-password|security\s+find-internet-password',
                "*.{py,sh}"),
    ScanPattern("cred-env-read", "credential_leak", "medium",
                "Reads .env files", r'load_dotenv|\.env.*open|CONFIG_FILE.*\.env'),
    ScanPattern("cred-hardcoded-key", "credential_leak", "critical",
                "Hardcoded API key (sk-..., ghp_..., AKIA...)",
                r'(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})',
                "*.{py,sh,md,yaml,yml,json}"),
    ScanPattern("cred-jwt-decode", "credential_leak", "high",
                "JWT token decoding", r'jwt.*decode|_decode_jwt|jwt\.decode'),

    # ── Config file modification ──
    ScanPattern("config-write", "file_access", "critical",
                "Writes to Hermes config.yaml",
                r'config\.yaml.*write|yaml\.dump.*config|CONFIG_PATH.*open.*w'),
    ScanPattern("config-read", "file_access", "high",
                "Reads Hermes config.yaml",
                r'config\.yaml.*read|yaml\.safe_load.*config|CONFIG_PATH.*open'),

    # ── Network ──
    ScanPattern("network-socket", "network", "medium",
                "Raw socket access", r'\bsocket\.'),
    ScanPattern("network-requests", "network", "low",
                "HTTP requests (normal for API skills)",
                r'\brequests\.(get|post|put|delete|patch)\b'),
    ScanPattern("network-urllib", "network", "low",
                "urllib HTTP calls", r'\burllib\.request\.'),

    # ── System / persistence ──
    ScanPattern("sys-cron-register", "file_access", "high",
                "Registers cron/systemd/launchd",
                r'crontab|cron.*install|systemctl.*enable|launchctl.*load',
                "*.{py,sh}"),
    ScanPattern("sys-pip-install", "dangerous_call", "medium",
                "pip install in setup scripts", r'pip\s+install|pip3\s+install',
                "*.sh"),
]

PATTERNS_BY_ID = {p.id: p for p in PATTERNS}
PATTERNS_BY_CATEGORY: dict[str, list[ScanPattern]] = {}
for p in PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(p.category, []).append(p)
PATTERNS_BY_SEVERITY: dict[str, list[ScanPattern]] = {}
for p in PATTERNS:
    PATTERNS_BY_SEVERITY.setdefault(p.severity, []).append(p)
