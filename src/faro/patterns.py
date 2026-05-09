"""Security scan patterns — data-driven, no code in pattern definitions.

v0.5: added 7 agent-audit rule categories, policy YAML loader, compile() fix.
"""

from dataclasses import dataclass
from typing import Optional
import re
import yaml
from pathlib import Path


@dataclass
class ScanPattern:
    """A single security scan rule."""
    id: str
    category: str
    severity: str
    description: str
    regex: Optional[str] = None
    file_glob: str = "*.py"
    remediation: str = ""


# ═══════════════════════════════════════════════════════════════════
# Built-in Hermes skill/plugin rules (core)
# ═══════════════════════════════════════════════════════════════════

CORE_PATTERNS: list[ScanPattern] = [
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
                "compile() — dynamic code compilation", r'(?<!\.)\bcompile\s*\('),

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

    # ── Shell execution chains ──
    ScanPattern("shell-curl-pipe-sh", "dangerous_call", "critical",
                "curl output piped to shell interpreter",
                r'curl\s+.*\|\s*(ba)?sh|curl\s+.*\|\s*bash',
                "*.{sh,py,md,yaml,yml}"),
    ScanPattern("shell-wget-pipe-sh", "dangerous_call", "critical",
                "wget output piped to shell interpreter",
                r'wget\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*bash',
                "*.{sh,py,md,yaml,yml}"),
    ScanPattern("shell-base64-decode-exec", "dangerous_call", "high",
                "base64 decode piped to shell execution",
                r'base64\s+-d.*\||base64\s+--decode.*\|.*sh',
                "*.{sh,py}"),
    ScanPattern("shell-nc-exec", "dangerous_call", "high",
                "netcat with execute flag or reverse shell pattern",
                r'\bnc\s.*-e\b|\bncat\s.*-e\b',
                "*.{sh,py}"),
    ScanPattern("shell-chmod-exec", "dangerous_call", "medium",
                "chmod +x making files executable",
                r'chmod\s+\+x',
                "*.{sh,py,md,yaml,yml}"),

    # ── JS/TS ──
    ScanPattern("js-child-process", "dangerous_call", "high",
                "Node.js child_process — subprocess execution",
                r'child_process|execSync|spawn\s*\(|exec\s*\(',
                "*.{js,ts}"),
    ScanPattern("js-eval-function", "dangerous_call", "critical",
                "JS eval() or new Function() — code injection",
                r'\beval\s*\(|new\s+Function\s*\(',
                "*.{js,ts}"),
    ScanPattern("js-fs-read-sensitive", "credential_leak", "high",
                "fs reading sensitive paths (~/.ssh, ~/.aws, .env, config)",
                r'readFile.*(\.ssh|\.aws|\.config|\.env|\.hermes|keychain|token)',
                "*.{js,ts}"),
    ScanPattern("js-process-env-access", "credential_leak", "medium",
                "process.env access — potential credential exfil",
                r'process\.env\b',
                "*.{js,ts}"),
    ScanPattern("js-axios-fetch-exfil", "network", "medium",
                "HTTP request with dynamic URL or data containing secrets",
                r'(axios\.(post|put)|fetch\s*\()',
                "*.{js,ts}"),

    # ── Package / config scripts ──
    ScanPattern("pkg-json-postinstall", "dangerous_call", "high",
                "package.json postinstall/preinstall script — auto-exec",
                r'"postinstall"\s*:|"preinstall"\s*:',
                "*.json"),
    ScanPattern("pkg-direct-url-dep", "dangerous_call", "high",
                "Direct URL or git dependency (non-registry)",
                r'(git\+https?://|https?://.*\.git|file:.*\.whl)',
                "*.{json,toml,txt}"),
    ScanPattern("cfg-makefile-shell", "dangerous_call", "medium",
                "Makefile/setup.py executing shell commands",
                r'pip\s+install|npm\s+install\s+-g|curl\s+.*\|',
                "Makefile*"),
]

# ═══════════════════════════════════════════════════════════════════
# Agent Audit rules (v0.5) — broader agent asset scanning
# ═══════════════════════════════════════════════════════════════════

# Helper: build ScanPattern safely
def _p(id, cat, sev, desc, regex, glob="*.py", rem=""):
    return ScanPattern(id, cat, sev, desc, regex, glob, rem)

AGENT_AUDIT_PATTERNS: list[ScanPattern] = [
    # ── 7.1 Credential leaks ──
    _p("cred-private-key", "credential_leak", "critical",
       "Private key material leaked",
       r'-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----', "*"),
    _p("cred-oauth-refresh-token", "credential_leak", "critical",
       "OAuth refresh token leaked",
       r'"refresh_token"\s*:\s*"[^"]{20,}"',
       "*.{json,md,py,txt,yaml,yml}"),
    _p("cred-basic-auth-curl", "credential_leak", "critical",
       "curl command with hardcoded Basic Auth credentials",
       "curl\\s+.*-u\\s+.+:.+",
       "*.{md,sh,py,txt}"),

    # ── 7.2 Tool permissions ──
    _p("tool-broad-shell", "tool_permission", "high",
       "Tool permission grants broad shell or wildcard commands",
       r'(\bShell\b|Bash\s*\([^)]*\*[^)]*\)|python3\s+\*|node\s+\*)',
       "*.{md,yaml,yml,json}"),
    _p("tool-unsafe-browser-code", "tool_permission", "high",
       "Browser automation with unsafe code execution",
       r'(browser_run_code_unsafe|mcp__playwright__browser_run_code_unsafe)',
       "*.{md,yaml,yml,json}"),

    # ── 7.3 Side effects ──
    _p("side-effect-git-write", "side_effect", "high",
       "Git write operations (push/commit/merge)",
       r'git\s+(push|commit|merge|tag)|create\s+(PR|MR|pull request|merge request)',
       "*.{md,py,sh,js,ts}"),
    _p("side-effect-doc-write", "side_effect", "high",
       "Document or cloud drive write operations",
       r'(documents\.batchUpdate|spreadsheets\.values\.update|drive\.files\.create|writeback|upload)',
       "*.{md,py,js,ts,json}"),

    # ── 7.4 Sensitive data access (conservative, no broad keywords) ──
    _p("sensitive-data-access", "sensitive_data_access", "medium",
       "Access to sensitive data or internal data systems",
       r'(ClickHouse|BigQuery|Snowflake|Presto|Kafka|Redis|Grafana|customer data|PII)',
       "*.{md,py,sh,js,ts,yaml,yml}"),

    # ── 7.5 Supply chain ──
    _p("supply-chain-install", "supply_chain", "high",
       "Dependency install or remote script execution",
       r'(pip\s+install|npm\s+install|pnpm\s+install|yarn\s+add|curl\s+.*\|\s*(bash|sh))',
       "*.{md,sh,py,js,json}"),
    _p("supply-chain-mcp-server", "supply_chain", "high",
       "MCP server or MCP dependency",
       r'(@modelcontextprotocol|MCP server|"@modelcontextprotocol/sdk")',
       "*.{json,md,js,ts}"),

    # ── 7.6 Persistence ──
    _p("persistence-scheduler", "persistence", "high",
       "Persistent scheduler registration (cron/systemd/launchd)",
       r'(crontab|systemctl\s+enable|launchctl\s+load)',
       "*.{md,py,sh,js,ts}"),
    _p("persistence-agent-hook", "persistence", "high",
       "Agent hook or config modification",
       r'(pre_llm_call|post_llm_call|hooks:)',
       "*.{md,py,sh,js,ts,yaml,yml}"),

    # ── 7.7 Prompt risk (conservative) ──
    _p("prompt-secret-access", "prompt_risk", "high",
       "Prompt instructs reading or extracting sensitive information",
       r'(read.*\.env|read.*credentials|copy.*token|extract.*cookie|dump.*secret)',
       "*.{md,txt,yaml,yml}"),
    _p("prompt-bypass-security", "prompt_risk", "high",
       "Prompt contains security bypass or exfiltration instructions",
       r'(ignore.*security policy|bypass.*permission|bypass.*approval|exfiltrate|hide.*from.*user)',
       "*.{md,txt,yaml,yml}"),
]

# ═══════════════════════════════════════════════════════════════════
# Pattern merge: built-in + agent audit + policy
# ═══════════════════════════════════════════════════════════════════

# Active patterns — core + agent audit by default
PATTERNS: list[ScanPattern] = CORE_PATTERNS + AGENT_AUDIT_PATTERNS

PATTERNS_BY_ID: dict[str, ScanPattern] = {p.id: p for p in PATTERNS}
PATTERNS_BY_CATEGORY: dict[str, list[ScanPattern]] = {}
for p in PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(p.category, []).append(p)
PATTERNS_BY_SEVERITY: dict[str, list[ScanPattern]] = {}
for p in PATTERNS:
    PATTERNS_BY_SEVERITY.setdefault(p.severity, []).append(p)


# ═══════════════════════════════════════════════════════════════════
# Policy loading
# ═══════════════════════════════════════════════════════════════════

def load_policy(policy_path: str) -> list[ScanPattern]:
    """Load external policy YAML and merge with built-in patterns.

    Merging rules:
    - Built-in rules (core + agent audit) are always included.
    - Policy rules are appended.
    - If a policy rule has the same id as a built-in rule, the policy rule
      REPLACES the built-in one (override).
    - Policy can omit 'rules' key — in that case only built-in patterns apply.
    """
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    with open(path, 'r') as f:
        policy = yaml.safe_load(f)

    if not isinstance(policy, dict):
        raise ValueError(f"Policy file must be a YAML mapping, got {type(policy).__name__}")

    policy_rules_data = policy.get("rules", [])
    if not isinstance(policy_rules_data, list):
        raise ValueError(f"Policy 'rules' must be a list, got {type(policy_rules_data).__name__}")

    # Parse policy rules
    policy_patterns: list[ScanPattern] = []
    for i, rule in enumerate(policy_rules_data):
        if not isinstance(rule, dict):
            raise ValueError(f"Policy rule #{i} must be a mapping, got {type(rule).__name__}")
        try:
            # Validate regex compiles
            if rule.get("regex"):
                re.compile(rule["regex"])
            policy_patterns.append(ScanPattern(
                id=rule["id"],
                category=rule.get("category", "custom"),
                severity=rule.get("severity", "medium"),
                description=rule.get("message", rule["id"]),
                regex=rule.get("regex"),
                file_glob=rule.get("file_glob", "*.py"),
                remediation=rule.get("remediation", ""),
            ))
        except re.error as e:
            raise ValueError(
                f"Policy rule '{rule.get('id', f'#{i}')}' has invalid regex: {e}"
            ) from e

    # Merge: start with built-in patterns
    merged: dict[str, ScanPattern] = {p.id: p for p in PATTERNS}

    # Override with policy patterns
    for pp in policy_patterns:
        if pp.id in merged:
            import sys as _sys
            _sys.stderr.write(f"[Faro] Policy overrides built-in rule: {pp.id}\n")
        merged[pp.id] = pp

    return list(merged.values())


def load_policy_config(policy_path: str) -> dict:
    """Load the full policy config dict (profile, discovery, etc.) without merging patterns.

    Returns the raw policy dict for access to profile, discovery, severity_escalation.
    """
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")
    with open(path, 'r') as f:
        return yaml.safe_load(f)
