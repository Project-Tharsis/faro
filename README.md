# Faro — Hermes Skill/Plugin Security Pipeline

Staging → Audit → Approve pipeline. Nothing becomes active without a scan.

## Install

```bash
cd ~/faro
pip install -e .
mkdir -p ~/.hermes/skills-staging ~/.hermes/plugins-staging
```

## Usage

```bash
# Scan
faro scan ~/.hermes/skills-staging/some-skill
faro scan --staged --full

# List staged
faro list

# Approve / Reject
faro approve some-skill
faro approve risky-one --force
faro reject bad-skill
faro reject bad-plugin --kind plugin

# Full JSON report
faro scan ~/path/to/skill --json
```

## pre_llm_call Hook

Add to `~/.hermes/config.yaml`:

```yaml
hooks:
  pre_llm_call:
    - command: "python ~/faro/src/faro/hook.py"
hooks_auto_accept: true
```

Warns when unapproved items sit in staging.

## Security Rules — 19 Checks

| Category | Checks | Severity |
|----------|--------|----------|
| Dangerous Calls | eval, exec, subprocess, os.system, os.popen, ctypes, compile | critical-high |
| Credential Leaks | Cookie DB, Keychain, hardcoded keys, JWT decode, .env read | critical-high |
| Config Access | config.yaml read/write | critical-high |
| Network | Raw sockets, HTTP requests, urllib | low-medium |
| System | Cron/systemd, pip install in scripts | medium-high |

## Risk → Action

| Level | Action |
|-------|--------|
| 🔴 critical | Blocked — requires `--force` |
| 🟠 high | Blocked — requires `--force` |
| 🟡 medium | Warning |
| 🟢 low | Info |
| ✅ none | Clean |

## License

MIT — Project Tharsis
