# Faro — Security audit skill for Hermes Agent

> ⚠️ Faro is a heuristic pattern-based scanner for Hermes Agent skills/plugins.
> It is NOT a sandbox, NOT a static analyzer, and does NOT guarantee safety.
> Always review scan results manually before approving.
>
> Faro is designed for single-user, single-machine Hermes Agent deployments.
> Multi-user or multi-instance setups are explicitly out of scope.

Faro enforces a **staging → audit → approve** pipeline for Hermes Agent skills
and plugins. Nothing becomes active without passing a security scan.

## Quick Start

```bash
# Install from GitHub
pip install git+https://github.com/Project-Tharsis/faro.git

# Create staging directories
mkdir -p ~/.hermes/skills-staging ~/.hermes/plugins-staging

# Seed the manifest with your current skills
faro init-manifest

# Install a new skill into staging (NOT directly into active)
cp -r new-skill ~/.hermes/skills-staging/

# Scan it
faro scan ~/.hermes/skills-staging/new-skill

# Review all staged items
faro list

# Approve (moves to active, adds to manifest)
faro approve new-skill

# Or reject (deletes from staging — does NOT touch manifest)
faro reject bad-skill
```

## How It Works

```
Install skill → staging/  →  faro scan  →  faro approve  →  active/
                                   ↓
                             faro reject  →  deleted from staging

Hook (pre_llm_call) warns if unapproved items detected in staging or active.
```

## Commands

| Command | Description |
|---------|-------------|
| `faro scan <path>` | Full security scan of a skill/plugin directory (path must exist + have markers) |
| `faro scan --staged` | Scan all staged items |
| `faro scan --policy <file>` | Scan assets discovered by policy `discovery.generic` config |
| `faro scan --dirs a,b,c` | Scan explicit generic directories (no marker required) |
| `faro list` | List staged items with risk levels |
| `faro approve <name>` | Approve staged item → move to active. Use `--owner`, `--approved-by`, `--expires`, `--allow`, `--reason` for audit trail |
| `faro reject <name>` | Reject staged item → delete from staging (does NOT modify manifest) |
| `faro prune <skill\|plugin\|all>` | Purge staging (explicit kind required) |
| `faro vet <name>` | Add already-active item to manifest |
| `faro check` | Find active items not in manifest |
| `faro check --deep` | Also verify content hashes (.md/.yaml included) |
| `faro report --policy <file>` | Generate aggregate report from policy discovery |
| `faro report --format markdown\|json` | Output format for report |
| `faro init-manifest` | Seed manifest with all current items |

### Policy-Driven Discovery (v0.6)

Faro supports scanning generic agent assets — not just Hermes skills/plugins.
Use an external YAML policy file to declare asset containers:

```yaml
# policy.yaml
version: 1
name: team-agent-policy
discovery:
  generic:
    - path: agents/
      marker: "*.md"
      kind: agent_prompt
    - path: hooks/
      marker: "*.py"
      kind: hook
rules:
  - id: custom-no-rm-rf
    severity: critical
    category: dangerous_call
    file_glob: "*.{sh,py,md}"
    regex: "rm\\s+-rf\\s+/"
    message: "Dangerous delete command"
```

```bash
faro scan --policy policy.yaml --json
faro report --policy policy.yaml --format markdown
```

### Discovery Path Guardrails

Faro explicitly rejects broad/root-like scan paths to prevent unintended
repo-wide or full-disk scans:

| Path | Status |
|------|--------|
| `.`, `./`, `..`, `../`, `~`, `~/`, `/` | ❌ Rejected (exit 2) |
| Policy path with `..` segment (e.g. `../agents`) | ❌ Rejected (exit 2) |
| `~/.hermes/skills-staging` | ✅ Allowed |
| `~/.hermes/plugins-staging` | ✅ Allowed |
| `agents/`, `hooks/`, `mcp/` | ✅ Allowed |
| `/absolute/path/to/explicit/agents` | ✅ Allowed |

Faro is NOT a repo scanner or system scanner. It is designed for explicit
agent asset containers — Hermes staging dirs, policy-declared directories,
or user-specified asset directories via `--dirs`.

### Approval Metadata (v0.7)

`faro approve` and `faro vet` support audit-trail metadata:

```bash
# Approve with owner, expiry, and allowed findings
faro approve my-skill \
  --owner alice@corp.com \
  --approved-by bob@corp.com \
  --expires 30d \
  --allow tool-broad-shell --reason "reviewed shell access"

# Vet an already-active item
faro vet my-skill --owner alice@corp.com --expires 2026-12-31

# Check with profile enforcement
faro check --profile team --json
```

| Profile | Requires owner | Requires approved_by | Requires expiry |
|---------|---------------|---------------------|-----------------|
| `personal` (default) | No | No (defaults to owner) | No |
| `team` | Yes | Yes | No |
| `enterprise` | Yes | Yes | No |

`check --profile` reports: `approval_legacy` (no v3 schema), `approval_metadata_missing`
(missing required fields), `approval_expired` (past expiry date).

All new fields are **optional** — old manifest entries load without migration.

### Fail-Closed Behavior

- `faro scan <missing-path>` → error, non-zero exit
- `faro scan <dir-without-markers>` → error, non-zero exit
- `faro prune <invalid-kind>` → error, no deletions
- `faro prune` (no args) → error, requires explicit kind

## Hook Integration

Add to `~/.hermes/config.yaml`:

```yaml
hooks:
  pre_llm_call:
    - command: "python -m faro.hook"
hooks_auto_accept: true
```

The hook runs before each LLM call. It checks:
- **Staging dirs** — unapproved items → warns
- **Active dirs vs manifest** — unvetted items → warns

Default mode is fast (structure hash only). Use `faro check --deep` to also
verify file contents haven't changed since approval.

## Development

### Override home directory

Faro targets `~/.hermes/` by default. Set `FARO_HOME` to redirect all paths
to a different directory — useful for testing or multi-instance setups:

```bash
FARO_HOME=/tmp/faro-test faro scan --staged
FARO_HOME=/tmp/faro-test faro list
```

Integration tests use this mechanism to run in a `tempfile.TemporaryDirectory`
without touching the real `~/.hermes`.

### Running tests

```bash
pip install -e ".[dev]"
pytest -q
# 100 tests: discovery, manifest, staging, scanning, identity, hashing, fail-closed
```

No special setup required — all tests are fully isolated via `FARO_HOME`.

## Security Rules

Faro runs 31+ automated checks across 8 categories:

| Category | Examples | Severity |
|----------|----------|----------|
| Dangerous calls | eval, exec, subprocess, os.system, ctypes | critical-high |
| Credential leaks | Cookie DB, Keychain, hardcoded keys, .env read, JWT decode | critical-high |
| Config access | config.yaml read/write | critical-high |
| Shell execution | curl\|sh, wget\|bash, base64 -d\|sh, nc -e, chmod +x | critical-medium |
| Network | Sockets, HTTP requests, urllib | low-medium |
| System | Cron/systemd, pip install in scripts | medium-high |
| JS/TS | child_process, eval(), new Function(), fs readFile, process.env | critical-medium |
| Package/config | package.json postinstall, direct URL/git deps, Makefile | high-medium |

Each finding has a severity: critical, high, medium, or low.
Critical and high findings block approval unless `--force` is used.

## Shallow vs Deep Checks

- **Shallow (default)**: Compares directory structure — file names and paths.
  Catches added/removed/renamed files. Fast enough for the pre_llm_call hook.
- **Deep (`--deep`)**: Also hashes file contents for `.py`, `.sh`, `.js`, `.ts`,
  `.md`, `.yaml`, `.yml`, `.json`, `.toml`, `.cfg`, `.ini`, `.txt`.
  Catches code changes in existing files. Use for manual audits, not in hooks.

Faro does NOT execute any code, analyze call graphs, or sandbox skills.
It is a heuristic pattern scanner — useful as a first line of defense,
not a replacement for manual review.

## Manifest (v2)

Faro maintains `~/.hermes/.faro-manifest.json` — a whitelist of approved
skills and plugins. Each entry stores:

- Path and kind (skill/plugin)
- `relative_path` — path from active root (e.g., `creative/pixel-art`)
- Structure hash (file paths, full SHA-256 hexdigest)
- Content hash (file contents, full SHA-256 hexdigest with boundary encoding)
- `hash_version` — v2

### Key Format

Keys use `kind:relative_path` (e.g., `skill:creative/pixel-art`).
Old `kind:name` (v1) keys have automatic fallback during lookup with
path verification. New entries always use v2.

Skills/plugins in active directories that are NOT in the manifest
are flagged as unvetted.

See [docs/MANIFEST.md](docs/MANIFEST.md) for full schema and migration guide.

## Directory Conventions

See [docs/CONVENTIONS.md](docs/CONVENTIONS.md) for what counts as a skill
or plugin, required marker files, and directory layout.

## Limitations

- Faro does NOT execute or sandbox skills — it only scans source text
- Regex-based patterns can produce false positives and false negatives
- Python `from subprocess import run` patterns may bypass regex rules
  (planned: AST-level scanner in v0.4.0)
- Designed for single-user Hermes Agent deployments only
- Not a substitute for manual review of third-party skills

## License

MIT — see [LICENSE](LICENSE).
