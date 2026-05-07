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

# Or reject (deletes from staging)
faro reject bad-skill
```

## How It Works

```
Install skill → staging/  →  faro scan  →  faro approve  →  active/
                                    ↓
                              faro reject  →  deleted

Hook (pre_llm_call) warns if unapproved items detected in staging or active.
```

## Commands

| Command | Description |
|---------|-------------|
| `faro scan <path>` | Full security scan of a skill/plugin directory |
| `faro scan --staged` | Scan all staged items |
| `faro list` | List staged items with risk levels |
| `faro approve <name>` | Approve staged item → move to active |
| `faro reject <name>` | Reject staged item → delete |
| `faro vet <name>` | Add already-active item to manifest |
| `faro check` | Find active items not in manifest |
| `faro check --deep` | Also verify content hashes |
| `faro init-manifest` | Seed manifest with all current items |

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
```

No special setup required — all tests are fully isolated via `FARO_HOME`.

## Security Rules

Faro runs 19 automated checks across 5 categories:

| Category | Examples | Severity |
|----------|----------|----------|
| Dangerous calls | eval, exec, subprocess, os.system | critical-high |
| Credential leaks | Cookie DB, Keychain, hardcoded keys | critical-high |
| Config access | config.yaml read/write | critical-high |
| Network | Sockets, HTTP requests | low-medium |
| System | Cron/systemd, pip install in scripts | medium-high |

Each finding has a severity: critical, high, medium, or low.
Critical and high findings block approval unless `--force` is used.

## Shallow vs Deep Checks

- **Shallow (default)**: Compares directory structure — file names and paths.
  Catches added/removed/renamed files. Fast enough for the pre_llm_call hook.
- **Deep (`--deep`)**: Also hashes script file contents (.py, .sh, .js, .ts).
  Catches code changes in existing files. Use for manual audits, not in hooks.

Faro does NOT execute any code, analyze call graphs, or sandbox skills.
It is a heuristic pattern scanner — useful as a first line of defense,
not a replacement for manual review.

## Manifest

Faro maintains `~/.hermes/.faro-manifest.json` — a whitelist of approved
skills and plugins. Each entry stores:
- Path and kind (skill/plugin)
- Structure hash (file paths)
- Content hash (script contents, for deep checks)

Skills/plugins in active directories that are NOT in the manifest
are flagged as unvetted.

## Directory Conventions

See [docs/CONVENTIONS.md](docs/CONVENTIONS.md) for what counts as a skill
or plugin, required marker files, and directory layout.

## Limitations

- Faro does NOT execute or sandbox skills — it only scans source text
- Regex-based patterns can produce false positives and false negatives
- Content hash checks are limited to .py, .sh, .js, .ts files
- Designed for single-user Hermes Agent deployments only
- Not a substitute for manual review of third-party skills

## License

MIT — see [LICENSE](LICENSE).
