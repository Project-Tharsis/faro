# Manifest

Faro uses `~/.hermes/.faro-manifest.json` as a whitelist of approved
skills and plugins. Any skill or plugin in the active directories
(`~/.hermes/skills/`, `~/.hermes/hermes-agent/plugins/`) that is NOT
in the manifest is flagged as unvetted.

## Schema (v2)

```json
{
  "skill:creative/pixel-art": {
    "name": "pixel-art",
    "path": "/home/user/.hermes/skills/creative/pixel-art",
    "kind": "skill",
    "relative_path": "creative/pixel-art",
    "structure_hash": "a1b2c3d4e5f6789...",
    "content_hash": "f1e2d3c4b5a69788...",
    "hash_version": 2,
    "vetted_at": "2026-05-08 12:00:00",
    "scanner_version": "0.3.0"
  }
}
```

### Fields

| Field | Description |
|-------|-------------|
| `name` | Directory leaf name |
| `path` | Absolute path to the skill/plugin directory |
| `kind` | `skill` or `plugin` |
| `relative_path` | Path relative to active root (e.g., `creative/pixel-art`) |
| `structure_hash` | SHA-256 of file paths + names (fast, for hook) |
| `content_hash` | SHA-256 of file contents for `.py/.sh/.js/.ts/.md/.yaml/.json/.toml` |
| `hash_version` | Hash algorithm version (v2 = 2) |
| `vetted_at` | ISO timestamp of last approval/vet |
| `scanner_version` | Faro version that generated this entry |

### Key Format (v2)

Keys use `kind:relative_path` format (e.g., `skill:creative/pixel-art`,
`plugin:model-providers/openai`).

- `relative_path` is computed from the active root:
  - Skill: `$FARO_HOME/.hermes/skills`
  - Plugin: `$FARO_HOME/.hermes/hermes-agent/plugins`
- Fallback: old `kind:name` (v1) keys are still recognized during lookup,
  with path verification to prevent name-collision bypass.

This prevents:
- Same-named skills in different parent directories from sharing a manifest entry
- Plugin subdirectories from being mistaken as independent plugins

## Hash Verification (v2)

### Structure Hash (default, hook)

SHA-256 of file relative paths with length-prefixed encoding and version marker.
Full 64-char hexdigest. Detects:
- Added files
- Removed files
- Renamed files

### Content Hash (deep, manual)

SHA-256 of file contents with version marker, length-prefixed relative path,
file size, and content — prevents content-splicing collisions.
Full 64-char hexdigest. Covers:
`.py`, `.sh`, `.js`, `.ts`, `.md`, `.yaml`, `.yml`, `.json`, `.toml`,
`.cfg`, `.ini`, `.txt`

Use `faro check --deep` to verify content hash.

## Migration

### From v0.2.0 to v0.3.0

Manifest keys changed from `kind:name` to `kind:relative_path`.
Hash algorithm upgraded to v2 (full hexdigest, boundary-aware).

**Old manifests have v1 fallback during lookup**, but new entries
always use v2. To fully migrate:

```bash
# Rebuild manifest with v2 keys and hashes
faro init-manifest
```

After migration, `faro check` will verify v2 hashes. Old v1 entries
without `hash_version=2` will show as "structure_changed" until
re-vetted.

## Operations

### Adding an Entry

```bash
faro approve <name>        # From staging (auto-adds to manifest)
faro vet <name>             # Already active
faro init-manifest          # Bulk: all current active items
```

### Removing an Entry

```bash
# Manual: edit ~/.hermes/.faro-manifest.json directly
# reject() no longer removes from manifest — it only clears staging
```

### Checking

```bash
faro check                  # Fast: structure hash only
faro check --deep           # Slow: also checks content hash (.md/.yaml included)
```

## Fail-Closed Behavior

Faro now enforces strict input validation:
- `faro scan <missing-path>` → error, non-zero exit
- `faro scan <unknown-dir>` → error, non-zero exit (no SKILL.md/plugin.yaml/__init__.py)
- `faro prune <invalid-kind>` → error, no deletions
- `faro prune` (no args) → error, requires explicit kind

## Atomicity

Manifest writes use a temp file + rename strategy for crash safety.
However, concurrent writes from multiple `faro` processes may still race.
Faro is designed for single-user operation — avoid running multiple
approve/vet/init-manifest commands simultaneously.
