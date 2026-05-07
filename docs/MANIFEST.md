# Manifest

Faro uses `~/.hermes/.faro-manifest.json` as a whitelist of approved
skills and plugins. Any skill or plugin in the active directories
(`~/.hermes/skills/`, `~/.hermes/hermes-agent/plugins/`) that is NOT
in the manifest is flagged as unvetted.

## Schema

```json
{
  "skill:pixel-art": {
    "name": "pixel-art",
    "path": "/home/user/.hermes/skills/creative/pixel-art",
    "kind": "skill",
    "structure_hash": "a1b2c3d4e5f6a7b8",
    "content_hash": "f1e2d3c4b5a69788",
    "vetted_at": "2026-05-07 12:00:00",
    "scanner_version": "0.2.0"
  }
}
```

### Fields

| Field | Description |
|-------|-------------|
| `name` | Directory name (unique per kind) |
| `path` | Absolute path to the skill/plugin directory |
| `kind` | `skill` or `plugin` |
| `structure_hash` | SHA-256 of file paths + names (fast, for hook) |
| `content_hash` | SHA-256 of .py/.sh/.js/.ts file contents (for deep checks) |
| `vetted_at` | ISO timestamp of last approval/vet |
| `scanner_version` | Faro version that generated this entry |

### Key Format

Keys use `kind:name` format (e.g., `skill:pixel-art`, `plugin:openai`).
This prevents name collisions between skills and plugins.

## Hash Verification

### Structure Hash (default, hook)

The structure hash only includes file paths and names — not contents.
It detects:
- Added files
- Removed files
- Renamed files

It does NOT detect:
- Changes to file contents (same path, different code)

### Content Hash (deep, manual)

The content hash includes actual file contents for `.py`, `.sh`, `.js`,
and `.ts` files. Use `faro check --deep` to verify.

## Migration

### From v0.1.0 to v0.2.0

Manifest keys changed from bare names to `kind:name` format.
**Old manifests are NOT compatible.** After upgrading:

```bash
# Delete old manifest and rebuild
rm ~/.hermes/.faro-manifest.json
faro init-manifest
```

### Future Schema Changes

Faro is 0.x — manifest schema may change without notice between versions.
Always check release notes before upgrading.

## Operations

### Adding an Entry

```bash
faro approve <name>        # From staging (auto-adds to manifest)
faro vet <name>             # Already active
faro init-manifest          # Bulk: all current active items
```

### Removing an Entry

```bash
faro reject <name>          # From staging (auto-removes from manifest)
# Manual: edit ~/.hermes/.faro-manifest.json directly
```

### Checking

```bash
faro check                  # Fast: structure hash only
faro check --deep           # Slow: also checks content hash
```

## Atomicity

Manifest writes use a temp file + rename strategy for crash safety.
However, concurrent writes from multiple `faro` processes may still race.
Faro is designed for single-user operation — avoid running multiple
approve/vet/init-manifest commands simultaneously.
