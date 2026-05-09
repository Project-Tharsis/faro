# Manifest

Faro uses `~/.hermes/.faro-manifest.json` as a whitelist of approved
skills and plugins. Any skill or plugin in the active directories
(`~/.hermes/skills/`, `~/.hermes/hermes-agent/plugins/`) that is NOT
in the manifest is flagged as unvetted.

## Schema (v3)

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
    "scanner_version": "0.7.0",
    "approval_schema_version": 3,
    "owner": "user@example.com",
    "approved_by": "reviewer@example.com",
    "expires_at": "2026-06-08",
    "approval_reason": "reviewed for personal Hermes skill use",
    "approval_source": "approve",
    "migrated_from": null,
    "allowed_findings": [
      {
        "id": "tool-broad-shell",
        "severity": "high",
        "count": 1,
        "files": ["SKILL.md"],
        "reason": "tool call is constrained by prompt and reviewed manually",
        "approved_by": "reviewer@example.com",
        "approved_at": "2026-05-09T12:00:00Z",
        "expires_at": "2026-06-08"
      }
    ]
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
| `approval_schema_version` | Schema version for approval fields (v3 = 3) |
| `owner` | Asset owner email (optional for personal, required for team/enterprise) |
| `approved_by` | Approver email (optional for personal, required for team/enterprise) |
| `expires_at` | Expiry date YYYY-MM-DD, or null for no expiry |
| `approval_reason` | Free-text reason for approval |
| `approval_source` | `approve`, `vet`, or `init-manifest` |
| `migrated_from` | Reserved for future migration tracking |
| `allowed_findings` | List of findings explicitly allowed (audit record, not suppress engine) |

### Approval Metadata (v3)

v0.7 adds approval metadata fields to support audit trails and profile-based
enforcement. All new fields are **optional** — old manifests without them
load normally.

```bash
# Approve with audit trail
faro approve my-skill --owner alice@corp.com --approved-by bob@corp.com --expires 30d

# Vet an already-active item
faro vet my-skill --owner alice@corp.com --expires 2026-12-31

# Allow specific findings
faro approve risky-skill --force --allow tool-broad-shell --reason "reviewed shell access"

# Check with profile enforcement
faro check --profile team --json
```

### Profile Behavior

| Profile | Requires owner | Requires approved_by | Requires expiry | Legacy v2 entry |
|---------|---------------|---------------------|-----------------|-----------------|
| `personal` (default) | No | No (defaults to owner) | No | Silent |
| `team` | Yes (exit 2) | Yes (exit 2) | No | Silent |
| `enterprise` | Yes (exit 2) | Yes (exit 2) | No | Reports `approval_legacy` |

**check reasons (v0.7):**

| Reason | Meaning |
|--------|---------|
| `approval_legacy` | Entry has no `approval_schema_version` (enterprise only) |
| `approval_metadata_missing` | Required fields (owner/approved_by) missing per profile |
| `approval_expired` | `expires_at` is in the past |

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
