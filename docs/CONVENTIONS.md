# Directory Conventions

Faro expects skills and plugins to follow Hermes Agent conventions.
This document defines what counts as a "skill" or "plugin" for Faro's
discovery and scanning.

## Skill Directory

A **skill** is any directory containing a `SKILL.md` file.

```
~/.hermes/skills/
├── creative/            # ← category dir (NOT a skill)
│   ├── pixel-art/       # ← skill (contains SKILL.md)
│   │   ├── SKILL.md
│   │   ├── scripts/
│   │   └── references/
│   └── ascii-art/       # ← skill
│       └── SKILL.md
└── feishu/              # ← category dir (NOT a skill)
    └── feishu-card-authoring/  # ← skill
        └── SKILL.md
```

**Marker file:** `SKILL.md`

Skills can be nested under category directories. Faro scans recursively
but only counts directories with `SKILL.md` as skills. Category directories
themselves are never included in the manifest or security checks.

## Plugin Directory

A **plugin** is any leaf directory containing a `plugin.yaml` or `__init__.py` file,
without child directories that also have those markers.

```
~/.hermes/hermes-agent/plugins/
├── model-providers/     # ← category dir (has child plugins, excluded)
│   ├── openai/          # ← plugin (leaf with __init__.py)
│   │   ├── __init__.py
│   │   └── plugin.yaml
│   ├── anthropic/       # ← plugin
│   │   └── __init__.py
│   └── ...
├── google_meet/         # ← plugin (leaf with __init__.py)
│   ├── __init__.py
│   └── plugin.yaml
└── memory/              # ← category dir (has child plugins, excluded)
    ├── mem0/            # ← plugin
    └── supermemory/     # ← plugin
```

**Marker files:** `plugin.yaml` OR `__init__.py`

Plugin category directories (those whose children also have marker files)
are excluded from manifest and scanning.

## Staging Directories

Before activation, skills and plugins go through staging:

```
~/.hermes/skills-staging/
└── new-skill/           # ← scanned, then approved or rejected

~/.hermes/plugins-staging/
└── new-plugin/
```

Staging mirrors the active directory structure but items here are **not**
loaded by Hermes Agent until `faro approve` moves them to active.

## Manifest Key Format

Manifest keys use the format `kind:name`:

```
skill:pixel-art
plugin:google_meet
plugin:openai
```

This prevents name collisions between skills and plugins with the same name.

## Adding a New Skill (Recommended Workflow)

```bash
# 1. Install into staging
cp -r ~/Downloads/my-new-skill ~/.hermes/skills-staging/

# 2. Scan
faro scan ~/.hermes/skills-staging/my-new-skill

# 3. Review findings, then approve
faro approve my-new-skill

# The skill is now in ~/.hermes/skills/ and the manifest
```

## Vetting Existing Skills

If a skill was already active before Faro was installed:

```bash
# Check what's unvetted
faro check

# Vet individual items
faro vet my-skill --kind skill
faro vet google_meet --kind plugin

# Or seed everything at once
faro init-manifest
```
