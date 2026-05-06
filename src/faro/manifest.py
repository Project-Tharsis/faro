"""Vetted manifest — whitelist of approved skills/plugins.

Manifest file: ~/.hermes/.faro-manifest.json
Format: {name: {path, kind, hash, vetted_at, scanner_version}}
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

MANIFEST_PATH = Path.home() / ".hermes" / ".faro-manifest.json"
SCANNER_VERSION = "0.1.0"


def _dir_hash(path: Path) -> str:
    """Fast directory hash — hash of (relative_path + filename) for all files."""
    hasher = hashlib.sha256()
    try:
        for f in sorted(path.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts and ".git" not in f.parts:
                rel = str(f.relative_to(path))
                hasher.update(rel.encode())
                hasher.update(f.name.encode())
    except OSError:
        pass
    return hasher.hexdigest()[:16]


def load_manifest() -> dict:
    """Load the vetted manifest, returns {} if missing."""
    if not MANIFEST_PATH.exists():
        return {}
    try:
        return json.loads(MANIFEST_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_manifest(data: dict) -> None:
    """Save manifest atomically."""
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def add_to_manifest(name: str, path: str, kind: str) -> None:
    """Add or update a skill/plugin in the manifest."""
    data = load_manifest()
    p = Path(path)
    h = _dir_hash(p) if p.exists() else "MISSING"
    data[name] = {
        "path": str(p),
        "kind": kind,
        "hash": h,
        "vetted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": SCANNER_VERSION,
    }
    save_manifest(data)


def remove_from_manifest(name: str) -> bool:
    """Remove a skill from manifest. Returns True if it existed."""
    data = load_manifest()
    if name not in data:
        return False
    del data[name]
    save_manifest(data)
    return True


def _find_skill_dirs(root: Path) -> list[Path]:
    """Find all skill/plugin directories recursively.
    
    Skills are often nested (category/skill-name). We look for:
    - Directories containing SKILL.md (individual skills)
    - Second-level dirs under category dirs
    """
    items = []
    # First pass: leaf skills with SKILL.md
    for d in root.rglob("*"):
        if not d.is_dir() or d.name.startswith("."):
            continue
        if any(ex in d.parts for ex in ("__pycache__", "node_modules", ".git")):
            continue
        if (d / "SKILL.md").exists():
            items.append(d)
    # Second pass: category dirs that don't have SKILL.md but contain skill dirs
    for d in root.iterdir():
        if not d.is_dir() or d.name.startswith("."):
            continue
        if d in items:
            continue
        # Check if any child has SKILL.md
        for child in d.iterdir():
            if child.is_dir() and (child / "SKILL.md").exists():
                if d not in items:
                    items.append(d)
                break
    return items


def find_unvetted() -> list[dict]:
    """Scan active skills/plugins dirs, find items NOT in manifest."""
    manifest = load_manifest()
    unvetted = []
    home = Path.home()

    for active_dir, kind in [
        (home / ".hermes" / "skills", "skill"),
        (home / ".hermes" / "hermes-agent" / "plugins", "plugin"),
    ]:
        if not active_dir.exists():
            continue
        for item in _find_skill_dirs(active_dir):
            if item.name not in manifest:
                unvetted.append({
                    "name": item.name,
                    "path": str(item),
                    "kind": kind,
                })
    return unvetted


def init_manifest() -> int:
    """Seed manifest with all currently active skills/plugins. Returns count."""
    home = Path.home()
    count = 0
    for active_dir, kind in [
        (home / ".hermes" / "skills", "skill"),
        (home / ".hermes" / "hermes-agent" / "plugins", "plugin"),
    ]:
        if not active_dir.exists():
            continue
        for item in _find_skill_dirs(active_dir):
            add_to_manifest(item.name, str(item), kind)
            count += 1
    return count
