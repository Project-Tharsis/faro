"""Vetted manifest — whitelist of approved skills/plugins.

Manifest file: ~/.hermes/.faro-manifest.json
Key format: "skill:name" or "plugin:name"
Value: {path, kind, structure_hash, content_hash, vetted_at, scanner_version}
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

MANIFEST_PATH = Path.home() / ".hermes" / ".faro-manifest.json"
SCANNER_VERSION = "0.2.0"

# Files whose content we hash for deep checks
CONTENT_EXTENSIONS = {".py", ".sh", ".js", ".ts"}


def _structure_hash(path: Path) -> str:
    """Fast hash of directory structure — file paths + names only, not contents."""
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


def _content_hash(path: Path) -> str:
    """Hash of actual script/text file contents in the directory."""
    hasher = hashlib.sha256()
    try:
        for f in sorted(path.rglob("*")):
            if f.is_file() and f.suffix in CONTENT_EXTENSIONS and "__pycache__" not in f.parts and ".git" not in f.parts:
                try:
                    hasher.update(f.read_bytes())
                except OSError:
                    pass
    except OSError:
        pass
    return hasher.hexdigest()[:16]


def _manifest_key(name: str, kind: str) -> str:
    """Build manifest key: 'skill:foo' or 'plugin:foo'."""
    return f"{kind}:{name}"


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        return {}
    try:
        return json.loads(MANIFEST_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_manifest(data: dict) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def add_to_manifest(name: str, path: str, kind: str) -> None:
    data = load_manifest()
    p = Path(path)
    key = _manifest_key(name, kind)
    data[key] = {
        "name": name,
        "path": str(p),
        "kind": kind,
        "structure_hash": _structure_hash(p) if p.exists() else "MISSING",
        "content_hash": _content_hash(p) if p.exists() else "MISSING",
        "vetted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": SCANNER_VERSION,
    }
    save_manifest(data)


def remove_from_manifest(name: str, kind: str) -> bool:
    data = load_manifest()
    key = _manifest_key(name, kind)
    if key not in data:
        return False
    del data[key]
    save_manifest(data)
    return True


def _find_skill_dirs(root: Path) -> list[Path]:
    """Find leaf skill/plugin directories — only dirs containing SKILL.md."""
    items = []
    for d in root.rglob("*"):
        if not d.is_dir() or d.name.startswith("."):
            continue
        if any(ex in d.parts for ex in ("__pycache__", "node_modules", ".git")):
            continue
        if (d / "SKILL.md").exists():
            items.append(d)
    return items


def find_unvetted(deep: bool = False) -> list[dict]:
    """Scan active dirs, find items NOT in manifest or with hash mismatch.

    Args:
        deep: If True, compare content_hash too (slower).
              Default False — only checks structure_hash (fast, for hook).
    """
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
            key = _manifest_key(item.name, kind)
            entry = manifest.get(key)

            if entry is None:
                # Not in manifest at all
                unvetted.append({
                    "name": item.name,
                    "path": str(item),
                    "kind": kind,
                    "reason": "not_in_manifest",
                })
                continue

            # In manifest — check structure_hash
            current_struct = _structure_hash(item)
            if current_struct != entry.get("structure_hash"):
                unvetted.append({
                    "name": item.name,
                    "path": str(item),
                    "kind": kind,
                    "reason": "structure_changed",
                    "expected_hash": entry.get("structure_hash"),
                    "actual_hash": current_struct,
                })
                continue

            # Deep check: content_hash
            if deep:
                current_content = _content_hash(item)
                if current_content != entry.get("content_hash"):
                    unvetted.append({
                        "name": item.name,
                        "path": str(item),
                        "kind": kind,
                        "reason": "content_changed",
                        "expected_hash": entry.get("content_hash"),
                        "actual_hash": current_content,
                    })

    return unvetted


def init_manifest() -> int:
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
