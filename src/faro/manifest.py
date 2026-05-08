"""Vetted manifest — whitelist of approved skills/plugins.

Manifest file: ~/.hermes/.faro-manifest.json
Key format v2: "skill:relative_path" or "plugin:relative_path"
  e.g., "skill:creative/pixel-art", "plugin:model-providers/openai"
  relative_path is computed from the active root:
    skill active root:  $FARO_HOME/.hermes/skills
    plugin active root: $FARO_HOME/.hermes/hermes-agent/plugins
Key format v1 (legacy, fallback only): "skill:name" or "plugin:name"

Value: {name, path, kind, relative_path, structure_hash, content_hash,
        vetted_at, scanner_version}
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional
from faro import get_home

HASH_VERSION = 2

def _get_manifest_path() -> Path:
    return get_home() / ".hermes" / ".faro-manifest.json"


SCANNER_VERSION = "0.3.0"

# Files whose content we hash for deep checks (v2: expanded set)
CONTENT_EXTENSIONS = {
    ".py", ".sh", ".js", ".ts",
    ".md", ".yaml", ".yml", ".json", ".toml",
    ".cfg", ".ini", ".txt"
}


def _structure_hash(path: Path) -> str:
    """Hash of directory structure — file paths + names, not contents.

    v2: full hexdigest (no truncation), includes version marker.
    """
    hasher = hashlib.sha256()
    hasher.update(b"faro-structure-v2\x00")
    try:
        for f in sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix()):
            if f.is_file() and "__pycache__" not in f.parts and ".git" not in f.parts:
                rel = f.relative_to(path).as_posix().encode("utf-8")
                hasher.update(len(rel).to_bytes(4, "big"))
                hasher.update(rel)
    except OSError:
        pass
    return hasher.hexdigest()


def _content_hash(path: Path) -> str:
    """Hash of script/text file contents in the directory.

    v2: includes version marker, relpath, file size, content,
    with length-prefixed separators — prevents content-splicing collisions.
    Full hexdigest (no truncation).
    """
    hasher = hashlib.sha256()
    hasher.update(b"faro-content-v2\x00")
    try:
        for f in sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix()):
            if (f.is_file() and f.suffix in CONTENT_EXTENSIONS
                    and "__pycache__" not in f.parts and ".git" not in f.parts):
                try:
                    data = f.read_bytes()
                    rel = f.relative_to(path).as_posix().encode("utf-8")
                    hasher.update(len(rel).to_bytes(4, "big"))
                    hasher.update(rel)
                    hasher.update(len(data).to_bytes(8, "big"))
                    hasher.update(data)
                except OSError:
                    pass
    except OSError:
        pass
    return hasher.hexdigest()


def _manifest_key(name: str, kind: str, relative_path: Optional[str] = None) -> str:
    """Build manifest key.

    v2 (relative_path provided): "skill:creative/foo"
    v1 fallback (no relative_path): "skill:foo"
    """
    if relative_path:
        return f"{kind}:{relative_path}"
    return f"{kind}:{name}"


def _compute_relative_path(item_path: Path, kind: str) -> str:
    """Compute relative_path from active root for a given kind.
    
    Falls back to directory name if path is not under active root
    (e.g., during testing with isolated paths).
    """
    home = get_home()
    if kind == "skill":
        active_root = home / ".hermes" / "skills"
    else:
        active_root = home / ".hermes" / "hermes-agent" / "plugins"
    try:
        return item_path.resolve().relative_to(active_root.resolve()).as_posix()
    except ValueError:
        # Path not under active root — use directory name as fallback
        return item_path.name


def load_manifest() -> dict:
    mp = _get_manifest_path()
    if not mp.exists():
        return {}
    try:
        return json.loads(mp.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_manifest(data: dict) -> None:
    """Save manifest atomically via temp file + rename."""
    mp = _get_manifest_path()
    mp.parent.mkdir(parents=True, exist_ok=True)
    tmp = mp.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.replace(mp)


def add_to_manifest(name: str, path: str, kind: str,
                    relative_path: Optional[str] = None) -> None:
    data = load_manifest()
    p = Path(path)
    rp = relative_path or _compute_relative_path(p, kind)
    key = _manifest_key(name, kind, relative_path=rp)
    data[key] = {
        "name": name,
        "path": str(p),
        "kind": kind,
        "relative_path": rp,
        "structure_hash": _structure_hash(p) if p.exists() else "MISSING",
        "content_hash": _content_hash(p) if p.exists() else "MISSING",
        "hash_version": HASH_VERSION,
        "vetted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": SCANNER_VERSION,
    }
    save_manifest(data)


def remove_from_manifest(name: str, kind: str, path: Optional[str] = None) -> bool:
    """Remove an entry from manifest by name+kind.

    If path is provided, tries v2 key lookup first (kind:relative_path),
    then falls back to iterating by name+kind.
    """
    data = load_manifest()
    # Try v2 key with computed relative_path if path provided
    if path is not None:
        rp = _compute_relative_path(Path(path), kind)
        key = _manifest_key(name, kind, relative_path=rp)
        if key in data:
            del data[key]
            save_manifest(data)
            return True

    # Fallback: search all entries by name + kind (works for any key format)
    for key, entry in list(data.items()):
        if entry.get("name") == name and entry.get("kind") == kind:
            del data[key]
            save_manifest(data)
            return True
    return False


def _find_skill_dirs(root: Path, kind: str = "skill") -> list[Path]:
    """Find leaf skill/plugin directories.

    Skills: dirs containing SKILL.md
    Plugins: dirs containing plugin.yaml (always a root, absorbs subdirectories)
             or __init__.py (leaf only, category dirs with child plugins excluded).
             Subdirectories of a plugin.yaml root are NOT separate plugins.
    """
    items = []
    # First pass: collect all plugin.yaml roots
    plugin_yaml_roots: set[Path] = set()

    for d in root.rglob("*"):
        if not d.is_dir() or d.name.startswith("."):
            continue
        if any(ex in d.parts for ex in ("__pycache__", "node_modules", ".git")):
            continue
        if kind == "skill":
            if (d / "SKILL.md").exists():
                items.append(d)
        else:
            if (d / "plugin.yaml").exists():
                items.append(d)
                plugin_yaml_roots.add(d)

    if kind == "plugin":
        # Second pass: find __init__.py leaf plugins
        for d in root.rglob("*"):
            if not d.is_dir() or d.name.startswith("."):
                continue
            if any(ex in d.parts for ex in ("__pycache__", "node_modules", ".git")):
                continue
            # Skip dirs already added as plugin.yaml roots
            if d in plugin_yaml_roots:
                continue
            # Skip subdirectories of plugin.yaml roots
            if any(d.resolve().is_relative_to(pr.resolve()) for pr in plugin_yaml_roots):
                continue
            if (d / "__init__.py").exists():
                # Exclude category dirs with child plugins
                has_child_plugin = False
                for child in d.iterdir():
                    if child.is_dir() and (
                        (child / "plugin.yaml").exists()
                        or (child / "__init__.py").exists()
                    ):
                        has_child_plugin = True
                        break
                if not has_child_plugin:
                    items.append(d)

    return items


def _lookup_entry(manifest: dict, item_path: Path, kind: str, item_name: str) -> Optional[dict]:
    """Look up a manifest entry for an item, trying v2 key first, then v1 fallback.

    v1 fallback requires path verification to prevent name-collision bypass.
    """
    rp = _compute_relative_path(item_path, kind)
    key_v2 = _manifest_key(item_name, kind, relative_path=rp)
    entry = manifest.get(key_v2)
    if entry is not None:
        return entry

    # v1 fallback: check kind:name, verify path matches
    key_v1 = _manifest_key(item_name, kind)
    entry_v1 = manifest.get(key_v1)
    if entry_v1 is not None:
        stored_path = Path(entry_v1.get("path", ""))
        try:
            if stored_path.resolve() == item_path.resolve():
                return entry_v1
        except OSError:
            pass
    return None


def find_unvetted(deep: bool = False) -> list[dict]:
    """Scan active dirs, find items NOT in manifest or with hash mismatch.

    Uses v2 manifest key format (kind:relative_path) with v1 fallback.
    """
    manifest = load_manifest()
    unvetted = []
    home = get_home()

    for active_dir, kind in [
        (home / ".hermes" / "skills", "skill"),
        (home / ".hermes" / "hermes-agent" / "plugins", "plugin"),
    ]:
        if not active_dir.exists():
            continue
        for item in _find_skill_dirs(active_dir, kind=kind):
            entry = _lookup_entry(manifest, item, kind, item.name)

            if entry is None:
                unvetted.append({
                    "name": item.name,
                    "relative_path": _compute_relative_path(item, kind),
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
                    "relative_path": _compute_relative_path(item, kind),
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
                        "relative_path": _compute_relative_path(item, kind),
                        "path": str(item),
                        "kind": kind,
                        "reason": "content_changed",
                        "expected_hash": entry.get("content_hash"),
                        "actual_hash": current_content,
                    })

    return unvetted


def init_manifest() -> int:
    home = get_home()
    count = 0
    for active_dir, kind in [
        (home / ".hermes" / "skills", "skill"),
        (home / ".hermes" / "hermes-agent" / "plugins", "plugin"),
    ]:
        if not active_dir.exists():
            continue
        for item in _find_skill_dirs(active_dir, kind=kind):
            rp = _compute_relative_path(item, kind)
            path_str = str(item)
            key = _manifest_key(item.name, kind, relative_path=rp)
            data = load_manifest()
            data[key] = {
                "name": item.name,
                "path": path_str,
                "kind": kind,
                "relative_path": rp,
                "structure_hash": _structure_hash(item),
                "content_hash": _content_hash(item),
                "hash_version": HASH_VERSION,
                "vetted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": SCANNER_VERSION,
            }
            save_manifest(data)
            count += 1
    return count
