"""Vetted manifest — whitelist of approved skills/plugins.

Manifest file: ~/.hermes/.faro-manifest.json
Key format v2: "skill:relative_path" or "plugin:relative_path"
  e.g., "skill:creative/pixel-art", "plugin:model-providers/openai"
  relative_path is computed from the active root:
    skill active root:  $FARO_HOME/.hermes/skills
    plugin active root: $FARO_HOME/.hermes/hermes-agent/plugins
Key format v1 (legacy, fallback only): "skill:name" or "plugin:name"

v0.5.3: symlink-safe directory walking via os.walk(followlinks=False).
        Symlink dirs are never returned by _find_skill_dirs — they are
        handled separately via _find_symlink_dirs.

Value: {name, path, kind, relative_path, structure_hash, content_hash,
        vetted_at, scanner_version}
"""

import hashlib
import json
import os as _os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from faro import get_home

HASH_VERSION = 2
SCANNER_VERSION = "0.7.0"
APPROVAL_SCHEMA_VERSION = 3

# Files whose content we hash for deep checks (v2: expanded set)
CONTENT_EXTENSIONS = {
    ".py", ".sh", ".js", ".ts",
    ".md", ".yaml", ".yml", ".json", ".toml",
    ".cfg", ".ini", ".txt"
}


def _get_manifest_path() -> Path:
    return get_home() / ".hermes" / ".faro-manifest.json"


def _is_excluded(path: Path) -> bool:
    """Check if any part of the path matches excluded dirs."""
    return any(part in ("__pycache__", "node_modules", ".git") for part in path.parts)


def _walk_dirs_no_symlink_follow(root: Path):
    """Yield real directories under root without following symlinks.

    Symlink directories are NOT yielded and os.walk will not
    recurse into them (because we remove them from dirnames).
    """
    if not root.exists():
        return
    for dirpath, dirnames, _ in _os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for name in dirnames:
            p = current / name
            if p.name.startswith(".") or _is_excluded(p):
                continue
            if p.is_symlink():
                continue  # don't recurse into symlink targets
            kept.append(name)
        dirnames[:] = kept
        for name in kept:
            yield current / name


def _find_symlink_dirs(root: Path) -> list[Path]:
    """Find all symlink directories under root.

    Returns the symlink paths themselves (not their targets).
    Does not recurse into symlink targets.
    """
    items = []
    if not root.exists():
        return items
    for dirpath, dirnames, _ in _os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for name in dirnames:
            p = current / name
            if p.name.startswith(".") or _is_excluded(p):
                continue
            if p.is_symlink():
                items.append(p)
                continue  # don't recurse into symlink targets
            kept.append(name)
        dirnames[:] = kept
    return items


def _find_skill_dirs(root: Path, kind: str = "skill") -> list[Path]:
    """Find leaf skill/plugin directories. Never returns symlink dirs.

    v0.5.3: uses _walk_dirs_no_symlink_follow — never follows symlinks.
    Skills: dirs containing SKILL.md
    Plugins: dirs containing plugin.yaml (always a root, absorbs subdirectories)
             or __init__.py (leaf only, category dirs with child plugins excluded).
    """
    items = []
    plugin_yaml_roots: set[Path] = set()

    for d in _walk_dirs_no_symlink_follow(root):
        # _walk ensures: real dir, not symlink, not hidden, not excluded
        if kind == "skill":
            if (d / "SKILL.md").exists():
                items.append(d)
        else:
            if (d / "plugin.yaml").exists():
                items.append(d)
                plugin_yaml_roots.add(d)

    if kind == "plugin":
        for d in _walk_dirs_no_symlink_follow(root):
            if d in plugin_yaml_roots:
                continue
            if any(d.resolve().is_relative_to(pr.resolve()) for pr in plugin_yaml_roots):
                continue
            if (d / "__init__.py").exists():
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


def _compute_relative_path(item_path: Path, kind: str) -> str:
    """Compute relative_path from active root for a given kind."""
    home = get_home()
    if kind == "skill":
        active_root = home / ".hermes" / "skills"
    else:
        active_root = home / ".hermes" / "hermes-agent" / "plugins"
    try:
        return item_path.resolve().relative_to(active_root.resolve()).as_posix()
    except ValueError:
        return item_path.name


def _manifest_key(name: str, kind: str, relative_path: Optional[str] = None) -> str:
    if relative_path:
        return f"{kind}:{relative_path}"
    return f"{kind}:{name}"


def load_manifest() -> dict:
    mp = _get_manifest_path()
    if not mp.exists():
        return {}
    try:
        return json.loads(mp.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_manifest(data: dict) -> None:
    mp = _get_manifest_path()
    mp.parent.mkdir(parents=True, exist_ok=True)
    tmp = mp.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.replace(mp)


def _parse_expires(value: str) -> str | None:
    """Parse --expires flag into ISO date string or None.

    Supported formats:
    - \"never\" or \"\" → None
    - \"Nd\" or \"N d\" (e.g., \"30d\", \"7d\") → today + N days
    - \"YYYY-MM-DD\" → validated future date

    Raises ValueError on invalid/expired input.
    """
    v = value.strip().lower() if value else ""
    if not v or v == "never":
        return None
    # "Nd" or "N d" format
    m = re.match(r"^(\d+)\s*d$", v)
    if m:
        days = int(m.group(1))
        dt = datetime.now() + timedelta(days=days)
        return dt.strftime("%Y-%m-%d")
    # "YYYY-MM-DD" format
    if re.match(r"^\d{4}-\d{2}-\d{2}$", v):
        try:
            dt = datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Invalid expiry date: {value!r}")
        if dt.date() <= datetime.now().date():
            raise ValueError(f"Expiry date must be in the future: {value!r}")
        return v
    raise ValueError(
        f"Invalid --expires format: {value!r}. "
        "Use '30d' (days), 'YYYY-MM-DD' (future date), or 'never'."
    )


def add_to_manifest(name: str, path: str, kind: str,
                    relative_path: Optional[str] = None,
                    owner: Optional[str] = None,
                    approved_by: Optional[str] = None,
                    expires_at: Optional[str] = None,
                    approval_reason: Optional[str] = None,
                    allowed_findings: Optional[list] = None,
                    approval_source: str = "approve") -> None:
    p = Path(path)
    # v0.5.3: hard block symlink directories
    if p.is_symlink():
        raise ValueError(f"Refusing to add symlink directory to manifest: {p}")
    data = load_manifest()
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
        "approval_schema_version": APPROVAL_SCHEMA_VERSION,
        "owner": owner,
        "approved_by": approved_by,
        "expires_at": expires_at,
        "approval_reason": approval_reason,
        "approval_source": approval_source,
        "migrated_from": None,
        "allowed_findings": allowed_findings or [],
    }
    save_manifest(data)


def remove_from_manifest(name: str, kind: str, path: Optional[str] = None) -> bool:
    data = load_manifest()
    if path is not None:
        rp = _compute_relative_path(Path(path), kind)
        key = _manifest_key(name, kind, relative_path=rp)
        if key in data:
            del data[key]
            save_manifest(data)
            return True
    for key, entry in list(data.items()):
        if entry.get("name") == name and entry.get("kind") == kind:
            del data[key]
            save_manifest(data)
            return True
    return False


def _structure_hash(path: Path) -> str:
    """Hash of directory structure — file paths + names, not contents."""
    hasher = hashlib.sha256()
    hasher.update(b"faro-structure-v2\x00")
    try:
        for f in sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix()):
            if f.is_file() and not f.is_symlink() and "__pycache__" not in f.parts and ".git" not in f.parts:
                rel = f.relative_to(path).as_posix().encode("utf-8")
                hasher.update(len(rel).to_bytes(4, "big"))
                hasher.update(rel)
    except OSError:
        pass
    return hasher.hexdigest()


def _content_hash(path: Path) -> str:
    """Hash of script/text file contents in the directory."""
    hasher = hashlib.sha256()
    hasher.update(b"faro-content-v2\x00")
    try:
        for f in sorted(path.rglob("*"), key=lambda p: p.relative_to(path).as_posix()):
            if (f.is_file() and not f.is_symlink() and f.suffix in CONTENT_EXTENSIONS
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


def _lookup_entry(manifest: dict, item_path: Path, kind: str, item_name: str) -> Optional[dict]:
    rp = _compute_relative_path(item_path, kind)
    key_v2 = _manifest_key(item_name, kind, relative_path=rp)
    entry = manifest.get(key_v2)
    if entry is not None:
        return entry
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


def find_unvetted(deep: bool = False, profile: str = "personal") -> list[dict]:
    """Scan active dirs, find items NOT in manifest or with hash mismatch.

    v0.7: added profile-aware approval metadata checks.
    - personal: reports approval_expired if expires_at is past.
    - team: reports approval_metadata_missing (no owner), approval_expired.
    - enterprise: reports approval_metadata_missing (no owner/approved_by),
      approval_legacy (no approval_schema_version), approval_expired.

    v0.5.3: symlink dirs detected first (from _find_symlink_dirs),
    before real skill/plugin dirs (from _find_skill_dirs).
    """
    manifest = load_manifest()
    unvetted = []
    home = get_home()
    today = datetime.now().date()

    def _check_approval(entry: dict, item_name: str, rp: str, path_str: str, k: str):
        """Check approval metadata for a manifest entry. Appends to unvetted."""
        schema_ver = entry.get("approval_schema_version")

        # Legacy v2 entry — no approval_schema_version
        if schema_ver is None:
            if profile == "enterprise":
                unvetted.append({
                    "name": item_name, "relative_path": rp, "path": path_str,
                    "kind": k, "reason": "approval_legacy",
                })
            return

        owner = entry.get("owner")
        approved_by = entry.get("approved_by")

        # Check metadata completeness per profile
        if profile == "team":
            if not owner:
                unvetted.append({
                    "name": item_name, "relative_path": rp, "path": path_str,
                    "kind": k, "reason": "approval_metadata_missing",
                    "missing": ["owner"],
                })
                return
        elif profile == "enterprise":
            missing = []
            if not owner:
                missing.append("owner")
            if not approved_by:
                missing.append("approved_by")
            if missing:
                unvetted.append({
                    "name": item_name, "relative_path": rp, "path": path_str,
                    "kind": k, "reason": "approval_metadata_missing",
                    "missing": missing,
                })
                return

        # Check expiry
        expires_str = entry.get("expires_at")
        if expires_str:
            try:
                expires_date = datetime.strptime(expires_str, "%Y-%m-%d").date()
                if expires_date <= today:
                    unvetted.append({
                        "name": item_name, "relative_path": rp, "path": path_str,
                        "kind": k, "reason": "approval_expired",
                        "expires_at": expires_str,
                    })
            except ValueError:
                pass  # unparseable expiry — skip, don't crash

    for active_dir, kind in [
        (home / ".hermes" / "skills", "skill"),
        (home / ".hermes" / "hermes-agent" / "plugins", "plugin"),
    ]:
        if not active_dir.exists():
            continue

        # Phase A: symlink dirs — always critical, never in manifest
        for symlink_dir in _find_symlink_dirs(active_dir):
            unvetted.append({
                "name": symlink_dir.name,
                "relative_path": _compute_relative_path(symlink_dir, kind),
                "path": str(symlink_dir),
                "kind": kind,
                "reason": "symlink_dir",
            })

        # Phase B: real skill/plugin dirs
        for item in _find_skill_dirs(active_dir, kind=kind):
            # _find_skill_dirs never returns symlink dirs, but check anyway
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
                    continue

            # v0.7: approval metadata check (only for hash-valid entries)
            _check_approval(entry, item.name,
                            _compute_relative_path(item, kind),
                            str(item), kind)

    return unvetted


def init_manifest() -> int:
    """Rebuild manifest from all active skills/plugins. Skips symlink dirs."""
    home = get_home()
    count = 0
    blocked = 0
    for active_dir, kind in [
        (home / ".hermes" / "skills", "skill"),
        (home / ".hermes" / "hermes-agent" / "plugins", "plugin"),
    ]:
        if not active_dir.exists():
            continue
        # Check symlink dirs first — block them
        for symlink_dir in _find_symlink_dirs(active_dir):
            print(f"🔴 init-manifest blocked symlink: {symlink_dir}")
            blocked += 1

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
                "approval_schema_version": APPROVAL_SCHEMA_VERSION,
                "owner": None,
                "approved_by": None,
                "expires_at": None,
                "approval_reason": None,
                "approval_source": "init-manifest",
                "migrated_from": None,
                "allowed_findings": [],
            }
            save_manifest(data)
            count += 1
    if blocked:
        print(f"🔴 {blocked} symlink director(ies) blocked — not whitelisted.")
    return count
