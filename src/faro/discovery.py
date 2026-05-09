"""Generic asset discovery — policy-driven directory walking.

v0.6: discovers skill, plugin, and generic agent assets.
Symlink-safe via os.walk(followlinks=False).
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from faro.manifest import (
    _walk_dirs_no_symlink_follow,
    _find_symlink_dirs,
    _is_excluded,
    _find_skill_dirs,
)


@dataclass
class DiscoveredAsset:
    """A discovered agent asset directory."""
    path: Path
    name: str
    asset_type: str          # "skill", "plugin", "generic"
    kind: str = "generic"    # policy kind or "generic"
    reason: str = ""         # "policy_discovery", "explicit_dir", "symlink_dir", "path_not_found"

    @property
    def is_error(self) -> bool:
        return self.reason in ("path_not_found", "symlink_dir")


def _find_dirs_by_marker(root: Path, marker_glob: str) -> list[Path]:
    """Find directories under root that contain at least one file matching marker_glob.

    Walks symlink-safe. Returns directories (not files).
    """
    if not root.exists():
        return []
    dirs_with_marker = set()
    for d in _walk_dirs_no_symlink_follow(root):
        try:
            for child in d.iterdir():
                if child.is_file() and child.match(marker_glob):
                    dirs_with_marker.add(d)
                    break
        except OSError:
            continue
    return sorted(dirs_with_marker, key=lambda p: p.as_posix())


def discover_generic_from_policy(
    policy_config: dict,
    base_dir: Optional[Path] = None,
) -> list[DiscoveredAsset]:
    """Parse policy discovery.generic and return DiscoveredAsset list.

    Paths are resolved relative to base_dir (policy file directory).
    Symlink directories are returned as error assets (blocked, not recursed).

    Args:
        policy_config: Parsed policy YAML dict.
        base_dir: Directory to resolve relative paths against.
    """
    discovery = policy_config.get("discovery")
    if not discovery or not isinstance(discovery, dict):
        return []

    generics = discovery.get("generic")
    if not generics:
        return []

    if not isinstance(generics, list):
        raise ValueError(
            "Invalid policy discovery: 'generic' must be a list, "
            f"got {type(generics).__name__}"
        )

    assets: list[DiscoveredAsset] = []
    seen_dirs: set[str] = set()

    for i, entry in enumerate(generics):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] must be a mapping"
            )

        path_str = entry.get("path")
        if not path_str or not isinstance(path_str, str):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] missing 'path' (string)"
            )

        marker = entry.get("marker")
        if marker is not None and not isinstance(marker, str):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] 'marker' must be string"
            )

        kind = entry.get("kind", "generic")
        if not isinstance(kind, str):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] 'kind' must be string"
            )

        # Resolve path relative to policy file directory
        p = Path(path_str)
        if not p.is_absolute() and base_dir:
            p = base_dir / p
        root = p.resolve() if not p.is_symlink() else p

        # Path not found
        if not root.exists():
            assets.append(DiscoveredAsset(
                path=root,
                name=p.name,
                asset_type="generic",
                kind=kind,
                reason="path_not_found",
            ))
            continue

        # Symlink directory — blocked, don't recurse
        if p.is_symlink():
            assets.append(DiscoveredAsset(
                path=p,
                name=p.name,
                asset_type="generic",
                kind=kind,
                reason="symlink_dir",
            ))
            continue

        if marker:
            # Find all directories containing marker files
            found_dirs = _find_dirs_by_marker(root, marker)
            for d in found_dirs:
                key = d.resolve().as_posix()
                if key not in seen_dirs:
                    seen_dirs.add(key)
                    # Check if this discovered dir is a symlink
                    if d.is_symlink():
                        assets.append(DiscoveredAsset(
                            path=d,
                            name=d.name,
                            asset_type="generic",
                            kind=kind,
                            reason="symlink_dir",
                        ))
                    else:
                        assets.append(DiscoveredAsset(
                            path=d,
                            name=d.name,
                            asset_type="generic",
                            kind=kind,
                            reason="policy_discovery",
                        ))
            if not found_dirs:
                # No marker matches — still return the root as generic
                assets.append(DiscoveredAsset(
                    path=root,
                    name=root.name,
                    asset_type="generic",
                    kind=kind,
                    reason="policy_discovery",
                ))
        else:
            # No marker — the directory itself is the asset
            if root.is_symlink():
                assets.append(DiscoveredAsset(
                    path=root,
                    name=root.name,
                    asset_type="generic",
                    kind=kind,
                    reason="symlink_dir",
                ))
            else:
                assets.append(DiscoveredAsset(
                    path=root,
                    name=root.name,
                    asset_type="generic",
                    kind=kind,
                    reason="policy_discovery",
                ))

    # Also detect symlink dirs under configured paths
    for entry in generics:
        path_str = entry.get("path", "")
        p = Path(path_str)
        if not p.is_absolute() and base_dir:
            p = base_dir / p
        if not p.exists() or p.is_symlink():
            continue
        # Find any symlink dirs within this tree
        for sym_dir in _find_symlink_dirs(p):
            key = sym_dir.as_posix()
            if key not in seen_dirs:
                seen_dirs.add(key)
                assets.append(DiscoveredAsset(
                    path=sym_dir,
                    name=sym_dir.name,
                    asset_type="generic",
                    kind="generic",
                    reason="symlink_dir",
                ))

    return assets


def discover_explicit_dirs(dirs: list[str]) -> list[DiscoveredAsset]:
    """Wrap explicit --dirs list into DiscoveredAsset list.

    Each directory is a generic asset root.
    Symlink dirs are flagged as symlink_dir.
    """
    assets = []
    for d in dirs:
        p = Path(d)
        if not p.exists():
            assets.append(DiscoveredAsset(
                path=p.resolve(),
                name=p.name,
                asset_type="generic",
                kind="generic",
                reason="path_not_found",
            ))
        elif p.is_symlink():
            assets.append(DiscoveredAsset(
                path=p,
                name=p.name,
                asset_type="generic",
                kind="generic",
                reason="symlink_dir",
            ))
        else:
            assets.append(DiscoveredAsset(
                path=p.resolve(),
                name=p.name,
                asset_type="generic",
                kind="generic",
                reason="explicit_dir",
            ))
    return assets


def policy_has_discovery(policy_config: Optional[dict]) -> bool:
    """Check if policy has discovery.generic configured.

    v0.6: also validates the config shape, raising ValueError on invalid.
    """
    if not policy_config or not isinstance(policy_config, dict):
        return False
    discovery = policy_config.get("discovery")
    if not isinstance(discovery, dict):
        return False
    generics = discovery.get("generic")
    if generics is None:
        return False
    if not isinstance(generics, list):
        raise ValueError(
            "Invalid policy discovery: 'generic' must be a list, "
            f"got {type(generics).__name__}"
        )
    # Validate each entry
    for i, entry in enumerate(generics):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] must be a mapping"
            )
        if "path" not in entry or not isinstance(entry.get("path"), str):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] missing 'path' (string)"
            )
        marker = entry.get("marker")
        if marker is not None and not isinstance(marker, str):
            raise ValueError(
                f"Invalid policy discovery: generic[{i}] 'marker' must be string"
            )
    return len(generics) > 0
