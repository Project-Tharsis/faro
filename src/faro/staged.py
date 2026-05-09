"""Staging directory manager — list, approve, reject, prune.

v0.5.3: symlink-aware staging discovery. _find_staged_items now returns
both real skill/plugin dirs AND symlink dirs. Symlink dirs are hard-blocked
on approve but discoverable/rejectable/purgeable.

v0.7: approve accepts approval metadata (owner, approved_by, expires_at,
allowed_findings) for manifest audit trail.
"""

from pathlib import Path
import shutil
import time
from faro import get_home
from faro.scanner import scan_directory
from faro.manifest import add_to_manifest, _find_skill_dirs, _find_symlink_dirs


def _get_dirs(home: Path | None = None) -> tuple[Path, Path, Path, Path]:
    if home is None:
        home = get_home()
    return (home / ".hermes" / "skills-staging", home / ".hermes" / "skills",
            home / ".hermes" / "plugins-staging", home / ".hermes" / "hermes-agent" / "plugins")


def _find_staged_items(staging_dir: Path, kind: str) -> list[Path]:
    """Recursively find skill/plugin dirs AND symlink dirs in staging.

    v0.5.3: symlink dirs are included so they can be rejected/pruned.
    _find_skill_dirs no longer returns symlinks, so we query both.
    """
    items = list(_find_skill_dirs(staging_dir, kind=kind))
    items.extend(_find_symlink_dirs(staging_dir))
    return items


def list_staged() -> list[dict]:
    skills_staging, _, plugins_staging, _ = _get_dirs()
    items = []
    for staging_dir, kind in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if not staging_dir.exists():
            continue
        for item in _find_staged_items(staging_dir, kind):
            r = scan_directory(str(item))
            items.append({"name": item.name, "path": str(item), "kind": kind,
                          "risk_level": r.risk_level, "critical": r.critical_count,
                          "high": r.high_count, "medium": r.medium_count})
    return items


def approve(name: str, kind: str = "skill", force: bool = False,
            owner: str | None = None, approved_by: str | None = None,
            expires_at: str | None = None, approval_reason: str | None = None,
            allow_ids: list[str] | None = None) -> str | None:
    skills_staging, skills_active, plugins_staging, plugins_active = _get_dirs()
    staging_dir = skills_staging if kind == "skill" else plugins_staging
    active_dir = skills_active if kind == "skill" else plugins_active

    # Search recursively for the named item (includes symlink dirs)
    src = None
    for item in _find_staged_items(staging_dir, kind):
        if item.name == name:
            src = item
            break
    if src is None:
        print(f"\u274c '{name}' not found in {kind}s staging")
        return None

    # v0.5.1: hard block symlink directories
    if src.is_symlink():
        print(f"\U0001f534 '{name}' is a symlink directory — blocked (even with --force).")
        return None

    dst = active_dir / name
    # Preserve directory nesting from staging (e.g., creative/pixel-art)
    try:
        rel_from_staging = src.resolve().relative_to(staging_dir.resolve())
        if rel_from_staging != Path(name):
            dst = active_dir / rel_from_staging
    except ValueError:
        pass  # src not under staging (shouldn't happen)
    if not force and dst.exists():
        print(f"\u26a0\ufe0f  '{name}' already active. Use --force to overwrite.")
        return None

    result = scan_directory(str(src))
    if result.risk_level in ("critical", "high") and not force:
        print(f"\U0001f534 '{name}' has {result.risk_level} risk ({result.critical_count}C/{result.high_count}H). Use --force.")
        return None

    # Hard block: external symlinks are path escape, not mitigatable by --force
    symlink_escapes = [f for f in result.findings if f.pattern_id == "symlink-escape"]
    if symlink_escapes:
        print(f"\U0001f534 '{name}' contains external symlink escape(s):")
        for s in symlink_escapes:
            print(f"   {s.file}")
        print("   External symlinks are blocked even with --force.")
        return None

    # v0.7: build allowed_findings from --allow IDs
    allowed_findings = []
    if allow_ids:
        symlink_ids = {"symlink-escape", "symlink-dir-escape"}
        for fid in allow_ids:
            if fid in symlink_ids:
                raise ValueError(f"'{fid}' can never be allowed (symlink escape).")
            matches = [f for f in result.findings if f.pattern_id == fid]
            if not matches:
                raise ValueError(
                    f"No finding with id '{fid}' in current scan. "
                    "Use --allow only for findings that actually exist."
                )
            allowed_findings.append({
                "id": fid,
                "severity": matches[0].severity,
                "count": len(matches),
                "files": [m.file for m in matches],
                "reason": approval_reason or "allowed at approval time",
                "approved_by": approved_by or owner or "unknown",
                "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": expires_at,
            })

    if dst.exists():
        shutil.rmtree(dst)
    shutil.move(str(src), str(dst))
    add_to_manifest(name, str(dst), kind,
                    owner=owner, approved_by=approved_by,
                    expires_at=expires_at,
                    approval_reason=approval_reason,
                    allowed_findings=allowed_findings if allowed_findings else None,
                    approval_source="approve")
    print(f"\u2705 Approved: {kind}/{name} \u2192 active ({result.risk_level}, {len(result.findings)} findings)")
    return str(dst)


def reject(name: str, kind: str = "skill") -> bool:
    skills_staging, _, plugins_staging, _ = _get_dirs()
    staging_dir = skills_staging if kind == "skill" else plugins_staging

    target = None
    for item in _find_staged_items(staging_dir, kind):
        if item.name == name:
            target = item
            break
    if target is None:
        print(f"\u274c '{name}' not found in {kind}s staging")
        return False

    if target.is_symlink():
        target.unlink()
    else:
        shutil.rmtree(target)
    print(f"\U0001f5d1\ufe0f  Rejected: {kind}/{name} deleted from staging")
    return True


def purge_staging(kind: str = "all") -> int:
    skills_staging, _, plugins_staging, _ = _get_dirs()
    count = 0
    for staging_dir, k in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if kind not in ("all", k):
            continue
        if not staging_dir.exists():
            continue
        for item in _find_staged_items(staging_dir, k):
            if item.is_symlink():
                item.unlink()
            else:
                shutil.rmtree(item)
            count += 1
    print(f"\U0001f5d1\ufe0f  Purged {count} items from staging")
    return count
