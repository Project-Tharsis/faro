"""Staging directory manager — list, approve, reject."""

from pathlib import Path
import shutil
from faro import get_home
from faro.scanner import scan_directory
from faro.manifest import add_to_manifest, _find_skill_dirs


def _get_dirs(home: Path | None = None) -> tuple[Path, Path, Path, Path]:
    if home is None:
        home = get_home()
    return (home / ".hermes" / "skills-staging", home / ".hermes" / "skills",
            home / ".hermes" / "plugins-staging", home / ".hermes" / "hermes-agent" / "plugins")


def _find_staged_items(staging_dir: Path, kind: str) -> list[Path]:
    """Recursively find skill/plugin dirs in staging, using kind-aware logic."""
    return _find_skill_dirs(staging_dir, kind=kind)


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


def approve(name: str, kind: str = "skill", force: bool = False) -> str | None:
    skills_staging, skills_active, plugins_staging, plugins_active = _get_dirs()
    staging_dir = skills_staging if kind == "skill" else plugins_staging
    active_dir = skills_active if kind == "skill" else plugins_active

    # Search recursively for the named item
    src = None
    for item in _find_staged_items(staging_dir, kind):
        if item.name == name:
            src = item
            break
    if src is None:
        print(f"❌ '{name}' not found in {kind}s staging")
        return None

    dst = active_dir / name
    if not force and dst.exists():
        print(f"⚠️  '{name}' already active. Use --force to overwrite.")
        return None

    result = scan_directory(str(src))
    if result.risk_level in ("critical", "high") and not force:
        print(f"🔴 '{name}' has {result.risk_level} risk ({result.critical_count}C/{result.high_count}H). Use --force.")
        return None

    if dst.exists():
        shutil.rmtree(dst)
    shutil.move(str(src), str(dst))
    add_to_manifest(name, str(dst), kind)
    print(f"✅ Approved: {kind}/{name} → active ({result.risk_level}, {len(result.findings)} findings)")
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
        print(f"❌ '{name}' not found in {kind}s staging")
        return False

    shutil.rmtree(target)
    # reject() only deletes staging — manifest changes are for approve/vet/init-manifest
    print(f"🗑️  Rejected: {kind}/{name} deleted from staging")
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
            shutil.rmtree(item)
            count += 1
    print(f"🗑️  Purged {count} items from staging")
    return count
