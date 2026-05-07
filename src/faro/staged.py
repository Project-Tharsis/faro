"""Staging directory manager — list, approve, reject."""

from pathlib import Path
import shutil
from faro.scanner import scan_directory
from faro.manifest import add_to_manifest, remove_from_manifest


def _get_dirs() -> tuple[Path, Path, Path, Path]:
    home = Path.home()
    return (home / ".hermes" / "skills-staging", home / ".hermes" / "skills",
            home / ".hermes" / "plugins-staging", home / ".hermes" / "hermes-agent" / "plugins")


def list_staged() -> list[dict]:
    skills_staging, _, plugins_staging, _ = _get_dirs()
    items = []
    for staging_dir, kind in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if not staging_dir.exists():
            continue
        for item in sorted(staging_dir.iterdir()):
            if item.is_dir() and not item.name.startswith("."):
                r = scan_directory(str(item))
                items.append({"name": item.name, "path": str(item), "kind": kind,
                              "risk_level": r.risk_level, "critical": r.critical_count,
                              "high": r.high_count, "medium": r.medium_count})
    return items


def approve(name: str, kind: str = "skill", force: bool = False) -> str | None:
    skills_staging, skills_active, plugins_staging, plugins_active = _get_dirs()
    src = (skills_staging if kind == "skill" else plugins_staging) / name
    dst = (skills_active if kind == "skill" else plugins_active) / name
    if not src.exists():
        print(f"❌ '{name}' not found in {kind}s staging")
        return None
    result = scan_directory(str(src))
    if result.risk_level in ("critical", "high") and not force:
        print(f"🔴 '{name}' has {result.risk_level} risk ({result.critical_count}C/{result.high_count}H). Use --force.")
        return None
    if dst.exists():
        if not force:
            print(f"⚠️  '{name}' already active. Use --force to overwrite.")
            return None
        shutil.rmtree(dst)
    shutil.move(str(src), str(dst))
    add_to_manifest(name, str(dst), kind)
    print(f"✅ Approved: {kind}/{name} → active ({result.risk_level}, {len(result.findings)} findings)")
    return str(dst)


def reject(name: str, kind: str = "skill") -> bool:
    skills_staging, _, plugins_staging, _ = _get_dirs()
    target = (skills_staging if kind == "skill" else plugins_staging) / name
    if not target.exists():
        print(f"❌ '{name}' not found in {kind}s staging")
        return False
    shutil.rmtree(target)
    remove_from_manifest(name, kind)
    print(f"🗑️  Rejected: {kind}/{name} deleted")
    return True


def purge_staging(kind: str = "all") -> int:
    skills_staging, _, plugins_staging, _ = _get_dirs()
    count = 0
    for staging_dir, k in [(skills_staging, "skill"), (plugins_staging, "plugin")]:
        if kind not in ("all", k):
            continue
        if not staging_dir.exists():
            continue
        for item in staging_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                shutil.rmtree(item)
                count += 1
    print(f"🗑️  Purged {count} items from staging")
    return count
