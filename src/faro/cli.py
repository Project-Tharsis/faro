"""Faro CLI — Hermes Skill/Plugin Security Pipeline."""

import sys
from pathlib import Path
from faro import get_home
from faro.scanner import scan_directory, scan_staging
from faro.reporter import to_text, to_json, summary_line
from faro.staged import list_staged, approve, reject, purge_staging
from faro.manifest import add_to_manifest, remove_from_manifest, find_unvetted, load_manifest, init_manifest


def cmd_scan(args: list[str]):
    json_mode = "--json" in args
    if not args or args[0] == "--staged":
        results = scan_staging()
        if json_mode:
            print(to_json(results))
            return
        if not results:
            print("No staged items found.")
            return
        for r in results:
            print(summary_line(r))
        if "--full" in args:
            print("\n" + to_text(results))
    else:
        path = args[0]
        result = scan_directory(path)
        if json_mode:
            print(to_json([result]))
        else:
            print(to_text([result]))
        sys.exit(1 if result.risk_level in ("critical", "high") else 0)


def cmd_list(args: list[str]):
    items = list_staged()
    json_mode = "--json" in args
    if not items:
        print("[]" if json_mode else "No staged items.")
        return
    if json_mode:
        import json as _json
        print(_json.dumps(items, indent=2, ensure_ascii=False))
        return
    icon_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}
    for item in items:
        icon = icon_map.get(item["risk_level"], "⚪")
        print(f"{icon} [{item['kind']:6s}] {item['name']:30s} {item['risk_level']:8s} ({item['critical']}C/{item['high']}H/{item['medium']}M)")


def cmd_approve(args: list[str]):
    if not args:
        print("Usage: faro approve <name> [--kind skill|plugin] [--force]")
        return
    name = args[0]
    kind = "skill"; force = False
    for i, a in enumerate(args):
        if a == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
        if a == "--force":
            force = True
    approve(name, kind=kind, force=force)


def cmd_reject(args: list[str]):
    if not args:
        print("Usage: faro reject <name> [--kind skill|plugin]")
        return
    name = args[0]; kind = "skill"
    for i, a in enumerate(args):
        if a == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
    reject(name, kind=kind)


def cmd_prune(args: list[str]):
    kind = args[0] if args and args[0] in ("skill", "plugin", "all") else "all"
    purge_staging(kind=kind)


def cmd_vet(args: list[str]):
    """Vet an already-active skill/plugin — add to manifest."""
    if not args:
        print("Usage: faro vet <name> [--kind skill|plugin] [--path <path>]")
        return
    name = args[0]; kind = "skill"; path = None
    for i, a in enumerate(args):
        if a == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
        if a == "--path" and i + 1 < len(args):
            path = args[i + 1]
    if not path:
        home = get_home()
        base = home / ".hermes" / "skills" if kind == "skill" else home / ".hermes" / "hermes-agent" / "plugins"
        # Search recursively for name
        for d in base.rglob(name):
            if d.is_dir():
                if kind == "skill" and not (d / "SKILL.md").exists():
                    continue
                path = str(d)
                break
        if not path:
            print(f"❌ '{name}' not found under {base}")
            return
    p = Path(path)
    if not p.exists():
        print(f"❌ Path not found: {path}")
        return
    add_to_manifest(name, path, kind)
    print(f"✅ Vetted: {kind}/{name}")


def cmd_check(args: list[str]):
    """Check active skills/plugins against manifest. Use --deep for content hash."""
    deep = "--deep" in args
    json_mode = "--json" in args
    unvetted = find_unvetted(deep=deep)
    if json_mode:
        import json as _json
        print(_json.dumps(unvetted, indent=2, ensure_ascii=False))
        return
    if not unvetted:
        label = " (deep)" if deep else ""
        print(f"✅ All active skills/plugins are in the manifest{label}.")
        return
    print(f"⚠️  {len(unvetted)} unvetted item(s) found:\n")
    for u in unvetted:
        reason = u.get("reason", "not_in_manifest")
        icon_map = {"not_in_manifest": "🔴", "structure_changed": "🟠", "content_changed": "🟡"}
        icon = icon_map.get(reason, "🔴")
        print(f"  {icon} [{u['kind']:6s}] {u['name']}")
        print(f"      reason: {reason}")
        if reason == "not_in_manifest":
            print(f"      → faro vet {u['name']} --kind {u['kind']}")
        else:
            print(f"      path: {u['path']}")
            print(f"      → faro vet {u['name']} --kind {u['kind']}  (to update manifest hash)")


def cmd_init_manifest(args: list[str]):
    """Initialize manifest with all currently active skills/plugins."""
    count = init_manifest()
    print(f"✅ Manifest initialized — {count} items whitelisted")


COMMANDS = {
    "scan": (cmd_scan, "Scan a skill/plugin or all staged (--staged)"),
    "list": (cmd_list, "List staged items"),
    "approve": (cmd_approve, "Approve staged → active (+ manifest)"),
    "reject": (cmd_reject, "Reject staged → delete (- manifest)"),
    "prune": (cmd_prune, "Purge all staging"),
    "vet": (cmd_vet, "Add active skill/plugin to manifest"),
    "check": (cmd_check, "Find active items NOT in manifest"),
    "init-manifest": (cmd_init_manifest, "Seed manifest with all active items"),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("faro — Hermes Skill/Plugin Security Pipeline\n")
        print("Usage: faro <command> [args]\n")
        for name, (_, desc) in COMMANDS.items():
            print(f"  {name:10s}  {desc}")
        return
    cmd_name = sys.argv[1]
    if cmd_name not in COMMANDS:
        print(f"Unknown: {cmd_name}. Available: {', '.join(COMMANDS)}")
        sys.exit(1)
    COMMANDS[cmd_name][0](sys.argv[2:])


if __name__ == "__main__":
    main()
