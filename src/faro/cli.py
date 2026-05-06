"""Faro CLI — Hermes Skill/Plugin Security Pipeline."""

import sys
from faro.scanner import scan_directory, scan_staging
from faro.reporter import to_text, to_json, summary_line
from faro.staged import list_staged, approve, reject, purge_staging


def cmd_scan(args: list[str]):
    if not args or args[0] == "--staged":
        results = scan_staging()
        if not results:
            print("No staged items found.")
            return
        for r in results:
            print(summary_line(r))
        if "--json" in args:
            print(to_json(results))
        elif "--full" in args:
            print("\n" + to_text(results))
    else:
        path = args[0]
        result = scan_directory(path)
        if "--json" in args:
            print(to_json([result]))
        else:
            print(to_text([result]))
        sys.exit(1 if result.risk_level in ("critical", "high") else 0)


def cmd_list(args: list[str]):
    items = list_staged()
    if not items:
        print("No staged items.")
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


COMMANDS = {
    "scan": (cmd_scan, "Scan a skill/plugin or all staged (--staged)"),
    "list": (cmd_list, "List staged items"),
    "approve": (cmd_approve, "Approve staged → active"),
    "reject": (cmd_reject, "Reject staged → delete"),
    "prune": (cmd_prune, "Purge all staging"),
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
