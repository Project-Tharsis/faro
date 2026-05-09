"""Faro CLI — Hermes Agent Asset Security Pipeline.

v0.5: --policy, --dirs, --profile, report command, agent audit rules.
"""

import sys
from pathlib import Path
from faro import get_home
from faro.scanner import scan_directory, scan_staging, scan_dirs
from faro.reporter import to_text, to_json, summary_line, report_markdown, report_json
from faro.staged import list_staged, approve, reject, purge_staging
from faro.manifest import add_to_manifest, remove_from_manifest, find_unvetted, load_manifest, init_manifest
from faro.patterns import load_policy, load_policy_config


# ── Built-in profiles ──────────────────────────────────────────────

KNOWN_FLAGS = {
    "--json", "--full", "--policy", "--dirs", "--profile",
    "--kind", "--force", "--owner", "--expires", "--path",
    "--format", "--staged", "--deep", "--help",
}


VALUE_FLAGS = {"--policy", "--dirs", "--profile", "--kind",
               "--owner", "--expires", "--path", "--format"}


def _validate_args(args):
    """Reject unknown flags and missing values. Prints to stderr and exits 2."""
    unknown = []
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            if args[i] not in KNOWN_FLAGS:
                unknown.append(args[i])
            if args[i] in VALUE_FLAGS:
                i += 1
                # Check: next token must exist and not be another flag
                if i >= len(args) or args[i].startswith("--"):
                    print(f"faro: flag {args[i-1]} requires a value", file=sys.stderr)
                    sys.exit(2)
        i += 1
    if unknown:
        print(f"faro: unknown flag(s): {', '.join(unknown)}", file=sys.stderr)
        print("Use faro --help for available flags.", file=sys.stderr)
        sys.exit(2)


BUILTIN_PROFILES = {
    "personal": {
        "critical": "block",
        "high": "warn_confirm",
        "medium": "warn",
        "low": "record",
    },
    "team": {
        "critical": "block",
        "high": "block_unless_approved",
        "medium": "owner_review",
        "low": "record",
    },
    "enterprise": {
        "critical": "block_no_allowlist",
        "high": "security_review_required",
        "medium": "owner_review",
        "low": "record",
    },
}


def _parse_policy(args):
    for i, a in enumerate(args):
        if a == "--policy" and i + 1 < len(args):
            return args[i + 1]
    return ""


def _parse_dirs(args):
    for i, a in enumerate(args):
        if a == "--dirs" and i + 1 < len(args):
            return [d.strip() for d in args[i + 1].split(",") if d.strip()]
    return []


def _parse_profile(args):
    for i, a in enumerate(args):
        if a == "--profile" and i + 1 < len(args):
            return args[i + 1]
    return ""


def _get_patterns(policy_path="", profile=""):
    policy_config = {}
    policy_name = "built-in"

    if profile and not policy_path:
        if profile in BUILTIN_PROFILES:
            policy_config = {"profiles": {profile: BUILTIN_PROFILES[profile]}}
            policy_name = f"profile:{profile}"
        else:
            print(f"Warning: unknown profile {profile!r}. Using personal.", file=sys.stderr)
            policy_config = {"profiles": {"personal": BUILTIN_PROFILES["personal"]}}
            policy_name = "profile:personal"

    if policy_path:
        try:
            patterns = load_policy(policy_path)
        except FileNotFoundError:
            print(f"faro: Policy file not found: {policy_path}", file=sys.stderr)
            sys.exit(2)
        except Exception as e:
            print(f"faro: Failed to load policy: {e}", file=sys.stderr)
            sys.exit(2)
        try:
            policy_config = load_policy_config(policy_path)
            policy_name = policy_config.get("name", Path(policy_path).stem)
        except Exception:
            pass
        return patterns, policy_name, policy_config

    from faro.patterns import PATTERNS
    return PATTERNS, policy_name, policy_config


# ── Commands ────────────────────────────────────────────────────────

def cmd_scan(args):
    _validate_args(args)
    json_mode = "--json" in args
    full_mode = "--full" in args
    policy_path = _parse_policy(args)
    profile = _parse_profile(args)
    dirs = _parse_dirs(args)

    patterns, policy_name, _ = _get_patterns(policy_path, profile)

    if dirs:
        results = scan_dirs(dirs, patterns=patterns, policy_name=policy_name)
    elif not args or args[0].startswith("--"):
        results = scan_staging(patterns=patterns, policy_name=policy_name)
    else:
        path = args[0]
        result = scan_directory(path, patterns=patterns, policy_name=policy_name)
        if json_mode:
            print(to_json([result]))
        else:
            print(to_text([result]))
        sys.exit(1 if result.risk_level in ("critical", "high", "error") else 0)
        return

    if json_mode:
        print(to_json(results))
    else:
        if not results:
            print("No items found.")
            return
        for r in results:
            print(summary_line(r))
        if full_mode:
            print()
            print(to_text(results))

    for r in results:
        if r.risk_level in ("critical", "high", "error"):
            sys.exit(1)
    sys.exit(0)


def cmd_list(args):
    _validate_args(args)
    items = list_staged()
    json_mode = "--json" in args
    if not items:
        print("[]" if json_mode else "No staged items.")
        return
    if json_mode:
        import json as _json
        print(_json.dumps(items, indent=2, ensure_ascii=False))
        return
    icon_map = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1",
                "low": "\U0001f7e2", "none": "\u2705"}
    for item in items:
        icon = icon_map.get(item["risk_level"], "\u26aa")
        print(f"{icon} [{item['kind']:6s}] {item['name']:30s} {item['risk_level']:8s} "
              f"({item['critical']}C/{item['high']}H/{item['medium']}M)")


def cmd_approve(args):
    _validate_args(args)
    if not args:
        print("Usage: faro approve <name> [--kind skill|plugin] [--force]")
        return
    name = args[0]
    kind = "skill"
    force = False
    for i, a in enumerate(args):
        if a == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
        if a == "--force":
            force = True
        # NOTE: --owner and --expires are v0.7 scope (manifest extension)
        # They are accepted but not yet written to manifest.
    result = approve(name, kind=kind, force=force)
    if result is None:
        sys.exit(1)


def cmd_reject(args):
    _validate_args(args)
    if not args:
        print("Usage: faro reject <name> [--kind skill|plugin]")
        return
    name = args[0]
    kind = "skill"
    for i, a in enumerate(args):
        if a == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
    ok = reject(name, kind=kind)
    if not ok:
        sys.exit(1)


def cmd_prune(args):
    _validate_args(args)
    if not args:
        print("Usage: faro prune <skill|plugin|all>")
        sys.exit(2)
    kind = args[0]
    if kind not in ("skill", "plugin", "all"):
        print(f"Invalid kind: '{kind}'. Must be skill, plugin, or all.")
        sys.exit(2)
    purge_staging(kind=kind)


def cmd_vet(args):
    _validate_args(args)
    if not args:
        print("Usage: faro vet <name> [--kind skill|plugin] [--path <path>]")
        return
    name = args[0]
    kind = "skill"
    path = None
    for i, a in enumerate(args):
        if a == "--kind" and i + 1 < len(args):
            kind = args[i + 1]
        if a == "--path" and i + 1 < len(args):
            path = args[i + 1]
    if not path:
        home = get_home()
        base = home / ".hermes" / "skills" if kind == "skill" else home / ".hermes" / "hermes-agent" / "plugins"
        for d in base.rglob(name):
            if d.is_dir():
                if kind == "skill" and not (d / "SKILL.md").exists():
                    continue
                path = str(d)
                break
        if not path:
            print(f"\u274c '{name}' not found under {base}")
            return
    p = Path(path)
    if not p.exists():
        print(f"\u274c Path not found: {path}")
        return
    try:
        add_to_manifest(name, path, kind)
    except ValueError as e:
        print(f"faro: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"\u2705 Vetted: {kind}/{name}")

def cmd_check(args):
    _validate_args(args)
    deep = "--deep" in args
    json_mode = "--json" in args

    unvetted = find_unvetted(deep=deep)
    if json_mode:
        import json as _json
        print(_json.dumps(unvetted, indent=2, ensure_ascii=False))
        return
    if not unvetted:
        label = " (deep)" if deep else ""
        print(f"\u2705 All active skills/plugins are in the manifest{label}.")
        return
    print(f"\u26a0\ufe0f  {len(unvetted)} unvetted item(s) found:")
    print()
    for u in unvetted:
        reason = u.get("reason", "not_in_manifest")
        icon_map = {"not_in_manifest": "\U0001f534", "structure_changed": "\U0001f7e0",
                    "content_changed": "\U0001f7e1", "symlink_dir": "\U0001f534"}
        icon = icon_map.get(reason, "\U0001f534")
        print(f"  {icon} [{u['kind']:6s}] {u['name']}")
        print(f"      reason: {reason}")
        if reason == "not_in_manifest":
            print(f"      \u2192 faro vet {u['name']} --kind {u['kind']}")
        elif reason == "symlink_dir":
            print(f"      Symlink directory must be replaced with a real directory.")
        else:
            print(f"      path: {u['path']}")
            print(f"      \u2192 faro vet {u['name']} --kind {u['kind']}  (to update manifest hash)")


def cmd_init_manifest(args):
    _validate_args(args)
    if args:
        print("Usage: faro init-manifest", file=sys.stderr)
        print("init-manifest takes no arguments.", file=sys.stderr)
        sys.exit(2)
    count = init_manifest()
    print(f"\u2705 Manifest initialized — {count} items whitelisted")


def cmd_report(args):
    _validate_args(args)
    policy_path = _parse_policy(args)
    profile = _parse_profile(args)
    dirs = _parse_dirs(args)
    fmt = "text"
    for i, a in enumerate(args):
        if a == "--format" and i + 1 < len(args):
            fmt = args[i + 1]

    patterns, policy_name, _ = _get_patterns(policy_path, profile)

    if dirs:
        results = scan_dirs(dirs, patterns=patterns, policy_name=policy_name)
    else:
        results = scan_staging(patterns=patterns, policy_name=policy_name)

    if not results:
        print("No results.")
        return

    if fmt == "json":
        print(report_json(results))
    elif fmt == "markdown":
        print(report_markdown(results))
    else:
        print(f"Faro Report — {policy_name}")
        print("-" * 40)
        total_c = sum(r.critical_count for r in results)
        total_h = sum(r.high_count for r in results)
        total_m = sum(r.medium_count for r in results)
        total_f = sum(len(r.findings) for r in results)
        print(f"Assets: {len(results)} | Findings: {total_f} ({total_c}C/{total_h}H/{total_m}M)")
        for r in results:
            print(f"  {summary_line(r)}")
        print("-" * 40)


COMMANDS = {
    "scan": (cmd_scan, "Scan a skill/plugin or all staged (--staged). Use --policy, --dirs, --profile"),
    "list": (cmd_list, "List staged items"),
    "approve": (cmd_approve, "Approve staged -> active (+ manifest). Use --owner, --expires"),
    "reject": (cmd_reject, "Reject staged -> delete (- manifest)"),
    "prune": (cmd_prune, "Purge all staging"),
    "vet": (cmd_vet, "Add active skill/plugin to manifest"),
    "check": (cmd_check, "Find active items NOT in manifest (--deep for content hash)"),
    "init-manifest": (cmd_init_manifest, "Seed manifest with all active items"),
    "report": (cmd_report, "Generate aggregate security report (--format markdown|json)"),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("faro — Hermes Agent Asset Security Pipeline (v0.5)")
        print()
        print("Usage: faro <command> [args]")
        print()
        print("Global flags: --policy <path>  --profile <name>  --dirs <a,b,c>")
        print()
        for name, (_, desc) in COMMANDS.items():
            print(f"  {name:14s}  {desc}")
        return
    cmd_name = sys.argv[1]
    if cmd_name not in COMMANDS:
        print(f"Unknown: {cmd_name}. Available: {', '.join(COMMANDS)}")
        sys.exit(1)
    COMMANDS[cmd_name][0](sys.argv[2:])


if __name__ == "__main__":
    main()
