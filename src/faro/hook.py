#!/usr/bin/env python3
"""Faro pre_llm_call hook — warns agent about unapproved or unvetted items.

Checks:
  1. Staging dirs — unapproved staged items
  2. Active dirs vs manifest — skills/plugins not in the vetted manifest

On Feishu: injects warning into conversation context (the user sees it).
On other platforms: writes to stderr for log visibility only.
"""

import json
import sys
from pathlib import Path
from faro.manifest import find_unvetted, _find_skill_dirs


def check_staging() -> list[dict]:
    home = Path.home()
    items = []
    for staging_dir, kind in [
        (home / ".hermes" / "skills-staging", "skill"),
        (home / ".hermes" / "plugins-staging", "plugin"),
    ]:
        if not staging_dir.exists():
            continue
        for item in _find_skill_dirs(staging_dir, kind=kind):
            items.append({"name": item.name, "kind": kind})
    return items


def main():
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    staged = check_staging()
    unvetted = find_unvetted()

    if not staged and not unvetted:
        sys.exit(0)

    warnings = []
    if staged:
        names = ", ".join(f"`{s['name']}`({s['kind']})" for s in staged)
        warnings.append(f"staged: {names}. Run `faro list` / `faro approve <name>`.")
    if unvetted:
        names = ", ".join(f"`{u['name']}`({u['kind']})" for u in unvetted)
        warnings.append(f"unvetted: {names}. Run `faro check` / `faro vet <name>`.")

    warning_text = " | ".join(warnings)
    platform = hook_input.get("extra", {}).get("platform", "")

    if platform and platform != "feishu":
        # Non-Feishu: log to stderr only (no conversation injection)
        sys.stderr.write(f"[faro] {warning_text}\n")
        sys.stderr.flush()
        sys.exit(0)

    # Feishu or unknown platform: inject into conversation
    warning = f"\n\n⚠️ **FARO** — {warning_text}\nDo NOT load these until they pass `faro scan`.\n"

    messages = hook_input.get("messages", [])
    if messages:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                if isinstance(msg.get("content"), str):
                    msg["content"] = msg["content"] + warning
                elif isinstance(msg.get("content"), list):
                    for block in msg["content"]:
                        if block.get("type") == "text":
                            block["text"] = block["text"] + warning
                            break
                break

    json.dump(hook_input, sys.stdout)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
