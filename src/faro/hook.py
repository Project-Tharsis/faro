#!/usr/bin/env python3
"""Faro pre_llm_call hook — warns agent about unapproved or unvetted items.

Checks:
  1. Staging dirs — unapproved staged items
  2. Active dirs vs manifest — skills/plugins not in the vetted manifest
"""

import json
import sys
from pathlib import Path
from faro.manifest import find_unvetted


def check_staging() -> list[dict]:
    home = Path.home()
    items = []
    for staging_dir, kind in [
        (home / ".hermes" / "skills-staging", "skill"),
        (home / ".hermes" / "plugins-staging", "plugin"),
    ]:
        if not staging_dir.exists():
            continue
        for item in staging_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                items.append({"name": item.name, "kind": kind})
    return items


def main():
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    platform = hook_input.get("extra", {}).get("platform", "")
    if platform != "feishu":
        sys.exit(0)

    staged = check_staging()
    unvetted = find_unvetted()
    warnings = []

    if staged:
        names = ", ".join(f"`{s['name']}`({s['kind']})" for s in staged)
        warnings.append(f"staged: {names}. Run `faro list` / `faro approve <name>`.")

    if unvetted:
        names = ", ".join(f"`{u['name']}`({u['kind']})" for u in unvetted)
        warnings.append(f"unvetted: {names}. Run `faro check` / `faro vet <name>`.")

    if not warnings:
        sys.exit(0)

    warning = "\n\n⚠️ **FARO** — " + " | ".join(warnings) + "\nDo NOT load these until they pass `faro scan`.\n"

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
