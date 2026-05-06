#!/usr/bin/env python3
"""Faro pre_llm_call hook — warns agent about unapproved staged items.

Hermes passes conversation context as JSON on stdin.
We inject a warning if unapproved staged skills/plugins exist.
"""

import json, sys
from pathlib import Path


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
                items.append({"name": item.name, "kind": kind, "path": str(item)})
    return items


def main():
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    staged = check_staging()
    if not staged:
        sys.exit(0)

    platform = hook_input.get("extra", {}).get("platform", "")
    if platform != "feishu":
        sys.exit(0)

    names = ", ".join(f"`{s['name']}`({s['kind']})" for s in staged)
    warning = (
        f"\n\n⚠️ **FARO** — unapproved staged: {names}\n"
        f"Do NOT load these. Run `faro list` to review, `faro approve <name>` to activate.\n"
    )

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
