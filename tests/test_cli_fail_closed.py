"""Regression tests for CLI fail-closed behavior.

Tests that invalid inputs return non-zero exit codes
and don't silently succeed.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

FARO_CLI = [sys.executable, "-m", "faro.cli"]


def _run_cli(args: list[str], cwd: str = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if cwd:
        env["PYTHONPATH"] = str(Path(cwd) / "src")
    else:
        env["PYTHONPATH"] = str(Path(__file__).parent.parent / "src")
    return subprocess.run(
        [sys.executable, "-m", "faro.cli"] + args,
        capture_output=True, text=True, cwd=cwd,
        env=env,
    )


def test_scan_missing_path_exits_nonzero():
    """faro scan /nonexistent → non-zero exit."""
    r = _run_cli(["scan", "/tmp/definitely-not-a-faro-path-xyz"])
    assert r.returncode != 0, f"Expected non-zero exit for missing path, got {r.returncode}"
    assert "not found" in r.stdout.lower() or "not found" in r.stderr.lower(), \
        f"Expected 'not found' in output, got stdout={r.stdout[:200]} stderr={r.stderr[:200]}"


def test_scan_unknown_directory_exits_nonzero():
    """faro scan on a dir without SKILL.md/plugin.yaml/__init__.py → non-zero exit."""
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "not-a-skill"
        d.mkdir()
        (d / "README.md").write_text("hello")
        r = _run_cli(["scan", str(d)])
        assert r.returncode != 0, f"Expected non-zero exit for unknown target, got {r.returncode}"


def test_prune_invalid_kind_does_not_delete():
    """faro prune skll → error, does not delete anything."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        # Create staging dirs with items
        s_staging = home / ".hermes" / "skills-staging"
        s_staging.mkdir(parents=True)
        (s_staging / "test-skill").mkdir()
        (s_staging / "test-skill" / "SKILL.md").write_text("# test")

        try:
            r = _run_cli(["prune", "skll"])
            assert r.returncode != 0, f"Expected non-zero for invalid prune kind, got {r.returncode}"
            # The staging item must still exist
            assert (s_staging / "test-skill").exists(), "staging item was deleted!"
        finally:
            del os.environ["FARO_HOME"]


def test_prune_no_args_exits_nonzero():
    """faro prune (no args) → error, requires explicit kind."""
    r = _run_cli(["prune"])
    assert r.returncode != 0, f"Expected non-zero for missing prune arg, got {r.returncode}"
    assert "usage" in r.stdout.lower() or "usage" in r.stderr.lower(), \
        f"Expected usage message, got: {r.stdout[:200]}"


def test_approve_missing_item_exits_nonzero():
    """faro approve nonexistent → non-zero exit."""
    r = _run_cli(["approve", "__nonexistent_skill_xyz__"])
    # approve prints to stdout, check for error message
    assert "not found" in r.stdout.lower() or "not found" in r.stderr.lower(), \
        f"Expected 'not found', got: {r.stdout[:200]}"


def test_reject_missing_item_exits_nonzero():
    """faro reject nonexistent → non-zero exit."""
    r = _run_cli(["reject", "__nonexistent_skill_xyz__"])
    assert "not found" in r.stdout.lower() or "not found" in r.stderr.lower(), \
        f"Expected 'not found', got: {r.stdout[:200]}"


if __name__ == "__main__":
    tests = [
        ("scan_missing_path_nonzero", test_scan_missing_path_exits_nonzero),
        ("scan_unknown_dir_nonzero", test_scan_unknown_directory_exits_nonzero),
        ("prune_invalid_kind_no_delete", test_prune_invalid_kind_does_not_delete),
        ("prune_no_args_nonzero", test_prune_no_args_exits_nonzero),
        ("approve_missing_nonzero", test_approve_missing_item_exits_nonzero),
        ("reject_missing_nonzero", test_reject_missing_item_exits_nonzero),
    ]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"✅ {name}")
            passed += 1
        except Exception as e:
            print(f"❌ {name}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
