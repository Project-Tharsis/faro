"""Integration tests for staging pipeline — approve, reject, purge, hook, scan_staging.

All tests are fully isolated via FARO_HOME pointing to a temp directory.
No real ~/.hermes is touched.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

TEST_SKILL_NAME = "__faro_test_skill__"
TEST_PLUGIN_NAME = "__faro_test_plugin__"


def _make_hermes_tree(home: Path) -> dict:
    """Create minimal ~/.hermes directory tree in a temp home."""
    dirs = {
        "skills_staging": home / ".hermes" / "skills-staging",
        "skills_active": home / ".hermes" / "skills",
        "plugins_staging": home / ".hermes" / "plugins-staging",
        "plugins_active": home / ".hermes" / "hermes-agent" / "plugins",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def _create_staged_skill(home: Path, name: str = TEST_SKILL_NAME, nested: bool = False) -> Path:
    d = home / ".hermes" / "skills-staging"
    if nested:
        d = d / "creative" / name
    else:
        d = d / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"# {name}")
    return d


def _create_staged_plugin(home: Path, name: str = TEST_PLUGIN_NAME, nested: bool = False) -> Path:
    d = home / ".hermes" / "plugins-staging"
    if nested:
        d = d / "model-providers" / name
    else:
        d = d / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "__init__.py").write_text(f"# {name}")
    return d


def test_approve_reject_kind():
    """approve() and reject() work with kind=skill and kind=plugin."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _make_hermes_tree(home)
        try:
            from faro.staged import approve, reject, list_staged

            # Skill
            _create_staged_skill(home)
            items = list_staged()
            assert any(i["name"] == TEST_SKILL_NAME for i in items), "staged skill not listed"

            result = approve(TEST_SKILL_NAME, kind="skill", force=True)
            assert result is not None, f"approve failed: {result}"
            assert (home / ".hermes" / "skills" / TEST_SKILL_NAME).exists(), "skill not moved to active"

            # Reject it
            (home / ".hermes" / "skills" / TEST_SKILL_NAME).rename(
                home / ".hermes" / "skills-staging" / TEST_SKILL_NAME)
            ok = reject(TEST_SKILL_NAME, kind="skill")
            assert ok, "reject should return True"
            assert not (home / ".hermes" / "skills-staging" / TEST_SKILL_NAME).exists()

            # Plugin
            _create_staged_plugin(home)
            result = approve(TEST_PLUGIN_NAME, kind="plugin", force=True)
            assert result is not None, "plugin approve failed"
            assert (home / ".hermes" / "hermes-agent" / "plugins" / TEST_PLUGIN_NAME).exists()

            (home / ".hermes" / "hermes-agent" / "plugins" / TEST_PLUGIN_NAME).rename(
                home / ".hermes" / "plugins-staging" / TEST_PLUGIN_NAME)
            ok = reject(TEST_PLUGIN_NAME, kind="plugin")
            assert ok, "plugin reject should return True"
        finally:
            del os.environ["FARO_HOME"]


def test_purge_staging_all_clears_both():
    """purge_staging('all') clears both skills and plugins."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _make_hermes_tree(home)
        try:
            from faro.staged import purge_staging

            _create_staged_skill(home)
            _create_staged_plugin(home)

            count = purge_staging(kind="all")
            assert count == 2, f"Expected 2 purged, got {count}"
            assert not (home / ".hermes" / "skills-staging" / TEST_SKILL_NAME).exists()
            assert not (home / ".hermes" / "plugins-staging" / TEST_PLUGIN_NAME).exists()
        finally:
            del os.environ["FARO_HOME"]


def test_hook_check_staging_nested():
    """Hook check_staging() finds nested skill by leaf name, not category."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _make_hermes_tree(home)
        try:
            from faro.hook import check_staging

            _create_staged_skill(home, "pixel-art", nested=True)

            items = check_staging()
            names = [i["name"] for i in items]
            assert "pixel-art" in names, f"nested skill not found: {names}"
            assert "creative" not in names, f"category dir in results: {names}"
        finally:
            del os.environ["FARO_HOME"]


def test_scan_staging_nested():
    """scan_staging() finds nested skills/plugins, not category dirs."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _make_hermes_tree(home)
        try:
            from faro.scanner import scan_staging

            _create_staged_skill(home, "pixel-art", nested=True)
            _create_staged_plugin(home, "openai", nested=True)

            results = scan_staging()
            names = {r.name for r in results}
            assert "pixel-art" in names, f"nested skill missing: {names}"
            assert "openai" in names, f"nested plugin missing: {names}"
            assert "creative" not in names, f"category dir scanned"
            assert "model-providers" not in names, f"category dir scanned"
        finally:
            del os.environ["FARO_HOME"]


def test_approve_rejects_category_dir():
    """approve() does not find category dirs like 'creative' as staged items."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _make_hermes_tree(home)
        try:
            from faro.staged import approve

            _create_staged_skill(home, "pixel-art", nested=True)
            result = approve("creative", kind="skill", force=True)
            assert result is None, "approve should not find category dir 'creative'"
        finally:
            del os.environ["FARO_HOME"]


def test_scan_staging_category_not_scanned():
    """scan_staging() with plugin category dir doesn't scan the category itself."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _make_hermes_tree(home)
        try:
            from faro.scanner import scan_staging

            cat = home / ".hermes" / "plugins-staging" / "model-providers"
            cat.mkdir(parents=True, exist_ok=True)
            (cat / "__init__.py").write_text("")
            sub = cat / "openai"
            sub.mkdir()
            (sub / "__init__.py").write_text("")

            results = scan_staging()
            names = {r.name for r in results}
            assert "openai" in names, "sub-plugin should be found"
            assert "model-providers" not in names, f"category dir scanned: {names}"
        finally:
            del os.environ["FARO_HOME"]


if __name__ == "__main__":
    tests = [
        ("approve_reject_kind", test_approve_reject_kind),
        ("purge_all_clears_both", test_purge_staging_all_clears_both),
        ("hook_nested", test_hook_check_staging_nested),
        ("scan_staging_nested", test_scan_staging_nested),
        ("approve_rejects_category", test_approve_rejects_category_dir),
        ("scan_category_excluded", test_scan_staging_category_not_scanned),
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
