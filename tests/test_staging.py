"""Integration tests for staging pipeline — approve, reject, purge, hook, scan_staging."""

import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Staging dirs used by tests
HOME = Path.home()
SKILLS_STAGING = HOME / ".hermes" / "skills-staging"
PLUGINS_STAGING = HOME / ".hermes" / "plugins-staging"
SKILLS_ACTIVE = HOME / ".hermes" / "skills"
PLUGINS_ACTIVE = HOME / ".hermes" / "hermes-agent" / "plugins"

TEST_SKILL_NAME = "__faro_test_skill__"
TEST_PLUGIN_NAME = "__faro_test_plugin__"


def _cleanup():
    """Remove test artifacts from staging and active dirs."""
    for d in [SKILLS_STAGING / TEST_SKILL_NAME,
              SKILLS_STAGING / "creative",
              PLUGINS_STAGING / TEST_PLUGIN_NAME,
              PLUGINS_STAGING / "model-providers",
              SKILLS_ACTIVE / TEST_SKILL_NAME,
              PLUGINS_ACTIVE / TEST_PLUGIN_NAME]:
        if d.exists():
            import shutil
            shutil.rmtree(d, ignore_errors=True)


def _create_staged_skill(name: str = TEST_SKILL_NAME, nested: bool = False):
    """Create a test skill in staging. Returns its Path."""
    if nested:
        d = SKILLS_STAGING / "creative" / name
    else:
        d = SKILLS_STAGING / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"# {name}")
    return d


def _create_staged_plugin(name: str = TEST_PLUGIN_NAME, nested: bool = False):
    """Create a test plugin in staging. Returns its Path."""
    if nested:
        d = PLUGINS_STAGING / "model-providers" / name
    else:
        d = PLUGINS_STAGING / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "__init__.py").write_text(f"# {name}")
    return d


def test_approve_reject_kind():
    """approve() and reject() work with kind=skill and kind=plugin."""
    _cleanup()
    try:
        from faro.staged import approve, reject, list_staged

        # Create test skill
        s = _create_staged_skill()
        items = list_staged()
        assert any(i["name"] == TEST_SKILL_NAME for i in items), "staged skill not listed"

        # Approve skill
        result = approve(TEST_SKILL_NAME, kind="skill", force=True)
        assert result is not None, f"approve failed: expected path, got None"
        assert (SKILLS_ACTIVE / TEST_SKILL_NAME).exists(), "skill not moved to active"

        # Reject it back (simulate: create a new staging copy)
        (SKILLS_ACTIVE / TEST_SKILL_NAME).rename(SKILLS_STAGING / TEST_SKILL_NAME)
        ok = reject(TEST_SKILL_NAME, kind="skill")
        assert ok, "reject should return True"
        assert not (SKILLS_STAGING / TEST_SKILL_NAME).exists(), "staging dir should be deleted"

        # Create test plugin
        p = _create_staged_plugin()
        result = approve(TEST_PLUGIN_NAME, kind="plugin", force=True)
        assert result is not None, "plugin approve failed"
        assert (PLUGINS_ACTIVE / TEST_PLUGIN_NAME).exists(), "plugin not moved to active"

        # Reject it
        (PLUGINS_ACTIVE / TEST_PLUGIN_NAME).rename(PLUGINS_STAGING / TEST_PLUGIN_NAME)
        ok = reject(TEST_PLUGIN_NAME, kind="plugin")
        assert ok, "plugin reject should return True"

    finally:
        _cleanup()


def test_purge_staging_all_clears_both():
    """purge_staging('all') clears both skills and plugins."""
    _cleanup()
    try:
        from faro.staged import purge_staging

        _create_staged_skill(TEST_SKILL_NAME)
        _create_staged_plugin(TEST_PLUGIN_NAME)

        count = purge_staging(kind="all")
        assert count == 2, f"Expected 2 purged, got {count}"

        assert not (SKILLS_STAGING / TEST_SKILL_NAME).exists(), "skill staging not purged"
        assert not (PLUGINS_STAGING / TEST_PLUGIN_NAME).exists(), "plugin staging not purged"

    finally:
        _cleanup()


def test_hook_check_staging_nested():
    """Hook check_staging() finds nested skill by leaf name, not category."""
    _cleanup()
    try:
        from faro.hook import check_staging

        _create_staged_skill("pixel-art", nested=True)

        items = check_staging()
        names = [i["name"] for i in items]
        assert "pixel-art" in names, f"nested skill not found: {names}"
        assert "creative" not in names, f"category dir should not be in: {names}"

    finally:
        _cleanup()


def test_scan_staging_nested():
    """scan_staging() finds nested skills/plugins, not category dirs."""
    _cleanup()
    try:
        from faro.scanner import scan_staging

        _create_staged_skill("pixel-art", nested=True)
        _create_staged_plugin("openai", nested=True)

        results = scan_staging()
        names = {r.name for r in results}
        assert "pixel-art" in names, f"nested skill missing: {names}"
        assert "openai" in names, f"nested plugin missing: {names}"
        assert "creative" not in names, f"category dir should not be scanned"
        assert "model-providers" not in names, f"category dir should not be scanned"

    finally:
        _cleanup()


def test_approve_rejects_category_dir():
    """approve() does not find category dirs like 'creative' as staged items."""
    _cleanup()
    try:
        from faro.staged import approve

        _create_staged_skill("pixel-art", nested=True)
        # Try to approve "creative" — should fail
        result = approve("creative", kind="skill", force=True)
        assert result is None, "approve should not find category dir 'creative'"

    finally:
        _cleanup()


def test_scan_staging_category_not_scanned():
    """scan_staging() with a plugin category dir doesn't scan the category itself."""
    _cleanup()
    try:
        from faro.scanner import scan_staging

        # Create a plugin category dir with __init__.py (like model-providers)
        cat = PLUGINS_STAGING / "model-providers"
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
        _cleanup()


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
