"""Regression tests for manifest identity — nested skill/plugin name collision prevention."""

import os
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faro.manifest import (
    _manifest_key, _compute_relative_path,
    _find_skill_dirs, find_unvetted,
    add_to_manifest, remove_from_manifest,
    load_manifest, _get_manifest_path,
)


def _setup_nested_active(home: Path):
    """Create active dirs with same-named skills in different parent dirs."""
    skills = home / ".hermes" / "skills"
    plugins = home / ".hermes" / "hermes-agent" / "plugins"
    skills.mkdir(parents=True, exist_ok=True)
    plugins.mkdir(parents=True, exist_ok=True)

    # cat1/foo + cat2/foo — same name, different parent
    (skills / "cat1" / "foo").mkdir(parents=True)
    (skills / "cat1" / "foo" / "SKILL.md").write_text("# foo v1")
    (skills / "cat2" / "foo").mkdir(parents=True)
    (skills / "cat2" / "foo" / "SKILL.md").write_text("# foo v2")


def test_same_name_nested_skill_distinct_manifest_entries():
    """cat1/foo and cat2/foo must have different manifest keys."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        _setup_nested_active(home)
        try:
            import faro.manifest as m
            orig = m._get_manifest_path
            # Use manifest in temp home
            m._get_manifest_path = orig  # restore — uses FARO_HOME

            # Vet only cat1/foo
            add_to_manifest("foo", str(home / ".hermes" / "skills" / "cat1" / "foo"), "skill")
            data = load_manifest()
            # Should have key skill:cat1/foo
            assert "skill:cat1/foo" in data, f"Expected skill:cat1/foo, got: {list(data.keys())}"
            # cat2/foo should NOT be in manifest
            assert "skill:cat2/foo" not in data

            # find_unvetted must report cat2/foo as not_in_manifest
            unvetted = find_unvetted()
            cat2_unvetted = [u for u in unvetted if u["name"] == "foo" and "cat2" in u["relative_path"]]
            assert len(cat2_unvetted) == 1, f"cat2/foo should be unvetted, got: {unvetted}"
            assert cat2_unvetted[0]["reason"] == "not_in_manifest"
        finally:
            del os.environ["FARO_HOME"]


def test_plugin_yaml_root_with_python_subpackage_scans_root():
    """demo/plugin.yaml + demo/lib/__init__.py → discovers demo, not demo/lib."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        demo = root / "demo"
        demo.mkdir()
        (demo / "plugin.yaml").write_text("name: demo")
        lib = demo / "lib"
        lib.mkdir()
        (lib / "__init__.py").write_text("")

        result = _find_skill_dirs(root, kind="plugin")
        names = {d.name for d in result}
        assert "demo" in names, f"plugin root 'demo' missing: {names}"
        assert "lib" not in names, f"sub-package 'lib' should not be a standalone plugin: {names}"


def test_plugin_category_with_child_plugins_still_excluded():
    """model-providers/__init__.py + model-providers/openai/__init__.py → only openai."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cat = root / "model-providers"
        cat.mkdir()
        (cat / "__init__.py").write_text("")
        sub = cat / "openai"
        sub.mkdir()
        (sub / "__init__.py").write_text("")

        result = _find_skill_dirs(root, kind="plugin")
        names = {d.name for d in result}
        assert "openai" in names, f"sub-plugin 'openai' missing: {names}"
        assert "model-providers" not in names, f"category dir should be excluded: {names}"


def test_reject_does_not_remove_active_manifest_entry():
    """Rejecting a staged update should not delete the active manifest entry."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)
        # Create active skill and add to manifest
        active = home / ".hermes" / "skills" / "my-skill"
        active.mkdir(parents=True)
        (active / "SKILL.md").write_text("# my-skill")
        add_to_manifest("my-skill", str(active), "skill")

        # Create staging dir with same name
        staging = home / ".hermes" / "skills-staging"
        staging.mkdir(parents=True, exist_ok=True)
        staged_item = staging / "my-skill"
        staged_item.mkdir()
        (staged_item / "SKILL.md").write_text("# updated")

        try:
            from faro.staged import reject
            ok = reject("my-skill", kind="skill")
            assert ok, "reject should succeed"
            assert not staged_item.exists(), "staged item should be deleted"

            # Active manifest entry must still exist
            data = load_manifest()
            found = any(
                entry.get("name") == "my-skill" and entry.get("kind") == "skill"
                for entry in data.values()
            )
            assert found, "active manifest entry was deleted by reject!"
        finally:
            del os.environ["FARO_HOME"]


if __name__ == "__main__":
    tests = [
        ("nested_skill_distinct_keys", test_same_name_nested_skill_distinct_manifest_entries),
        ("plugin_yaml_root_with_subpackage", test_plugin_yaml_root_with_python_subpackage_scans_root),
        ("plugin_category_excluded", test_plugin_category_with_child_plugins_still_excluded),
        ("reject_preserves_active_manifest", test_reject_does_not_remove_active_manifest_entry),
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
