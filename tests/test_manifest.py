"""Regression tests for faro manifest and CLI."""

import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faro.manifest import (
    _manifest_key, _structure_hash, _content_hash,
    _find_skill_dirs, find_unvetted,
    add_to_manifest, remove_from_manifest,
    load_manifest, _get_manifest_path,
)


def test_key_format():
    """skill:foo / plugin:foo keys prevent name collision."""
    import faro.manifest as m
    orig = m._get_manifest_path
    tmp = Path(tempfile.mktemp(suffix=".json"))
    m._get_manifest_path = lambda: tmp
    try:
        add_to_manifest("same", "/tmp/same-skill", "skill")
        add_to_manifest("same", "/tmp/same-plugin", "plugin")
        data = load_manifest()
        assert "skill:same" in data, "skill key missing"
        assert "plugin:same" in data, "plugin key missing"
        assert data["skill:same"]["kind"] == "skill"
        assert data["plugin:same"]["kind"] == "plugin"
    finally:
        tmp.unlink(missing_ok=True)
        m._get_manifest_path = orig


def test_name_collision_removed():
    """Remove one doesn't affect the other."""
    import faro.manifest as m
    orig = m._get_manifest_path
    tmp = Path(tempfile.mktemp(suffix=".json"))
    m._get_manifest_path = lambda: tmp
    try:
        add_to_manifest("same", "/tmp/same-skill", "skill")
        add_to_manifest("same", "/tmp/same-plugin", "plugin")
        remove_from_manifest("same", "skill")
        data = load_manifest()
        assert "skill:same" not in data
        assert "plugin:same" in data, "plugin accidentally removed"
        remove_from_manifest("same", "plugin")  # cleanup
    finally:
        tmp.unlink(missing_ok=True)
        m._get_manifest_path = orig


def test_find_skill_dirs_skill_leaf_only():
    """Skills: only dirs with SKILL.md; no category parents."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cat = root / "creative"
        skill = cat / "pixel-art"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("# pixel-art")
        (cat / "not-a-skill").mkdir()
        (cat / "README.md").write_text("readme")

        result = _find_skill_dirs(root, kind="skill")
        names = {d.name for d in result}
        assert "pixel-art" in names, f"leaf skill missing: {names}"
        assert "creative" not in names, f"category parent should not be in {names}"
        assert "not-a-skill" not in names, f"non-skill dir in {names}"


def test_find_skill_dirs_plugin_found():
    """Plugins: dirs with plugin.yaml or __init__.py are found."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        plugin = root / "demo-plugin"
        plugin.mkdir()
        (plugin / "plugin.yaml").write_text("name: demo")
        (plugin / "__init__.py").write_text("")

        result = _find_skill_dirs(root, kind="plugin")
        names = {d.name for d in result}
        assert "demo-plugin" in names, f"plugin dir missing: {names}"


def test_find_skill_dirs_plugin_category_excluded():
    """Plugin category dirs (model-providers) are excluded."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cat = root / "model-providers"
        cat.mkdir()
        (cat / "__init__.py").write_text("")  # category has __init__.py
        sub = cat / "openai"
        sub.mkdir()
        (sub / "__init__.py").write_text("")

        result = _find_skill_dirs(root, kind="plugin")
        names = {d.name for d in result}
        assert "openai" in names, f"sub-plugin missing: {names}"
        assert "model-providers" not in names, f"category should be excluded: {names}"


def test_structure_hash_stable():
    """structure_hash only changes on file add/remove/rename, not content."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skill = root / "test-skill"
        skill.mkdir()
        (skill / "source.py").write_text("x = 1")

        s1 = _structure_hash(skill)

        # Change content, keep structure
        (skill / "source.py").write_text("x = 999")

        s2 = _structure_hash(skill)
        assert s1 == s2, "structure_hash changed on content-only change"


def test_content_hash_changes():
    """content_hash changes when file content changes."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skill = root / "test-content"
        skill.mkdir()
        (skill / "source.py").write_text("x = 1")

        c1 = _content_hash(skill)
        (skill / "source.py").write_text("x = 2")
        c2 = _content_hash(skill)

        assert c1 != c2, "content_hash didn't change when content changed"


def test_json_output_pure():
    """faro scan --staged --json produces valid JSON, even when empty."""
    result = __import__("subprocess").run(
        [sys.executable, "-m", "faro.cli", "scan", "--staged", "--json"],
        capture_output=True, text=True, cwd=str(Path(__file__).parent.parent)
    )
    output = result.stdout.strip()
    data = json.loads(output)
    assert isinstance(data, list), f"Expected JSON array, got: {output[:100]}"


if __name__ == "__main__":
    tests = [
        ("key_format", test_key_format),
        ("name_collision", test_name_collision_removed),
        ("leaf_only_skill", test_find_skill_dirs_skill_leaf_only),
        ("plugin_found", test_find_skill_dirs_plugin_found),
        ("plugin_category_excluded", test_find_skill_dirs_plugin_category_excluded),
        ("structure_hash_stable", test_structure_hash_stable),
        ("content_hash_changes", test_content_hash_changes),
        ("json_pure", test_json_output_pure),
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
