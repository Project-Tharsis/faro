"""Regression tests for faro manifest and CLI."""

import json
import tempfile
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faro.manifest import (
    _manifest_key, _structure_hash, _content_hash,
    _find_skill_dirs, find_unvetted,
    add_to_manifest, remove_from_manifest,
    load_manifest, save_manifest, MANIFEST_PATH, init_manifest,
)


def setup_module():
    """Backup and clear manifest for clean test runs."""
    global _orig_manifest
    _orig_manifest = None
    if MANIFEST_PATH.exists():
        _orig_manifest = MANIFEST_PATH.read_bytes()
    # Use temp manifest
    import faro.manifest as m
    m.MANIFEST_PATH = Path(tempfile.mktemp(suffix=".json"))


def teardown_module():
    """Restore original manifest."""
    import faro.manifest as m
    if _orig_manifest:
        MANIFEST_PATH.write_bytes(_orig_manifest)


def test_key_format():
    """skill:foo / plugin:foo keys prevent name collision."""
    add_to_manifest("same", "/tmp/same-skill", "skill")
    add_to_manifest("same", "/tmp/same-plugin", "plugin")
    data = load_manifest()
    assert "skill:same" in data, "skill key missing"
    assert "plugin:same" in data, "plugin key missing"
    assert data["skill:same"]["kind"] == "skill"
    assert data["plugin:same"]["kind"] == "plugin"


def test_name_collision_removed():
    """Remove one doesn't affect the other."""
    remove_from_manifest("same", "skill")
    data = load_manifest()
    assert "skill:same" not in data
    assert "plugin:same" in data, "plugin accidentally removed"
    remove_from_manifest("same", "plugin")  # cleanup


def test_find_skill_dirs_leaf_only():
    """_find_skill_dirs returns only SKILL.md dirs, not category parents."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cat = root / "creative"
        skill = cat / "pixel-art"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("# pixel-art")
        (cat / "not-a-skill").mkdir()
        (cat / "README.md").write_text("readme")

        result = _find_skill_dirs(root)
        names = [d.name for d in result]
        assert "pixel-art" in names, f"leaf skill missing from {names}"
        assert "creative" not in names, f"category parent should not be in {names}"
        assert "not-a-skill" not in names, f"non-skill dir in {names}"


def test_find_unvetted_structure_changed():
    """Changing a file name triggers structure_changed."""
    import faro.manifest as m
    m.MANIFEST_PATH = Path(tempfile.mktemp(suffix=".json"))
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skill = root / "test-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("# test")
        (skill / "source.py").write_text("x = 1")

        add_to_manifest("test-skill", str(skill), "skill")

        # Now change structure: rename file
        (skill / "source.py").rename(skill / "renamed.py")

        unvetted = find_unvetted()
        assert len(unvetted) > 0, "structure change should be detected"
        # But we're not scanning the actual $HERMES_HOME, so just check function

    # Cleanup
    m.MANIFEST_PATH.unlink(missing_ok=True)


def test_json_output_pure():
    """faro scan --staged --json produces valid JSON, no summary lines."""
    # Create a temporary staged item
    home = Path.home()
    staging = home / ".hermes" / "skills-staging" / "json-test-skill"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "SKILL.md").write_text("# test")
    (staging / "safe.py").write_text("print('hello')")

    faro_bin = str(Path(__file__).parent.parent / ".venv" / "bin" / "faro")
    result = subprocess.run(
        [faro_bin, "scan", "--staged", "--json"],
        capture_output=True, text=True
    )

    # Cleanup
    import shutil
    shutil.rmtree(staging)

    # Parse as JSON
    output = result.stdout.strip()
    try:
        data = json.loads(output)
        assert isinstance(data, list), f"Expected JSON array, got: {output[:100]}"
        assert len(data) == 1
        assert data[0]["name"] == "json-test-skill"
    except json.JSONDecodeError:
        raise AssertionError(f"Output is not valid JSON: {output[:200]}")


def test_content_hash_changes():
    """Changing file content changes content_hash but not structure_hash."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        skill = root / "test-content"
        skill.mkdir()
        (skill / "source.py").write_text("x = 1")

        s1 = _structure_hash(skill)
        c1 = _content_hash(skill)

        # Change content, keep structure
        (skill / "source.py").write_text("x = 2")

        s2 = _structure_hash(skill)
        c2 = _content_hash(skill)

        assert s1 == s2, "structure_hash changed when only content changed"
        assert c1 != c2, "content_hash didn't change when content changed"


if __name__ == "__main__":
    # Run tests manually
    tests = [
        ("key_format", test_key_format),
        ("name_collision", test_name_collision_removed),
        ("leaf_only", test_find_skill_dirs_leaf_only),
        ("json_pure", test_json_output_pure),
        ("content_hash", test_content_hash_changes),
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
