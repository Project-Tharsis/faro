"""Regression tests for hash v2 — content hash must include file boundaries."""

import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faro.manifest import _content_hash, _structure_hash


def test_content_hash_includes_file_boundaries():
    """a.py='ab', b.py='c' vs a.py='a', b.py='bc' must produce different hashes."""
    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        root1 = Path(td1)
        root2 = Path(td2)

        # Case 1: a.py='ab', b.py='c' → concatenated = 'abc'
        (root1 / "a.py").write_text("ab")
        (root1 / "b.py").write_text("c")

        # Case 2: a.py='a', b.py='bc' → concatenated = 'abc'
        (root2 / "a.py").write_text("a")
        (root2 / "b.py").write_text("bc")

        h1 = _content_hash(root1)
        h2 = _content_hash(root2)

        assert h1 != h2, (
            f"Content hash collision! Both hashes = {h1}\n"
            f"a.py='ab'+b.py='c' should ≠ a.py='a'+b.py='bc'"
        )


def test_content_hash_changes_when_md_changes():
    """Changing SKILL.md must change content_hash (v2 includes .md files)."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        (root / "SKILL.md").write_text("# version 1")
        h1 = _content_hash(root)

        (root / "SKILL.md").write_text("# version 2")
        h2 = _content_hash(root)

        assert h1 != h2, f"Content hash didn't change when SKILL.md changed! Both = {h1}"


def test_content_hash_changes_when_yaml_changes():
    """Changing .yaml config must change content_hash (v2 includes .yaml files)."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        (root / "config.yaml").write_text("key: value1")
        h1 = _content_hash(root)

        (root / "config.yaml").write_text("key: value2")
        h2 = _content_hash(root)

        assert h1 != h2, f"Content hash didn't change when config.yaml changed!"


def test_structure_hash_changes_on_added_file():
    """Adding a file must change structure_hash."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("x")
        h1 = _structure_hash(root)

        (root / "b.py").write_text("y")
        h2 = _structure_hash(root)

        assert h1 != h2, f"Structure hash didn't change when file added!"


def test_structure_hash_stable_on_content_change():
    """Changing file content only should NOT change structure_hash."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("x = 1")
        h1 = _structure_hash(root)

        (root / "a.py").write_text("x = 999")
        h2 = _structure_hash(root)

        assert h1 == h2, f"Structure hash changed on content-only change!"


def test_hash_is_full_hexdigest():
    """v2 hashes must be full SHA-256 hexdigest (64 chars), not truncated."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("hello world" * 100)

        ch = _content_hash(root)
        sh = _structure_hash(root)

        assert len(ch) == 64, f"Content hash truncated: {len(ch)} chars (expected 64)"
        assert len(sh) == 64, f"Structure hash truncated: {len(sh)} chars (expected 64)"


if __name__ == "__main__":
    tests = [
        ("hash_file_boundaries", test_content_hash_includes_file_boundaries),
        ("hash_md_changes", test_content_hash_changes_when_md_changes),
        ("hash_yaml_changes", test_content_hash_changes_when_yaml_changes),
        ("structure_added_file", test_structure_hash_changes_on_added_file),
        ("structure_stable_content", test_structure_hash_stable_on_content_change),
        ("hash_full_hexdigest", test_hash_is_full_hexdigest),
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
