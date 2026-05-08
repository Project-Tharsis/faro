"""Regression tests for symlink detection and archive file scanning."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faro.scanner import scan_directory


def test_symlink_escape_is_critical():
    """External symlink → critical finding."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "test-skill"
        root.mkdir()
        (root / "SKILL.md").write_text("# test")

        # Create symlink to external path
        external = Path(td) / "external.txt"
        external.write_text("secret")
        symlink = root / "link_to_external"
        symlink.symlink_to(external)

        result = scan_directory(str(root))
        symlink_findings = [f for f in result.findings if f.pattern_id == "symlink-escape"]
        assert len(symlink_findings) >= 1, \
            f"External symlink not detected as critical, findings: {result.findings}"
        assert symlink_findings[0].severity == "critical"


def test_symlink_internal_is_medium():
    """Internal symlink (within item root) → medium finding."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "test-skill"
        root.mkdir()
        (root / "SKILL.md").write_text("# test")
        (root / "subdir").mkdir()

        internal_target = root / "subdir" / "target.txt"
        internal_target.write_text("data")
        symlink = root / "link_to_internal"
        symlink.symlink_to(internal_target)

        result = scan_directory(str(root))
        symlink_findings = [f for f in result.findings if f.pattern_id == "symlink-internal"]
        assert len(symlink_findings) >= 1, \
            f"Internal symlink not detected as medium, findings: {result.findings}"
        assert all(f.severity in ("medium",) for f in symlink_findings)


def test_archive_file_is_high():
    """Archive files (.zip, .tar, .whl) → high finding."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "test-skill"
        root.mkdir()
        (root / "SKILL.md").write_text("# test")
        (root / "payload.zip").write_bytes(b"PK\x03\x04")
        (root / "payload.tar").write_bytes(b"ustar\x00")

        result = scan_directory(str(root))
        archive_findings = [f for f in result.findings if f.pattern_id == "archive-file"]
        assert len(archive_findings) >= 2, \
            f"Archive files not detected, findings: {result.findings}"
        assert all(f.severity == "high" for f in archive_findings)


def test_approve_rejects_symlink_escape():
    """approve() blocks external symlinks even with --force."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        os.environ["FARO_HOME"] = str(home)

        # Create active dirs
        staging = home / ".hermes" / "skills-staging"
        active = home / ".hermes" / "skills"
        staging.mkdir(parents=True)
        active.mkdir(parents=True)

        # Create staged skill with external symlink
        skill = staging / "evil-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("# evil")

        # External symlink
        external = Path(td) / "secret.txt"
        external.write_text("stolen data")
        (skill / "escape").symlink_to(external)

        try:
            from faro.staged import approve
            result = approve("evil-skill", kind="skill", force=True)
            assert result is None, \
                f"approve with --force should reject symlink escape, got: {result}"
        finally:
            del os.environ["FARO_HOME"]


def test_scan_full_pipeline_detects_ast():
    """Full scan_directory() triggers AST scanner for .py files."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "test-skill"
        root.mkdir()
        (root / "SKILL.md").write_text("# test")

        # Write a Python file with from subprocess import run
        (root / "bad.py").write_text("""
from subprocess import run
run(["id"])
""")

        result = scan_directory(str(root))
        ast_findings = [f for f in result.findings if "ast" in f.pattern_id]
        assert len(ast_findings) >= 1, \
            f"AST scanner not triggered in scan_directory(), findings: {result.findings}"


if __name__ == "__main__":
    tests = [
        ("symlink_escape_critical", test_symlink_escape_is_critical),
        ("symlink_internal_medium", test_symlink_internal_is_medium),
        ("archive_file_high", test_archive_file_is_high),
        ("approve_rejects_symlink_escape", test_approve_rejects_symlink_escape),
        ("scan_pipeline_detects_ast", test_scan_full_pipeline_detects_ast),
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
