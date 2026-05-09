"""v0.7 tests: manifest approval metadata, profile behavior, allowed_findings."""

import json
import os
import tempfile
import subprocess
import sys
import time
from pathlib import Path

FARO_CLI = [sys.executable, "-m", "faro.cli"]


def _run_cli(args, cwd=None, home=None):
    faro_home = str(Path(home) if home else Path(tempfile.mkdtemp()))
    env = {"PYTHONPATH": "src", "FARO_HOME": faro_home}
    result = subprocess.run(
        FARO_CLI + args,
        capture_output=True, text=True, timeout=15,
        cwd=cwd, env={**os.environ, **env},
    )
    return result


def _make_skill(home: Path, name: str, subdir: str = ""):
    """Create a minimal skill directory under home/.hermes/skills-staging/subdir."""
    staging = home / ".hermes" / "skills-staging"
    if subdir:
        staging = staging / subdir
    staging.mkdir(parents=True, exist_ok=True)
    skill_dir = staging / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text("# Minimal skill\n")
    return skill_dir


def _make_plugin(home: Path, name: str):
    """Create a minimal plugin directory."""
    staging = home / ".hermes" / "plugins-staging"
    staging.mkdir(parents=True, exist_ok=True)
    plugin_dir = staging / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.yaml").write_text("name: test-plugin\n")
    (plugin_dir / "__init__.py").write_text("# plugin\n")
    return plugin_dir


# ============================================================
# Old manifest compatibility
# ============================================================

def test_old_manifest_loads_without_approval_fields():
    """Manifest without approval_schema_version should load normally."""
    td = Path(tempfile.mkdtemp())
    mf = td / ".hermes"
    mf.mkdir(parents=True)
    manifest = {
        "skill:old-skill": {
            "name": "old-skill",
            "path": str(td / "skills" / "old-skill"),
            "kind": "skill",
            "relative_path": "old-skill",
            "structure_hash": "abc123",
            "content_hash": "def456",
            "hash_version": 2,
            "vetted_at": "2025-01-01 00:00:00",
            "scanner_version": "0.5.0",
        }
    }
    (mf / ".faro-manifest.json").write_text(json.dumps(manifest))

    r = _run_cli(["check", "--json"], home=td)
    data = json.loads(r.stdout)
    # Legacy v2 → personal profile should not report anything (no approval check for legacy)
    assert data == [], f"Expected no findings for legacy v2 in personal, got {data}"


def test_old_manifest_enterprise_reports_legacy():
    """Old manifest without schema version: enterprise reports approval_legacy."""
    td = Path(tempfile.mkdtemp())
    mf = td / ".hermes"
    active = mf / "skills" / "old-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Old\n")

    manifest = {
        "skill:old-skill": {
            "name": "old-skill",
            "path": str(active),
            "kind": "skill",
            "relative_path": "old-skill",
            "structure_hash": _hash_dir(active),
            "content_hash": _hash_content(active),
            "hash_version": 2,
            "vetted_at": "2025-01-01 00:00:00",
            "scanner_version": "0.5.0",
        }
    }
    (mf / ".faro-manifest.json").write_text(json.dumps(manifest))

    r = _run_cli(["check", "--profile", "enterprise", "--json"], home=td)
    data = json.loads(r.stdout)
    reasons = [d["reason"] for d in data]
    assert "approval_legacy" in reasons, f"Expected approval_legacy, got {reasons}"
    assert "not_in_manifest" not in reasons, "Legacy should not be not_in_manifest"


# ============================================================
# Approval metadata writing
# ============================================================

def test_approve_writes_approval_metadata():
    """approve --owner --expires 30d should write metadata to manifest."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--owner", "user@x.com",
        "--expires", "30d",
    ], home=td)
    assert r.returncode == 0, f"Approve failed: {r.stderr}"

    mf = td / ".hermes" / ".faro-manifest.json"
    data = json.loads(mf.read_text())
    key = next(iter(data))
    entry = data[key]
    assert entry["owner"] == "user@x.com"
    assert entry["expires_at"] is not None
    assert entry["approval_schema_version"] == 3
    assert entry["approval_source"] == "approve"


def test_vet_writes_approval_metadata():
    """vet --owner --expires should write metadata."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "vet-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Vet me\n")

    r = _run_cli([
        "vet", "vet-skill",
        "--path", str(active),
        "--owner", "reviewer@x.com",
        "--expires", "2026-12-31",
    ], home=td)
    assert r.returncode == 0, f"Vet failed: {r.stderr}"

    mf = td / ".hermes" / ".faro-manifest.json"
    data = json.loads(mf.read_text())
    key = next(iter(data))
    entry = data[key]
    assert entry["owner"] == "reviewer@x.com"
    assert entry["expires_at"] == "2026-12-31"
    assert entry["approval_source"] == "vet"


# ============================================================
# Expires parsing
# ============================================================

def test_invalid_expires_exit_2():
    """Invalid --expires format should exit 2."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--owner", "u@x.com",
        "--expires", "invalid",
    ], home=td)
    assert r.returncode == 2, f"Expected exit 2 for invalid expires, got {r.returncode}"


def test_past_expires_exit_2():
    """Past date in --expires should exit 2."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--owner", "u@x.com",
        "--expires", "2020-01-01",
    ], home=td)
    assert r.returncode == 2, f"Expected exit 2 for past expires, got {r.returncode}"


# ============================================================
# Profile enforcement — personal
# ============================================================

def test_personal_auto_approved_by():
    """personal profile + --owner → approved_by = owner (auto)."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--profile", "personal",
        "--owner", "alice@x.com",
    ], home=td)
    assert r.returncode == 0

    mf = td / ".hermes" / ".faro-manifest.json"
    data = json.loads(mf.read_text())
    entry = next(iter(data.values()))
    assert entry["approved_by"] == "alice@x.com"


# ============================================================
# Profile enforcement — team
# ============================================================

def test_team_requires_owner_exit_2():
    """team profile without --owner should exit 2."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--profile", "team",
    ], home=td)
    assert r.returncode == 2


def test_team_requires_approved_by_exit_2():
    """team profile with owner but no approved_by (and no env) → exit 2."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--profile", "team",
        "--owner", "bob@x.com",
    ], home=td)
    assert r.returncode == 2


def test_team_with_faro_approver_env_passes():
    """team profile with FARO_APPROVER env set should pass."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--profile", "team",
        "--owner", "bob@x.com",
    ], home=td)
    # Without FARO_APPROVER this fails, but we test the env variant
    # by overriding environ
    faro_home = str(td)
    env = {
        "PYTHONPATH": "src",
        "FARO_HOME": faro_home,
        "FARO_APPROVER": "admin@x.com",
        **os.environ,
    }
    result = subprocess.run(
        FARO_CLI + ["approve", "test-skill", "--profile", "team", "--owner", "bob@x.com"],
        capture_output=True, text=True, timeout=15, env=env,
    )
    assert result.returncode == 0, f"Expected 0, got {result.returncode}: {result.stderr}"


def test_team_check_metadata_missing():
    """check --profile team should report approval_metadata_missing when no owner."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "no-owner-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# No owner\n")
    mf = td / ".hermes" / ".faro-manifest.json"
    entry = {
        "skill:no-owner-skill": {
            "name": "no-owner-skill",
            "path": str(active),
            "kind": "skill",
            "relative_path": "no-owner-skill",
            "structure_hash": _hash_dir(active),
            "content_hash": _hash_content(active),
            "hash_version": 2,
            "vetted_at": "2026-01-01 00:00:00",
            "scanner_version": "0.7.0",
            "approval_schema_version": 3,
            "owner": None,
            "approved_by": None,
            "expires_at": None,
            "allowed_findings": [],
        }
    }
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps(entry))

    r = _run_cli(["check", "--profile", "team", "--json"], home=td)
    data = json.loads(r.stdout)
    assert len(data) >= 1
    assert data[0]["reason"] == "approval_metadata_missing"


# ============================================================
# Profile enforcement — enterprise
# ============================================================

def test_enterprise_requires_owner_and_approved_by():
    """enterprise profile without owner or approved_by → exit 2."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "test-skill")

    r = _run_cli([
        "approve", "test-skill",
        "--profile", "enterprise",
    ], home=td)
    assert r.returncode == 2


def test_enterprise_no_expires_is_ok():
    """enterprise with owner+approved_by but no expires should pass check."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "ent-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Enterprise\n")
    mf = td / ".hermes" / ".faro-manifest.json"
    entry = {
        "skill:ent-skill": {
            "name": "ent-skill",
            "path": str(active),
            "kind": "skill",
            "relative_path": "ent-skill",
            "structure_hash": _hash_dir(active),
            "content_hash": _hash_content(active),
            "hash_version": 2,
            "vetted_at": "2026-01-01 00:00:00",
            "scanner_version": "0.7.0",
            "approval_schema_version": 3,
            "owner": "alice@corp.com",
            "approved_by": "bob@corp.com",
            "expires_at": None,
            "allowed_findings": [],
        }
    }
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps(entry))

    r = _run_cli(["check", "--profile", "enterprise", "--json"], home=td)
    data = json.loads(r.stdout)
    reasons = [d["reason"] for d in data]
    # No metadata_missing because owner+approved_by are set, no expiry required
    assert "approval_metadata_missing" not in reasons, f"Should not report missing: {data}"


# ============================================================
# Expiry detection
# ============================================================

def test_expired_entry_reported():
    """Past expires_at should be reported as approval_expired."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "expired-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Expired\n")
    mf = td / ".hermes" / ".faro-manifest.json"
    entry = {
        "skill:expired-skill": {
            "name": "expired-skill",
            "path": str(active),
            "kind": "skill",
            "relative_path": "expired-skill",
            "structure_hash": _hash_dir(active),
            "content_hash": _hash_content(active),
            "hash_version": 2,
            "vetted_at": "2025-01-01 00:00:00",
            "scanner_version": "0.7.0",
            "approval_schema_version": 3,
            "owner": "old@x.com",
            "approved_by": "boss@x.com",
            "expires_at": "2025-06-01",
            "allowed_findings": [],
        }
    }
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps(entry))

    r = _run_cli(["check", "--profile", "personal", "--json"], home=td)
    data = json.loads(r.stdout)
    reasons = [d["reason"] for d in data]
    assert "approval_expired" in reasons, f"Expected approval_expired, got {reasons}"


# ============================================================
# Allowed findings
# ============================================================

def test_allow_valid_finding_writes_allowed_findings():
    """--allow with existing finding id should write to manifest."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "risky-skill")
    # Add dangerous content to trigger a finding (Bash(*) triggers tool-broad-shell on .md)
    skill_dir = td / ".hermes" / "skills-staging" / "risky-skill"
    (skill_dir / "SKILL.md").write_text(
        "# Risky\n"
        "Bash(python3 *)\n"
    )

    r = _run_cli([
        "approve", "risky-skill", "--force",
        "--owner", "u@x.com",
        "--allow", "tool-broad-shell",
        "--reason", "reviewed shell access",
    ], home=td)
    assert r.returncode == 0, f"Approve failed: {r.stderr}"

    mf = td / ".hermes" / ".faro-manifest.json"
    data = json.loads(mf.read_text())
    entry = next(iter(data.values()))
    af = entry.get("allowed_findings", [])
    assert len(af) >= 1, f"No allowed_findings: {entry}"
    assert af[0]["id"] == "tool-broad-shell"


def test_allow_nonexistent_finding_exit_2():
    """--allow with non-existent finding id should exit 2."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "clean-skill")

    r = _run_cli([
        "approve", "clean-skill",
        "--owner", "u@x.com",
        "--allow", "this-does-not-exist",
    ], home=td)
    assert r.returncode == 2, f"Expected exit 2 for bad --allow, got {r.returncode}"


def test_allow_symlink_escape_hard_block():
    """--allow symlink-escape should always be rejected."""
    td = Path(tempfile.mkdtemp())
    _make_skill(td, "link-skill")
    # Create a symlink file in the skill dir
    ext = td / "external"
    ext.mkdir()
    (ext / "secret.txt").write_text("secret\n")
    skill_dir = td / ".hermes" / "skills-staging" / "link-skill"
    sym = skill_dir / "link_to_secret"
    sym.symlink_to(ext / "secret.txt")

    r = _run_cli([
        "approve", "link-skill", "--force",
        "--owner", "u@x.com",
        "--allow", "symlink-escape",
    ], home=td)
    # Should be blocked even with --force + --allow
    assert r.returncode != 0, f"Symlink escape should never be allowed: {r.returncode}"


# ============================================================
# init-manifest
# ============================================================

def test_init_manifest_writes_v3_schema():
    """init-manifest should write v3 schema with null owner/approved_by, source=init-manifest."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "init-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Init\n")

    r = _run_cli(["init-manifest"], home=td)
    assert r.returncode == 0

    mf = td / ".hermes" / ".faro-manifest.json"
    data = json.loads(mf.read_text())
    entry = next(iter(data.values()))
    assert entry["approval_schema_version"] == 3
    assert entry["approval_source"] == "init-manifest"
    assert entry["owner"] is None
    assert entry["approved_by"] is None


# ============================================================
# v0.7.1 fixes
# ============================================================

def test_vet_symlink_escape_hard_block():
    """vet should refuse to add asset with symlink escape to manifest."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "vet-link-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Link skill\n")
    ext = td / "external"
    ext.mkdir()
    (ext / "secret.txt").write_text("secret\n")
    sym = active / "link_to_secret"
    sym.symlink_to(ext / "secret.txt")

    r = _run_cli([
        "vet", "vet-link-skill",
        "--path", str(active),
        "--owner", "u@x.com",
    ], home=td)
    # Should exit 2 (hard-block), manifest not created
    assert r.returncode == 2, f"Expected exit 2, got {r.returncode}"
    manifest_path = td / ".hermes" / ".faro-manifest.json"
    assert not manifest_path.exists() or json.loads(manifest_path.read_text()) == {},\
        f"Manifest should be empty: {manifest_path}"


def test_vet_allow_nonexistent_exit_2():
    """vet --allow with non-existent finding id should exit 2."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "vet-clean"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Clean skill\n")

    r = _run_cli([
        "vet", "vet-clean",
        "--path", str(active),
        "--owner", "u@x.com",
        "--allow", "does-not-exist",
    ], home=td)
    assert r.returncode == 2, f"Expected exit 2, got {r.returncode}"


def test_vet_allow_symlink_escape_exit_2():
    """vet --allow symlink-escape should exit 2."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "vet-clean2"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# Clean\n")

    r = _run_cli([
        "vet", "vet-clean2",
        "--path", str(active),
        "--owner", "u@x.com",
        "--allow", "symlink-escape",
    ], home=td)
    assert r.returncode == 2, f"Expected exit 2, got {r.returncode}"


def test_team_check_requires_approved_by():
    """check --profile team should report missing approved_by."""
    td = Path(tempfile.mkdtemp())
    active = td / ".hermes" / "skills" / "no-aprv-skill"
    active.mkdir(parents=True)
    (active / "SKILL.md").write_text("# No approved_by\n")
    mf = td / ".hermes" / ".faro-manifest.json"
    entry = {
        "skill:no-aprv-skill": {
            "name": "no-aprv-skill",
            "path": str(active),
            "kind": "skill",
            "relative_path": "no-aprv-skill",
            "structure_hash": _hash_dir(active),
            "content_hash": _hash_content(active),
            "hash_version": 2,
            "vetted_at": "2026-01-01 00:00:00",
            "scanner_version": "0.7.0",
            "approval_schema_version": 3,
            "owner": "bob@x.com",
            "approved_by": None,
            "expires_at": None,
            "allowed_findings": [],
        }
    }
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps(entry))

    r = _run_cli(["check", "--profile", "team", "--json"], home=td)
    data = json.loads(r.stdout)
    reasons = [d["reason"] for d in data]
    assert "approval_metadata_missing" in reasons, \
        f"Team should require approved_by, got {reasons}"


# ============================================================
# Helpers (mirror manifest.py for test manifest creation)
# ============================================================

def _hash_dir(p: Path) -> str:
    import hashlib
    hasher = hashlib.sha256()
    hasher.update(b"faro-structure-v2\x00")
    try:
        for f in sorted(p.rglob("*"), key=lambda x: x.relative_to(p).as_posix()):
            if f.is_file() and not f.is_symlink() and "__pycache__" not in f.parts and ".git" not in f.parts:
                rel = f.relative_to(p).as_posix().encode("utf-8")
                hasher.update(len(rel).to_bytes(4, "big"))
                hasher.update(rel)
    except OSError:
        pass
    return hasher.hexdigest()


def _hash_content(p: Path) -> str:
    import hashlib
    CONTENT_EXTENSIONS = {
        ".py", ".sh", ".js", ".ts",
        ".md", ".yaml", ".yml", ".json", ".toml",
        ".cfg", ".ini", ".txt"
    }
    hasher = hashlib.sha256()
    hasher.update(b"faro-content-v2\x00")
    try:
        for f in sorted(p.rglob("*"), key=lambda x: x.relative_to(p).as_posix()):
            if (f.is_file() and not f.is_symlink() and f.suffix in CONTENT_EXTENSIONS
                    and "__pycache__" not in f.parts and ".git" not in f.parts):
                try:
                    data = f.read_bytes()
                    rel = f.relative_to(p).as_posix().encode("utf-8")
                    hasher.update(len(rel).to_bytes(4, "big"))
                    hasher.update(rel)
                    hasher.update(len(data).to_bytes(8, "big"))
                    hasher.update(data)
                except OSError:
                    pass
    except OSError:
        pass
    return hasher.hexdigest()
