"""v0.6 tests: policy-driven generic discovery."""

import json
import tempfile
import subprocess
import sys
from pathlib import Path


FARO_CLI = [sys.executable, "-m", "faro.cli"]


def _run_cli(args, cwd=None, home=None):
    faro_home = str(Path(home)) if home else str(Path(tempfile.mkdtemp()))
    env = {"PYTHONPATH": "src", "FARO_HOME": faro_home}
    result = subprocess.run(
        FARO_CLI + args,
        capture_output=True, text=True, timeout=15,
        cwd=cwd, env={**__import__("os").environ, **env},
    )
    return result


# ============================================================
# Policy marker discovery
# ============================================================

def test_policy_marker_discovery():
    """Policy with marker should discover directories containing matching files."""
    td = Path(tempfile.mkdtemp())
    # Create asset structure
    agents = td / "agents"
    agents.mkdir()
    (agents / "reviewer.md").write_text("# Reviewer agent\n")
    (agents / "README.txt").write_text("ignore\n")

    # Create policy
    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test-policy
discovery:
  generic:
    - path: agents/
      marker: "*.md"
      kind: agent_prompt
""")

    r = _run_cli(["scan", "--policy", str(policy), "--json"], cwd=str(td))
    data = json.loads(r.stdout)
    assert len(data) >= 1, f"No results: {data}"
    result = data[0]
    assert result["type"] == "generic"
    assert result["policy"] == "test-policy"


def test_policy_marker_subdirectory_discovery():
    """Marker should discover matching dirs in subdirectories."""
    td = Path(tempfile.mkdtemp())
    agents = td / "agents"
    (agents / "finance").mkdir(parents=True)
    (agents / "finance" / "reviewer.md").write_text("# Finance\n")
    (agents / "eng").mkdir(parents=True)
    (agents / "eng" / "reviewer.md").write_text("# Eng\n")

    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test
discovery:
  generic:
    - path: agents/
      marker: "*.md"
      kind: agent_prompt
""")

    r = _run_cli(["scan", "--policy", str(policy), "--json"], cwd=str(td))
    data = json.loads(r.stdout)
    assert len(data) >= 2, f"Expected 2 subdirs: {data}"
    types = {d["type"] for d in data}
    assert types == {"generic"}


def test_explicit_dirs():
    """faro scan --dirs should scan directories as generic assets."""
    td = Path(tempfile.mkdtemp())
    d1 = td / "my-agents"
    d1.mkdir()
    (d1 / "README.md").write_text("# Agents\n")
    d2 = td / "my-hooks"
    d2.mkdir()
    (d2 / "script.py").write_text("print(1)\n")

    r = _run_cli(["scan", "--dirs", f"{d1},{d2}", "--json"], cwd=str(td))
    data = json.loads(r.stdout)
    assert len(data) == 2
    for d in data:
        assert d["type"] == "generic"


def test_missing_configured_path():
    """Policy path that doesn't exist should produce error result, not crash."""
    td = Path(tempfile.mkdtemp())
    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test
discovery:
  generic:
    - path: does-not-exist/
      marker: "*.md"
""")

    r = _run_cli(["scan", "--policy", str(policy), "--json"], cwd=str(td))
    data = json.loads(r.stdout)
    assert len(data) >= 1
    assert data[0]["risk_level"] == "error"


def test_symlink_generic_dir_blocked():
    """Symlink generic dir should be reported as error/critical, not scan target."""
    td = Path(tempfile.mkdtemp())
    real_target = td / "external-agent"
    real_target.mkdir()
    (real_target / "prompt.md").write_text("# External\n")
    agents = td / "agents"
    agents.mkdir()
    symlink = agents / "link"
    symlink.symlink_to(real_target.resolve())

    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test
discovery:
  generic:
    - path: agents/
      marker: "*"
""")

    r = _run_cli(["scan", "--policy", str(policy), "--json"], cwd=str(td))
    data = json.loads(r.stdout)
    # Should find the symlink dir as critical/error
    has_error = any(d["risk_level"] in ("critical", "error") for d in data)
    assert has_error, f"No error result for symlink: {data}"


def test_no_recurse_into_symlink_target():
    """Discovery should NOT follow symlink dirs into their targets."""
    td = Path(tempfile.mkdtemp())
    ext = Path(tempfile.mkdtemp())  # external tree
    (ext / "a").mkdir(parents=True)
    (ext / "a" / "reviewer.md").write_text("# A\n")
    agents = td / "agents-dir"
    agents.mkdir()
    symlink = agents / "linked-category"
    symlink.symlink_to(ext.resolve())

    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test
discovery:
  generic:
    - path: agents-dir/
      marker: "*.md"
""")

    r = _run_cli(["scan", "--policy", str(policy), "--json"], cwd=str(td))
    data = json.loads(r.stdout)
    # Should report linked-category as error (symlink), not a/
    names = [d["name"] for d in data]
    assert "linked-category" in names
    assert "a" not in names, f"Should not recurse into symlink target: {data}"


def test_invalid_discovery_config_errors():
    """Invalid discovery configs should exit 2."""
    td = Path(tempfile.mkdtemp())

    # generic is not a list
    p1 = td / "bad1.yaml"
    p1.write_text("version: 1\ndiscovery:\n  generic: not-a-list\n")
    r = _run_cli(["scan", "--policy", str(p1)], cwd=str(td))
    assert r.returncode == 2, f"Expected exit 2, got {r.returncode}"

    # missing path
    p2 = td / "bad2.yaml"
    p2.write_text("version: 1\ndiscovery:\n  generic:\n    - marker: '*.md'\n")
    r2 = _run_cli(["scan", "--policy", str(p2)], cwd=str(td))
    assert r2.returncode == 2, f"Expected exit 2, got {r2.returncode}"

    # marker is not string
    p3 = td / "bad3.yaml"
    p3.write_text("version: 1\ndiscovery:\n  generic:\n    - path: ok/\n      marker: 123\n")
    r3 = _run_cli(["scan", "--policy", str(p3)], cwd=str(td))
    assert r3.returncode == 2, f"Expected exit 2, got {r3.returncode}"

    # discovery is a string, not a mapping
    p4 = td / "bad4.yaml"
    p4.write_text("version: 1\ndiscovery: string\n")
    r4 = _run_cli(["scan", "--policy", str(p4)], cwd=str(td))
    assert r4.returncode == 2, f"Expected exit 2 for discovery-as-string, got {r4.returncode}"


def test_no_marker_match_no_fallback():
    """Marker with no matching files should produce no assets (not fallback to root)."""
    td = Path(tempfile.mkdtemp())
    agents = td / "agents"
    agents.mkdir()
    (agents / "README.txt").write_text("no markdown here\n")
    (agents / "config.json").write_text("{}\n")

    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test
discovery:
  generic:
    - path: agents/
      marker: "*.md"
""")

    r = _run_cli(["scan", "--policy", str(policy), "--json"], cwd=str(td))
    # Should produce 0 results — scanning the root dir is NOT a fallback
    data = json.loads(r.stdout)
    assert data == [], f"Expected empty results, got {data}"
    assert r.returncode == 0


def test_root_like_paths_rejected():
    """Root-like paths (. / ~) should exit 2."""
    td = Path(tempfile.mkdtemp())

    for bad_path in [".", "~/"]:
        p = td / f"bad-root-{bad_path.replace('/', '-')}.yaml"
        p.write_text(f"version: 1\ndiscovery:\n  generic:\n    - path: {bad_path}\n      marker: '*.md'\n")
        r = _run_cli(["scan", "--policy", str(p)], cwd=str(td))
        assert r.returncode == 2, f"Expected exit 2 for path={bad_path!r}, got {r.returncode}"

    # path that resolves to policy base dir (e.g. ".")
    p2 = td / "bad-resolves-to-base.yaml"
    agents_sub = td / "agents"
    agents_sub.mkdir(exist_ok=True)
    p2.write_text("version: 1\ndiscovery:\n  generic:\n    - path: ../\n      marker: '*.md'\n")
    r2 = _run_cli(["scan", "--policy", str(p2)], cwd=str(agents_sub))
    assert r2.returncode == 2, f"Expected exit 2 for base-dir-resolving path, got {r2.returncode}"


def test_report_with_policy_discovery():
    """faro report --policy should use policy discovery."""
    td = Path(tempfile.mkdtemp())
    agents = td / "agents"
    agents.mkdir()
    (agents / "reviewer.md").write_text("# Reviewer\nBash(python3 *)\n")

    policy = td / "policy.yaml"
    policy.write_text("""
version: 1
name: test
discovery:
  generic:
    - path: agents/
      marker: "*.md"
""")

    r = _run_cli(["report", "--policy", str(policy), "--format", "json"], cwd=str(td))
    data = json.loads(r.stdout)
    assert data["summary"]["assets_scanned"] >= 1
