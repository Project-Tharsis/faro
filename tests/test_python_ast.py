"""Regression tests for Python AST scanner — patterns regex can't catch."""

import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faro.python_ast import scan_python_ast

TEST_CODE = {
    "from_subprocess_import_run": '''
from subprocess import run
run(["id"])
''',
    "subprocess_alias": '''
import subprocess as sp
sp.Popen("id", shell=True)
''',
    "from_subprocess_import_check_output": '''
from subprocess import check_output as co
co(["id"])
''',
    "os_system_import_alias": '''
from os import system
system("id")
''',
    "pickle_loads": '''
import pickle
pickle.loads(b"data")
''',
    "marshal_loads": '''
import marshal
marshal.loads(b"data")
''',
    "yaml_load_no_safeloader": '''
import yaml
yaml.load("key: value")
''',
    "ctypes_cdll": '''
import ctypes
ctypes.CDLL("x.so")
''',
    "ctypes_cdll_from_import": '''
from ctypes import CDLL
CDLL("x.so")
''',
    "dynamic_import": '''
mod = __import__("subprocess")
''',
    "importlib_import_module": '''
import importlib
importlib.import_module("subprocess")
''',
    "eval": '''
eval("1+1")
''',
    "exec": '''
exec("print('hi')")
''',
    "expanduser_ssh": '''
import os
os.path.expanduser("~/.ssh/id_rsa")
''',
    "open_config": '''
open("~/.hermes/config.yaml", "w")
''',
}


def _scan_code(code: str, filename: str = "test.py") -> list:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        f = root / filename
        f.write_text(code)
        return scan_python_ast(f, root)


def _findings_have_pattern(findings: list, pattern_id: str) -> bool:
    return any(f.pattern_id == pattern_id for f in findings)


def test_from_subprocess_import_run_is_detected():
    f = _scan_code(TEST_CODE["from_subprocess_import_run"])
    assert _findings_have_pattern(f, "danger-subprocess-ast"), \
        f"from subprocess import run not detected, got: {f}"


def test_subprocess_alias_is_detected():
    f = _scan_code(TEST_CODE["subprocess_alias"])
    assert _findings_have_pattern(f, "danger-subprocess-ast")


def test_os_system_import_alias_is_detected():
    f = _scan_code(TEST_CODE["os_system_import_alias"])
    assert _findings_have_pattern(f, "danger-os-ast"), \
        f"from os import system not detected, got: {f}"


def test_pickle_loads_is_detected():
    f = _scan_code(TEST_CODE["pickle_loads"])
    assert _findings_have_pattern(f, "danger-pickle-ast")


def test_marshal_loads_is_detected():
    f = _scan_code(TEST_CODE["marshal_loads"])
    assert _findings_have_pattern(f, "danger-marshal-ast")


def test_yaml_load_without_safe_loader_is_detected():
    f = _scan_code(TEST_CODE["yaml_load_no_safeloader"])
    assert _findings_have_pattern(f, "danger-yaml-load-ast")


def test_ctypes_cdll_is_detected():
    f = _scan_code(TEST_CODE["ctypes_cdll"])
    assert _findings_have_pattern(f, "danger-ctypes-ast")


def test_ctypes_cdll_from_import_is_detected():
    f = _scan_code(TEST_CODE["ctypes_cdll_from_import"])
    assert _findings_have_pattern(f, "danger-ctypes-ast")


def test_dynamic_import_is_detected():
    f = _scan_code(TEST_CODE["dynamic_import"])
    assert _findings_have_pattern(f, "danger-import-ast")


def test_importlib_is_detected():
    findings = _scan_code(TEST_CODE["importlib_import_module"])
    assert any(
        f.pattern_id in ("danger-importlib-ast", "danger-import-ast")
        for f in findings
    ), f"importlib.import_module not detected, got: {findings}"


def test_eval_is_detected():
    f = _scan_code(TEST_CODE["eval"])
    assert _findings_have_pattern(f, "danger-eval-ast")


def test_exec_is_detected():
    f = _scan_code(TEST_CODE["exec"])
    assert _findings_have_pattern(f, "danger-exec-ast")


def test_expanduser_ssh_is_detected():
    f = _scan_code(TEST_CODE["expanduser_ssh"])
    assert _findings_have_pattern(f, "cred-sensitive-path-ast"), \
        f"expanduser ~/.ssh not detected, got: {f}"


def test_open_config_is_detected():
    f = _scan_code(TEST_CODE["open_config"])
    assert _findings_have_pattern(f, "config-write-ast"), \
        f"open config.yaml not detected, got: {f}"


def test_clean_file_has_no_findings():
    code = '''
def hello():
    print("hello world")
'''
    f = _scan_code(code, filename="clean.py")
    assert len(f) == 0, f"Clean file should have no findings, got: {f}"


if __name__ == "__main__":
    tests = [
        ("from_subprocess_import_run", test_from_subprocess_import_run_is_detected),
        ("subprocess_alias", test_subprocess_alias_is_detected),
        ("os_system_import_alias", test_os_system_import_alias_is_detected),
        ("pickle_loads", test_pickle_loads_is_detected),
        ("marshal_loads", test_marshal_loads_is_detected),
        ("yaml_load_no_safeloader", test_yaml_load_without_safe_loader_is_detected),
        ("ctypes_cdll", test_ctypes_cdll_is_detected),
        ("ctypes_cdll_from_import", test_ctypes_cdll_from_import_is_detected),
        ("dynamic_import", test_dynamic_import_is_detected),
        ("importlib", test_importlib_is_detected),
        ("eval", test_eval_is_detected),
        ("exec", test_exec_is_detected),
        ("expanduser_ssh", test_expanduser_ssh_is_detected),
        ("open_config", test_open_config_is_detected),
        ("clean_file_no_findings", test_clean_file_has_no_findings),
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
