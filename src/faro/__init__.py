"""faro — Hermes Skill/Plugin security pipeline."""

import os
from pathlib import Path

__version__ = "0.1.0"


def get_home() -> Path:
    """Resolve Hermes home dir. Use FARO_HOME env var if set, else Path.home()."""
    env = os.environ.get("FARO_HOME")
    return Path(env) if env else Path.home()
