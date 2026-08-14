#!/usr/bin/env python3
"""Investigate an alert against a folder of logs.

    ./analyze.py cases/my-case          # real endpoints (preflighted first)
    ./analyze.py cases/my-case --stub    # offline, no GPU
    ./analyze.py --init cases/new-case   # scaffold an empty case folder

A case folder is:

    <case>/
        alert.json      the alert an external detector already raised
        logs/           your raw logs, any text format
        patterns/       optional; hand-written summaries override the generated ones

Assumes the serving layer is already up (`make up`, `make health`). Stop a run in
progress with ./abort.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent

# Re-exec under the project venv if we were started with a bare `./analyze.py`. The
# dependencies live in .venv, and "ModuleNotFoundError: pydantic" is a useless first
# impression for a tool whose whole point is being easy to start.
#
# The check is sys.prefix, not the interpreter path: a venv's bin/python symlinks to the
# system interpreter, so comparing resolved executables says "already there" when we are
# not.
_VENV = _ROOT / ".venv"
_VENV_PY = _VENV / "bin" / "python"
if _VENV_PY.exists() and Path(sys.prefix) != _VENV:
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(_ROOT / "src"))

from soc_poc.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
