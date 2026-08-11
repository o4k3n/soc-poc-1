#!/usr/bin/env python3
"""Run one full investigation against the fixtures.

    make demo            # real vLLM endpoints (preflighted first)
    make demo-offline    # stub backend, no GPU

Starts nothing heavy: the serving layer is expected to be up already (`make up`).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from soc_poc.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
