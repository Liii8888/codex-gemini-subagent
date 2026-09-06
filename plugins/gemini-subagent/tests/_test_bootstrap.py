"""Opt the test process and its Python children into mock runtime isolation.

Production entrypoints never import this module or add tests/support to their
module search path. Keeping injection here avoids a production environment
switch that can split the real provider's per-user authentication lock.
"""

import os
import sys
from pathlib import Path

support = str(Path(__file__).resolve().parent / "support")
if support not in sys.path:
    sys.path.insert(0, support)
python_paths = os.environ.get("PYTHONPATH", "").split(os.pathsep)
os.environ["PYTHONPATH"] = os.pathsep.join(
    [support] + [path for path in python_paths if path and path != support]
)

from gemini_test_isolation import install  # noqa: E402

install()
