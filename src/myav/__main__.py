"""Allow ``python -m myav`` as an alias for the ``myav`` command."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":  # pragma: no cover - exercised by the launcher
    sys.exit(main())
