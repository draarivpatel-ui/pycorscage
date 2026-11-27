"""Allow ``python -m pycorscage`` to invoke the command-line auditor."""

from __future__ import annotations

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
