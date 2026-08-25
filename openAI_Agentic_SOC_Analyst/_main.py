"""
_main.py - Compatibility launcher for the Agentic SOC Analyst.

The primary entrypoint is `start_button.py`. This file exists so legacy
instructions that call `python3 _main.py` keep working.
"""

from __future__ import annotations

import runpy


def main() -> None:
    runpy.run_module("start_button", run_name="__main__")


if __name__ == "__main__":
    main()

