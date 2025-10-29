"""Compatibility layer for color output.

Tries to import `colorama`; if unavailable (e.g., offline env),
provides no-op fallbacks so existing code keeps working.
"""

from __future__ import annotations

try:
    from colorama import Fore as _Fore, Style as _Style, init as _init
except ModuleNotFoundError:  # running without colorama installed
    class _ColorFallback:
        def __getattr__(self, _name: str) -> str:
            return ""

    def _init(*_args, **_kwargs) -> None:
        return None

    _Fore = _ColorFallback()
    _Style = _ColorFallback()


def init(*args, **kwargs):
    return _init(*args, **kwargs)


Fore = _Fore
Style = _Style

__all__ = ["Fore", "Style", "init"]
