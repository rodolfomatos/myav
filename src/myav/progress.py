"""Visual progress bar for long scans.

Renders a block-style bar (``████████░░░░ 50%``) to stderr only when the stream is a
TTY. When piped, redirected, or running under --json/--quiet, nothing is emitted so
logs and machine-readable output stay clean.

Pure standard library — no tqdm/rich dependency.
"""

from __future__ import annotations

import shutil
import sys
import time

FILLED = "█"
EMPTY = "░"


def _is_tty(stream) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, OSError):
        return False


def _term_width(default: int = 80) -> int:
    try:
        return shutil.get_terminal_size(fallback=(default, 20)).columns
    except (OSError, ValueError):
        return default


class ProgressBar:
    """A simple stderr progress bar.

    Usage::

        bar = ProgressBar(total=100, stream=sys.stderr)
        for i in range(100):
            ...
            bar.update(i + 1, label="current file")
        bar.close()
    """

    def __init__(
        self,
        total: int,
        stream=None,
        width: int = 0,
        enabled: bool = True,
        tty: bool | None = None,
    ) -> None:
        self.stream = stream or sys.stderr
        self.enabled = enabled and (tty if tty is not None else _is_tty(self.stream))
        self.total = max(total, 0)
        self.width = width or _term_width()
        self.started = time.monotonic()
        self.last_line_len = 0
        self._closed = False

    # ------------------------------------------------------------------ render

    def _render(self, current: int, label: str = "") -> None:
        if not self.enabled or self._closed:
            return
        total = self.total
        pct = (current / total * 100) if total else 0.0
        filled = int(self.width * current / total) if total else 0
        bar = FILLED * filled + EMPTY * (self.width - filled)
        elapsed = time.monotonic() - self.started
        rate = current / elapsed if elapsed > 0 else 0.0
        line = (
            f"\r{bar} {pct:5.1f}% ({current}/{total}) "
            f"{rate:4.1f} files/s {elapsed:5.1f}s  {label}"
        )
        # Pad to clear any leftover characters from a longer previous line.
        line = line + " " * max(0, self.last_line_len - len(line))
        self.last_line_len = len(line)
        self.stream.write(line)
        self.stream.flush()

    # ------------------------------------------------------------------ lifecycle

    def update(self, current: int, label: str = "") -> None:
        self._render(current, label)

    def close(self) -> None:
        if self.enabled and not self._closed:
            self.stream.write("\n")
            self.stream.flush()
        self._closed = True


def make_progress_bar(
    total: int,
    *,
    stream=None,
    json_output: bool = False,
    quiet: bool = False,
) -> ProgressBar | None:
    """Return a :class:`ProgressBar` when output should be shown, else ``None``."""
    if json_output or quiet:
        return None
    return ProgressBar(total, stream=stream)
