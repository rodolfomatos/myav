"""Progress bar tests."""

from __future__ import annotations

import io

from myav.progress import EMPTY, FILLED, ProgressBar, _is_tty, _term_width


def test_is_tty_returns_bool() -> None:
    assert isinstance(_is_tty(io.StringIO()), bool)


def test_term_width_returns_int() -> None:
    assert isinstance(_term_width(), int)
    assert _term_width() > 0


def test_progress_bar_renders_on_tty() -> None:
    stream = io.StringIO()
    bar = ProgressBar(total=10, stream=stream, tty=True)
    bar.update(5, label="scanning file.txt")
    bar.close()
    output = stream.getvalue()
    assert FILLED in output
    assert EMPTY in output
    assert "50.0%" in output
    assert "5/10" in output


def test_progress_bar_empty_when_not_tty() -> None:
    stream = io.StringIO()
    bar = ProgressBar(total=10, stream=stream, tty=False)
    bar.update(5, label="scanning file.txt")
    bar.close()
    assert stream.getvalue() == ""


def test_progress_bar_100_percent() -> None:
    stream = io.StringIO()
    bar = ProgressBar(total=4, stream=stream, tty=True)
    bar.update(4, label="done")
    bar.close()
    output = stream.getvalue()
    assert "100.0%" in output
    assert "4/4" in output


def test_progress_bar_zero_total() -> None:
    stream = io.StringIO()
    bar = ProgressBar(total=0, stream=stream, tty=True)
    bar.update(0, label="nothing")
    bar.close()
    output = stream.getvalue()
    assert "0/0" in output


def test_progress_bar_clear_longer_previous_line() -> None:
    stream = io.StringIO()
    bar = ProgressBar(total=100, stream=stream, tty=True, width=40)
    bar.update(50, label="a very long label that is longer than the next one")
    first = stream.getvalue()
    stream.truncate(0)
    stream.seek(0)
    bar.update(51, label="short")
    second = stream.getvalue()
    # The second line should be padded to clear the first line's residue.
    assert len(second) >= len(first)


def test_progress_bar_disabled_when_json() -> None:
    # json_output / quiet are handled at the CLI layer; here we just confirm
    # constructing with tty=False yields no output.
    stream = io.StringIO()
    bar = ProgressBar(total=10, stream=stream, tty=False)
    bar.update(3)
    bar.close()
    assert stream.getvalue() == ""


def test_block_characters() -> None:
    assert FILLED == "█"
    assert EMPTY == "░"
