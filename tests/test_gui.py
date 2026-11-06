"""GUI tests (research track).

These tests verify the GUI tooling only — no detection feature ships
as part of MYAV Core from this ticket.

Tests use a headless Tkinter root (withdrawn window) so they can run
without a display, if Tkinter is available.
"""

from __future__ import annotations

import pytest


def _import_tkinter():
    """Try to import tkinter; return None if unavailable."""
    try:
        import tkinter as tk  # noqa: F401
        return True
    except ImportError:
        return False


tkinter_available = _import_tkinter()


@pytest.mark.skipif(not tkinter_available, reason="Tkinter not available")
def test_gui_imports() -> None:
    """Verify the GUI module can be imported without Tkinter errors."""
    from myav.research.gui import MyavGUI  # noqa: F401


@pytest.mark.skipif(not tkinter_available, reason="Tkinter not available")
def test_myav_gui_creates_tabs() -> None:
    """Verify the GUI creates all expected tabs."""
    from myav.research.gui import MyavGUI

    app = MyavGUI()
    app.withdraw()  # Don't show during test

    tab_names = [app.notebook.tab(tab_id, "text") for tab_id in app.notebook.tabs()]
    assert "Scan" in tab_names
    assert "Quarantine" in tab_names
    assert "Reports" in tab_names
    assert "Config" in tab_names
    assert "Research" in tab_names

    app.destroy()


@pytest.mark.skipif(not tkinter_available, reason="Tkinter not available")
def test_myav_gui_scan_output_exists() -> None:
    """Verify the scan tab has an output text widget."""
    from myav.research.gui import MyavGUI

    app = MyavGUI()
    app.withdraw()

    assert app.scan_output is not None
    app.destroy()


@pytest.mark.skipif(not tkinter_available, reason="Tkinter not available")
def test_myav_gui_quarantine_tree_exists() -> None:
    """Verify the quarantine tab has a treeview."""
    from myav.research.gui import MyavGUI

    app = MyavGUI()
    app.withdraw()

    assert app.quarantine_tree is not None
    app.destroy()


@pytest.mark.skipif(not tkinter_available, reason="Tkinter not available")
def test_myav_gui_reports_list_exists() -> None:
    """Verify the reports tab has a listbox."""
    from myav.research.gui import MyavGUI

    app = MyavGUI()
    app.withdraw()

    assert app.reports_list is not None
    app.destroy()


@pytest.mark.skipif(not tkinter_available, reason="Tkinter not available")
def test_myav_gui_research_output_exists() -> None:
    """Verify the research tab has an output text widget."""
    from myav.research.gui import MyavGUI

    app = MyavGUI()
    app.withdraw()

    assert app.research_output is not None
    app.destroy()


def test_tkinter_available_check() -> None:
    """Verify whether Tkinter is available in this environment."""
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.destroy()
        assert True
    except Exception:
        pytest.skip("Tkinter not available in this environment")
