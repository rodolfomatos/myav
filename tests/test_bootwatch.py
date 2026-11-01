"""Startup inventory parsing and baseline diffing. Read-only, never disables anything."""

from __future__ import annotations

from pathlib import Path

from myav import bootwatch
from myav.platforms import detect_platform


def test_entry_key_is_stable_and_case_insensitive() -> None:
    assert bootwatch.entry_key("App", "C:\\app.exe") == bootwatch.entry_key(" app ", "C:\\app.exe")
    assert bootwatch.entry_key("A", "x") != bootwatch.entry_key("B", "x")


def test_parse_cim_json_dict_and_empty() -> None:
    assert bootwatch.parse_cim_json("") == []
    assert bootwatch.parse_cim_json("not json") == []
    payload = '{"Name": "Updater", "Command": "C:\\\\u.exe", "Location": "Startup"}'
    entries = bootwatch.parse_cim_json(payload)
    assert len(entries) == 1
    assert entries[0].name == "Updater"
    assert entries[0].location == "Startup"


def test_parse_cim_json_list_and_skips_empty() -> None:
    payload = (
        '[{"Name": "A", "Command": "a.exe"}, '
        '{"Name": "", "Command": ""}, '
        '{"Command": "only-command.exe"}]'
    )
    entries = bootwatch.parse_cim_json(payload)
    assert [entry.name for entry in entries] == ["A", "only-command.exe"]


def test_parse_reg_output() -> None:
    text = (
        "HKEY_CURRENT_USER\\...\\Run\r\n"
        "    One    REG_SZ    C:\\one.exe\r\n"
        "    Two    REG_EXPAND_SZ    C:\\two.exe\r\n"
        "not a value\r\n"
        "    Bad\r\n"
    )
    entries = bootwatch.parse_reg_output(text, "HKCU\\Run")
    assert len(entries) == 2
    assert entries[0].name == "One"
    assert entries[0].command == "C:\\one.exe"
    assert entries[0].location == "HKCU\\Run"


def test_parse_desktop_file(tmp_path: Path) -> None:
    path = tmp_path / "app.desktop"
    path.write_text("[Desktop Entry]\nName=App\nExec=/usr/bin/app %U\n")
    entry = bootwatch.parse_desktop_file(path)
    assert entry is not None
    assert entry.name == "App"
    assert entry.command == "/usr/bin/app %U"


def test_parse_desktop_file_hidden_and_empty(tmp_path: Path) -> None:
    hidden = tmp_path / "hidden.desktop"
    hidden.write_text("[Desktop Entry]\nName=Hidden\nExec=x\nHidden=true\n")
    assert bootwatch.parse_desktop_file(hidden) is None

    empty = tmp_path / "empty.desktop"
    empty.write_text("nonsense")
    assert bootwatch.parse_desktop_file(empty) is None

    assert bootwatch.parse_desktop_file(tmp_path / "missing.desktop") is None


def test_linux_autostart(home: Path) -> None:
    directory = home / ".config" / "autostart"
    directory.mkdir(parents=True)
    (directory / "a.desktop").write_text("[Desktop Entry]\nName=A\nExec=a\n")
    entries = bootwatch.linux_autostart(home)
    assert any(entry.name == "A" for entry in entries)


def test_collect_linux(home: Path) -> None:
    directory = home / ".config" / "autostart"
    directory.mkdir(parents=True)
    (directory / "a.desktop").write_text("[Desktop Entry]\nName=A\nExec=a\n")
    linux = detect_platform(home=home, env={"MYAV_PLATFORM": "linux"})
    entries, notes = bootwatch.collect(linux, home=home)
    assert any(entry.name == "A" for entry in entries)
    assert notes == []


def test_collect_wsl_without_windows_binaries(home: Path, monkeypatch) -> None:
    wsl = detect_platform(home=home, env={"MYAV_PLATFORM": "wsl"})
    monkeypatch.setattr(
        bootwatch, "find_windows_binaries", lambda: {"powershell": None, "reg": None}
    )
    entries, notes = bootwatch.collect(wsl, home=home)
    assert "PowerShell not reachable — Windows startup entries unavailable" in notes
    assert "reg.exe not reachable — registry Run keys unavailable" in notes


def test_collect_wsl_with_fake_windows_binaries(home: Path, monkeypatch) -> None:
    wsl = detect_platform(home=home, env={"MYAV_PLATFORM": "wsl"})
    monkeypatch.setattr(
        bootwatch, "find_windows_binaries", lambda: {"powershell": "ps", "reg": "reg"}
    )

    def fake_run(argv, timeout=30):
        if argv[0] == "ps":
            return '[{"Name": "Win", "Command": "w.exe", "Location": "Startup"}]'
        return "    Run    REG_SZ    r.exe\n"

    monkeypatch.setattr(bootwatch, "_run", fake_run)
    entries, notes = bootwatch.collect(wsl, home=home)
    names = {entry.name for entry in entries}
    assert "Win" in names
    assert "Run" in names
    assert notes == []


def test_collect_wsl_empty_powershell_note(home: Path, monkeypatch) -> None:
    wsl = detect_platform(home=home, env={"MYAV_PLATFORM": "wsl"})
    monkeypatch.setattr(
        bootwatch, "find_windows_binaries", lambda: {"powershell": "ps", "reg": "reg"}
    )
    monkeypatch.setattr(bootwatch, "_run", lambda *a, **k: "")
    _entries, notes = bootwatch.collect(wsl, home=home)
    assert "PowerShell returned no startup data" in notes


def test_collect_macos_note(tmp_path: Path, monkeypatch) -> None:
    mac = detect_platform(env={"MYAV_PLATFORM": "macos"})
    monkeypatch.setattr(bootwatch, "linux_autostart", lambda home=None: [])
    entries, notes = bootwatch.collect(mac, home=tmp_path)
    assert entries == []
    assert any("Full Disk Access" in note for note in notes)


def test_check_first_run_and_new_entry(home: Path, state) -> None:
    linux = detect_platform(home=home, env={"MYAV_PLATFORM": "linux"})
    directory = home / ".config" / "autostart"
    directory.mkdir(parents=True)
    (directory / "a.desktop").write_text("[Desktop Entry]\nName=A\nExec=a\n")

    first = bootwatch.check(state, linux, home=home)
    assert first["first_run"] is True
    # On the first run everything is *stored* as the baseline; the CLI tells the user
    # "nothing is flagged yet" instead of treating it as an alert.
    assert first["entries"] >= 1
    assert any(entry["name"] == "A" for entry in first["new"])

    (directory / "b.desktop").write_text("[Desktop Entry]\nName=B\nExec=b\n")
    second = bootwatch.check(state, linux, home=home)
    assert second["first_run"] is False
    assert [entry["name"] for entry in second["new"]] == ["B"]


def test_check_removed_entry(home: Path, state) -> None:
    linux = detect_platform(home=home, env={"MYAV_PLATFORM": "linux"})
    directory = home / ".config" / "autostart"
    directory.mkdir(parents=True)
    file = directory / "a.desktop"
    file.write_text("[Desktop Entry]\nName=A\nExec=a\n")
    bootwatch.check(state, linux, home=home)
    file.unlink()
    result = bootwatch.check(state, linux, home=home)
    assert result["removed"]


def test_find_windows_binaries_returns_keys() -> None:
    result = bootwatch.find_windows_binaries()
    assert set(result) == {"powershell", "reg"}
