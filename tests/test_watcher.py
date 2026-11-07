"""Write watcher: ignore rules, settle buffer, queue and a once-mode run.

The real inotify observer is replaced with a fake so the tests never depend on kernel
behaviour, but the parts that matter — debounce, dedupe, queue overflow — are real code.
"""

from __future__ import annotations

from pathlib import Path

from conftest import StubClam, make_engines

from myav.engine import CLEAN, MALICIOUS
from myav.watcher import SettleBuffer, Watcher, _Handler, should_ignore


class FakeEvent:
    def __init__(self, src_path: str, is_directory: bool = False, dest_path: str | None = None):
        self.src_path = src_path
        self.dest_path = dest_path
        self.is_directory = is_directory


class FakeObserver:
    def __init__(self) -> None:
        self.daemon = False
        self.started = False
        self.stopped = False
        self.handler = None
        self.path = None

    def schedule(self, handler, path, recursive=False):
        self.handler = handler
        self.path = path

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def join(self, timeout=None):
        pass


def test_should_ignore(paths, platform) -> None:
    assert should_ignore(paths.quarantine_dir / "x.bin", paths, platform)
    assert should_ignore(paths.state_dir / "state.db", paths, platform)
    assert should_ignore(paths.cache_dir / "x", paths, platform)
    assert should_ignore(Path("/home/u/Downloads/.myav-tmp"), paths, platform)
    assert not should_ignore(Path("/home/u/Downloads/report.pdf"), paths, platform)


def test_should_ignore_wsl_windows_and_internal(tmp_path: Path) -> None:
    from myav.platforms import detect_platform

    wsl = detect_platform(home=tmp_path, env={"MYAV_PLATFORM": "wsl"})
    from myav.paths import default_paths

    wsl_paths = default_paths(home=tmp_path, platform=wsl)
    assert should_ignore(Path("/mnt/c/Users/u/file.exe"), wsl_paths, wsl)
    assert should_ignore(Path("/mnt/wsl/docker/x"), wsl_paths, wsl)
    assert not should_ignore(Path("/mnt/d/usb/file.bin"), wsl_paths, wsl)


def test_settle_buffer_waits_for_quiet_period() -> None:
    clock = {"t": 100.0}
    buffer = SettleBuffer(settle_seconds=2.0, clock=lambda: clock["t"])
    buffer.add(Path("/tmp/a"))

    assert buffer.pending() == 1
    assert buffer.due() == []

    clock["t"] = 102.0
    assert buffer.due() == [Path("/tmp/a")]
    assert buffer.pending() == 0


def test_settle_buffer_resets_timer_on_new_write() -> None:
    clock = {"t": 0.0}
    buffer = SettleBuffer(settle_seconds=2.0, clock=lambda: clock["t"])
    buffer.add(Path("/tmp/a"))
    clock["t"] = 1.5
    buffer.add(Path("/tmp/a"))
    clock["t"] = 3.0
    assert buffer.due() == []
    clock["t"] = 3.6
    assert buffer.due() == [Path("/tmp/a")]


def test_handler_ignores_directories_and_ignored_paths(paths, platform) -> None:
    buffer = SettleBuffer(settle_seconds=1.0)
    handler = _Handler(buffer, paths, platform)

    handler.on_created(FakeEvent("/tmp/dir", is_directory=True))
    handler.on_created(FakeEvent(str(paths.state_dir / "x")))
    handler.on_created(FakeEvent("/home/u/Downloads/ok.txt"))
    handler.on_modified(FakeEvent("/home/u/Downloads/ok2.txt"))
    handler.on_moved(FakeEvent("/home/u/Downloads/old", dest_path="/home/u/Downloads/new.txt"))

    assert buffer.pending() == 3


def test_watch_root_refuses_bad_roots(
    config, paths, state, platform, tmp_path, monkeypatch
) -> None:
    engines = make_engines(platform)
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    assert watcher.watch_root(tmp_path / "missing") is False
    assert watcher.watch_root(paths.state_dir) is False

    root = tmp_path / "watched"
    root.mkdir()
    assert watcher.watch_root(root) is True
    assert watcher.watch_root(root) is False
    assert watcher.stats.roots == [root]


def test_enqueue_counts_drops(config, paths, state, platform) -> None:
    engines = make_engines(platform)
    watcher = Watcher(config, paths, state, engines, platform)
    watcher.queue = __import__("queue").Queue(maxsize=1)

    watcher._enqueue(Path("/tmp/a"))
    watcher._enqueue(Path("/tmp/b"))
    assert watcher.stats.queued == 1
    assert watcher.stats.dropped == 1


def test_run_once_scans_existing_files(
    config, paths, state, platform, tmp_path, monkeypatch
) -> None:
    config.watcher.watch_dirs = [tmp_path / "watched"]
    config.watcher.watch_removable = False
    config.watcher.workers = 2
    (tmp_path / "watched").mkdir()
    (tmp_path / "watched" / "one.txt").write_text("hello")
    (tmp_path / "watched" / "two.txt").write_text("world")

    engines = make_engines(platform, clam=StubClam(CLEAN))
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    stats = watcher.run(once=True)
    assert stats.roots == [tmp_path / "watched"]
    assert stats.scanned == 2
    assert stats.errors == 0
    assert {outcome.path.name for outcome in stats.outcomes} == {"one.txt", "two.txt"}


def test_run_once_dedupes_identical_content(
    config, paths, state, platform, tmp_path, monkeypatch
) -> None:
    config.watcher.watch_dirs = [tmp_path / "watched"]
    config.watcher.watch_removable = False
    (tmp_path / "watched").mkdir()
    (tmp_path / "watched" / "a.txt").write_text("same")
    (tmp_path / "watched" / "b.txt").write_text("same")

    engines = make_engines(platform, clam=StubClam(CLEAN))
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    stats = watcher.run(once=True)
    assert stats.scanned == 1


def test_run_once_quarantines_malicious(
    config, paths, state, platform, tmp_path, monkeypatch
) -> None:
    config.watcher.watch_dirs = [tmp_path / "watched"]
    config.watcher.watch_removable = False
    (tmp_path / "watched").mkdir()
    target = tmp_path / "watched" / "bad.bin"
    target.write_text("malware")

    engines = make_engines(platform, clam=StubClam(MALICIOUS, "Test.Sig"))
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    stats = watcher.run(once=True)
    assert stats.scanned == 1
    assert stats.outcomes[0].quarantined is not None
    assert not target.exists()


def test_watcher_blocks_malicious_on_block_on_malicious(
    config, paths, state, platform, tmp_path, monkeypatch
) -> None:
    config.watcher.watch_dirs = [tmp_path / "watched"]
    config.watcher.watch_removable = False
    config.watcher.block_on_malicious = True
    (tmp_path / "watched").mkdir()
    target = tmp_path / "watched" / "bad.bin"
    target.write_text("malware")

    engines = make_engines(platform, clam=StubClam(MALICIOUS, "Test.Sig"))
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    stats = watcher.run(once=True)
    assert stats.scanned == 1
    assert stats.blocked == 1
    assert stats.outcomes[0].quarantined is not None
    # Quarantine removed the payload; blocking is satisfied by that removal.
    assert not target.exists()


def test_watcher_does_not_block_without_flag(
    config, paths, state, platform, tmp_path, monkeypatch
) -> None:
    config.watcher.watch_dirs = [tmp_path / "watched"]
    config.watcher.watch_removable = False
    config.watcher.block_on_malicious = False
    (tmp_path / "watched").mkdir()
    target = tmp_path / "watched" / "bad.bin"
    target.write_text("malware")

    engines = make_engines(platform, clam=StubClam(MALICIOUS, "Test.Sig"))
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    stats = watcher.run(once=True)
    assert stats.scanned == 1
    assert stats.blocked == 0
    assert stats.outcomes[0].quarantined is not None
    assert not target.exists()


def test_create_dirs_in_run(config, paths, state, platform, tmp_path, monkeypatch) -> None:
    missing = tmp_path / "created" / "Downloads"
    config.watcher.watch_dirs = [missing]
    config.watcher.watch_removable = False
    engines = make_engines(platform)
    watcher = Watcher(config, paths, state, engines, platform)
    monkeypatch.setattr(watcher, "_obs", FakeObserver)

    watcher.run(once=True, create_dirs=True)
    assert missing.is_dir()


def test_stop_sets_event(config, paths, state, platform) -> None:
    engines = make_engines(platform)
    watcher = Watcher(config, paths, state, engines, platform)
    watcher.stop()
    assert watcher._stop.is_set()
