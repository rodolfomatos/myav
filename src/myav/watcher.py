"""Write watcher: Downloads, Desktop and removable volumes.

inotify/FSEvents/ReadDirectoryChangesW via ``watchdog``. Detection is *after* the write
closes — myav is a detector, not a blocker (docs/THREAT_MODEL.md §A).

The interesting logic is extracted into pure helpers (``should_ignore``, ``SettleBuffer``)
so it can be tested without a filesystem event.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .config import Config
from .paths import Paths, discover_removable_mounts, is_within
from .pipeline import Engines, Outcome, scan_file
from .platforms import Platform
from .state import State


def should_ignore(path: Path, paths: Paths, platform: Platform) -> bool:
    """True for paths myav must never scan from the watcher."""
    if is_within(path, paths.quarantine_dir):
        return True
    if is_within(path, paths.state_dir) or is_within(path, paths.cache_dir):
        return True
    if path.name.startswith(".myav-"):
        return True
    if platform.is_wsl and is_within(path, Path("/mnt") / "c"):
        return True
    if platform.is_wsl and is_within(path, Path("/mnt") / "wsl"):
        return True
    return False


class SettleBuffer:
    """Hold file events until the file stops changing.

    A browser writes a download in many chunks; scanning the first chunk guarantees a
    partial read. We wait ``settle_seconds`` after the last event for that path.
    """

    def __init__(self, settle_seconds: float, clock=time.monotonic):
        self.settle_seconds = settle_seconds
        self._clock = clock
        self._last: dict[Path, float] = {}
        self._lock = threading.Lock()

    def add(self, path: Path) -> None:
        with self._lock:
            self._last[Path(path)] = self._clock()

    def due(self, now: float | None = None) -> list[Path]:
        now = self._clock() if now is None else now
        ready: list[Path] = []
        with self._lock:
            for path, last in list(self._last.items()):
                if now - last >= self.settle_seconds:
                    ready.append(path)
                    del self._last[path]
        return ready

    def pending(self) -> int:
        with self._lock:
            return len(self._last)


@dataclass
class WatcherStats:
    queued: int = 0
    dropped: int = 0
    scanned: int = 0
    errors: int = 0
    blocked: int = 0
    outcomes: list[Outcome] = field(default_factory=list)
    roots: list[Path] = field(default_factory=list)


class _Handler(FileSystemEventHandler):
    def __init__(self, settle: SettleBuffer, paths: Paths, platform: Platform):
        self.settle = settle
        self.paths = paths
        self.platform = platform

    def _consider(self, raw_path: str, is_directory: bool) -> None:
        if is_directory:
            return
        path = Path(raw_path)
        if should_ignore(path, self.paths, self.platform):
            return
        self.settle.add(path)

    def on_created(self, event):  # noqa: D102
        self._consider(event.src_path, event.is_directory)

    def on_modified(self, event):  # noqa: D102
        self._consider(event.src_path, event.is_directory)

    def on_moved(self, event):  # noqa: D102
        self._consider(event.dest_path, event.is_directory)


class Watcher:
    def __init__(
        self,
        config: Config,
        paths: Paths,
        state: State,
        engines: Engines,
        platform: Platform,
        block_on_malicious: bool | None = None,
    ):
        self.config = config
        self.paths = paths
        self.state = state
        self.engines = engines
        self.platform = platform
        self.block_on_malicious = bool(
            block_on_malicious if block_on_malicious is not None
            else self.config.watcher.block_on_malicious
        )
        self.settle = SettleBuffer(config.watcher.settle_seconds)
        self.queue: queue.Queue[Path] = queue.Queue(maxsize=config.watcher.queue_size)
        self.stats = WatcherStats()
        self._stop = threading.Event()
        self._observers: dict[Path, Observer] = {}
        self._known_hashes: set[str] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ watches

    def _obs(self) -> Observer:
        return Observer(timeout=1.0)

    def watch_root(self, root: Path) -> bool:
        root = Path(root)
        if root in self._observers or not root.is_dir():
            return False
        if should_ignore(root, self.paths, self.platform):
            return False
        observer = self._obs()
        observer.schedule(
            _Handler(self.settle, self.paths, self.platform), str(root), recursive=True
        )
        observer.daemon = True
        observer.start()
        self._observers[root] = observer
        self.stats.roots.append(root)
        return True

    def _mount_loop(self, interval: float = 5.0) -> None:
        while not self._stop.is_set():
            try:
                for mount in discover_removable_mounts():
                    self.watch_root(mount)
            except Exception:  # noqa: BLE001 - a mount poll must never kill the watcher
                pass
            self._stop.wait(interval)

    # -------------------------------------------------------------------- queue

    def _enqueue(self, path: Path) -> None:
        try:
            self.queue.put_nowait(path)
            self.stats.queued += 1
        except queue.Full:
            self.stats.dropped += 1

    def _dispatcher(self) -> None:
        while not self._stop.is_set():
            for path in self.settle.due():
                self._enqueue(path)
            self._stop.wait(0.2)
        for path in self.settle.due(now=float("inf")):
            self._enqueue(path)

    def _worker(self) -> None:
        while True:
            try:
                path = self.queue.get(timeout=0.5)
            except queue.Empty:
                if self._stop.is_set():
                    return
                continue
            try:
                outcome = scan_file(
                    path, self.config, self.paths, self.state, self.engines, kind="watch"
                )
                if outcome.sha256:
                    with self._lock:
                        if outcome.sha256 in self._known_hashes:
                            continue
                        self._known_hashes.add(outcome.sha256)
                with self._lock:
                    self.stats.scanned += 1
                    self.stats.outcomes.append(outcome)
                # Block malicious files if configured to do so. The file is
                # usually already removed by quarantine, so the outcome is
                # blocked either way; chmod only when it still exists.
                if (
                    self.block_on_malicious
                    and outcome.level == "MALICIOUS"
                    and not outcome.skipped
                ):
                    try:
                        if path.exists():
                            os.chmod(path, 0o000)
                    except OSError:
                        pass
                    with self._lock:
                        self.stats.blocked += 1
            except Exception:  # noqa: BLE001 - never die on one bad file
                self.stats.errors += 1
            finally:
                self.queue.task_done()

    # --------------------------------------------------------------------- run

    def run(self, once: bool = False, create_dirs: bool = False) -> WatcherStats:
        roots = list(self.config.watcher.watch_dirs)
        if self.config.watcher.watch_removable:
            roots.extend(discover_removable_mounts())
        for root in roots:
            if create_dirs:
                Path(root).mkdir(parents=True, exist_ok=True)
            self.watch_root(root)

        dispatcher = threading.Thread(target=self._dispatcher, daemon=True)
        dispatcher.start()
        workers = [
            threading.Thread(target=self._worker, daemon=True)
            for _ in range(max(1, self.config.watcher.workers))
        ]
        for worker in workers:
            worker.start()
        mount_thread = threading.Thread(target=self._mount_loop, daemon=True)
        mount_thread.start()

        if once:
            for root in list(self._observers):
                for path in _walk(root):
                    if not should_ignore(path, self.paths, self.platform):
                        self._enqueue(path)
            self._stop.set()
        else:
            try:
                while not self._stop.is_set():
                    self._stop.wait(1.0)
            except KeyboardInterrupt:
                self._stop.set()

        dispatcher.join(timeout=10)
        for worker in workers:
            worker.join(timeout=10)
        for observer in self._observers.values():
            observer.stop()
        for observer in self._observers.values():
            observer.join(timeout=5)
        return self.stats

    def stop(self) -> None:
        self._stop.set()


def _walk(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path
