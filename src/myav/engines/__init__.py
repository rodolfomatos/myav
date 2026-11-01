"""Engine adapters. Each one returns only :class:`myav.engine.EngineResult`."""

from .clamav import ClamAVEngine
from .virustotal import VirusTotalEngine
from .yara import YaraEngine

__all__ = ["ClamAVEngine", "VirusTotalEngine", "YaraEngine"]
