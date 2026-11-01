"""Platform adapters. Import ``detect_platform`` from here."""

from .base import (
    ANDROID_CAPS,
    DESKTOP_CAPS,
    IOS_CAPS,
    BaseDirs,
    Capability,
    Platform,
    detect_platform,
)

__all__ = [
    "ANDROID_CAPS",
    "DESKTOP_CAPS",
    "IOS_CAPS",
    "BaseDirs",
    "Capability",
    "Platform",
    "detect_platform",
]
