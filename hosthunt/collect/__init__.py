"""Live artefact collectors. Each returns a :class:`hosthunt.models.Bundle`."""
from __future__ import annotations

import platform

from ..models import Bundle


def collect_live(hash_files: bool = False, event_limit: int = 5000, quick: bool = False) -> Bundle:
    system = platform.system().lower()
    if system == "windows":
        from .windows import WindowsCollector
        return WindowsCollector(hash_files=hash_files, event_limit=event_limit, quick=quick).collect()
    if system in ("linux", "darwin"):
        from .linux import LinuxCollector
        return LinuxCollector(hash_files=hash_files, event_limit=event_limit, quick=quick).collect()
    raise RuntimeError(f"Unsupported platform: {system}")
