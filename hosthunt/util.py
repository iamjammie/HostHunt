"""Small helpers shared across the package."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def run(cmd: List[str], timeout: int = 60, text: bool = True) -> str:
    """Run a command, return stdout ("" on any failure)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=text, timeout=timeout,
                             errors="replace" if text else None)
        return res.stdout or ""
    except Exception:  # noqa: BLE001
        return ""


def which(binary: str) -> Optional[str]:
    from shutil import which as _w
    return _w(binary)


def sha256_file(path: str, max_bytes: int = 64 * 1024 * 1024) -> Optional[str]:
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:  # noqa: BLE001
        return None


def ts_from_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=0).isoformat()


def file_times(path: str) -> Dict[str, Any]:
    try:
        st = os.lstat(path)
        return {"mtime": ts_from_epoch(st.st_mtime), "ctime": ts_from_epoch(st.st_ctime),
                "atime": ts_from_epoch(st.st_atime), "size": st.st_size, "mode": oct(st.st_mode)}
    except Exception:  # noqa: BLE001
        return {}


def read_text(path: str, limit: int = 256 * 1024) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except Exception:  # noqa: BLE001
        return ""


_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M:%S %p", "%Y%m%d%H%M%S", "%Y-%m-%d",
)


def parse_ts(value: Any) -> Optional[datetime]:
    """Best-effort timestamp parser returning an aware UTC datetime (or None)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            v = float(value)
            if v > 1e12:
                v /= 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except Exception:  # noqa: BLE001
            return None
    s = str(value).strip()
    if not s or s.upper() in ("N/A", "NEVER", "NONE", "NULL"):
        return None
    # WMI datetime: 20261101091233.123456+000
    m = re.match(r"^(\d{14})\.\d+([+-]\d{3})$", s)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
            offset_min = int(m.group(2))
            from datetime import timedelta
            return (dt - timedelta(minutes=offset_min)).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    # .NET JSON date: /Date(1699000000000)/
    m = re.match(r"^/Date\((\d+)\)/$", s)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000.0, tz=timezone.utc)
    if re.match(r"^\d{9,13}(\.\d+)?$", s):
        return parse_ts(float(s))
    s2 = s.replace("Z", "+00:00") if s.endswith("Z") else s
    # Trim excessive fractional seconds (Windows gives 7 digits)
    s2 = re.sub(r"(\.\d{6})\d+", r"\1", s2)
    try:
        dt = datetime.fromisoformat(s2)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def norm_ts(value: Any) -> Optional[str]:
    dt = parse_ts(value)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat() if dt else None


def flatten_strings(obj: Any) -> Iterable[str]:
    """Yield every string value inside a nested dict/list (for IOC sweeps)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from flatten_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from flatten_strings(v)
    elif obj is not None:
        yield str(obj)


def lower(s: Any) -> str:
    return str(s or "").lower()


def basename_any(path: str) -> str:
    p = str(path or "").strip().strip('"')
    return re.split(r"[\\/]", p)[-1].lower() if p else ""
