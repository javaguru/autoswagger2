# autoswagger2/utils/cache.py
import hashlib
import json
import math
import os
import tempfile
import threading
import time


def _normalize_ttl(ttl):
    """Return non-negative float TTL in seconds, or None to disable expiration."""
    if ttl is None:
        return None
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        return 3600.0
    val = float(ttl)
    if not math.isfinite(val):
        return 3600.0
    return max(0.0, val)


def _remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


_CACHE_IO_LOCK = threading.RLock()


class SpecCache:
    def __init__(self, cache_dir="~/.autoswagger2/cache", ttl=3600, enabled=True):
        self.cache_dir = os.path.expanduser(cache_dir)
        self.ttl = _normalize_ttl(ttl)
        self.enabled = bool(enabled)
        self._lock = _CACHE_IO_LOCK
        if self.enabled:
            os.makedirs(self.cache_dir, exist_ok=True)

    def _get_hash(self, url):
        return hashlib.sha256(url.encode('utf-8')).hexdigest()

    def _cache_path(self, url):
        return os.path.join(self.cache_dir, f"{self._get_hash(url)}.json")

    def get_cached_spec(self, url):
        """Avoids redundant requests by reading valid, non-expired specs from cache."""
        if not self.enabled:
            return None

        cache_path = self._cache_path(url)
        with self._lock:
            try:
                stat = os.stat(cache_path)
            except OSError:
                return None

            if self.ttl is not None:
                age = time.time() - stat.st_mtime
                if self.ttl <= 0.0 or age > self.ttl:
                    _remove_quietly(cache_path)
                    return None

            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                _remove_quietly(cache_path)
                return None
            except OSError:
                return None

            if not isinstance(data, dict):
                _remove_quietly(cache_path)
                return None

            return data

    def cache_spec(self, url, spec):
        """Atomically stores discovered specs in the cache when enabled."""
        if not self.enabled or not isinstance(spec, dict):
            return

        cache_path = self._cache_path(url)
        tmp_path = None
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                prefix=f".{self._get_hash(url)}.",
                suffix=".tmp",
                dir=self.cache_dir,
            )
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(spec, f)
            with self._lock:
                os.replace(tmp_path, cache_path)
            tmp_path = None
        except Exception:
            if tmp_path is not None:
                _remove_quietly(tmp_path)
