# autoswagger2/utils/rate_limiter.py
"""Thread-safe global rate limiter shared across HTTP clients in a scan."""

import math
import threading
import time

_REGISTRY_LOCK = threading.Lock()


def _parse_rate(raw_rate):
    """Return a finite positive float rate (requests/sec), or 0.0 if disabled."""
    if isinstance(raw_rate, bool) or not isinstance(raw_rate, (int, float)):
        return 0.0
    rate = float(raw_rate)
    if not math.isfinite(rate) or rate <= 0.0:
        return 0.0
    return rate


class RateLimiter:
    """Thread-safe pacing limiter enforcing a maximum request rate per second."""

    def __init__(self, rate_per_sec=0.0):
        self.rate = _parse_rate(rate_per_sec)
        self.interval = (1.0 / self.rate) if self.rate > 0.0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self):
        """Reserve the next request slot and sleep outside the lock if needed."""
        if self.interval <= 0.0:
            return 0.0

        with self._lock:
            now = time.monotonic()
            if now >= self._next_allowed:
                self._next_allowed = now + self.interval
                delay = 0.0
            else:
                delay = self._next_allowed - now
                self._next_allowed += self.interval

        if delay > 0.0:
            time.sleep(delay)
        return delay


_NOOP_LIMITER = RateLimiter(0.0)


def get_rate_limiter(args=None):
    """Return the shared RateLimiter attached to `args` (or a no-op limiter)."""
    if args is None:
        return _NOOP_LIMITER

    rate = _parse_rate(getattr(args, "rate", 0.0))
    if rate <= 0.0:
        return _NOOP_LIMITER

    with _REGISTRY_LOCK:
        existing = getattr(args, "_rate_limiter", None)
        if isinstance(existing, RateLimiter) and existing.rate == rate:
            return existing

        limiter = RateLimiter(rate)
        try:
            setattr(args, "_rate_limiter", limiter)
        except (AttributeError, TypeError):
            pass
        return limiter
