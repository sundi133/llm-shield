"""In-memory state store for guardrails that need to track state (e.g., rate limiting)."""

import threading
import time
from typing import Any, Optional


class StateStore:
    """Thread-safe in-memory key-value store with TTL and sliding-window support."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        self._expiry: dict[str, float] = {}
        self._windows: dict[str, list[float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get a value by key. Returns None if expired or missing."""
        with self._lock:
            if key in self._expiry and time.monotonic() > self._expiry[key]:
                del self._data[key]
                del self._expiry[key]
                return None
            return self._data.get(key)

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set a value with an optional TTL in seconds."""
        with self._lock:
            self._data[key] = value
            if ttl is not None:
                self._expiry[key] = time.monotonic() + ttl
            elif key in self._expiry:
                del self._expiry[key]

    def increment(self, key: str, window_seconds: float) -> int:
        """Record a timestamp for the given key and return the count within the sliding window.

        Args:
            key: Identifier (e.g., client_id or agent_key).
            window_seconds: Size of the sliding window in seconds.

        Returns:
            Current number of events within the window (including this one).
        """
        now = time.monotonic()
        with self._lock:
            if key not in self._windows:
                self._windows[key] = []
            timestamps = self._windows[key]
            # Prune expired entries
            cutoff = now - window_seconds
            self._windows[key] = [t for t in timestamps if t > cutoff]
            self._windows[key].append(now)
            return len(self._windows[key])
