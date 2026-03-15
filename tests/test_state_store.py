"""Tests for StateStore."""

import time
import pytest

from storage.state_store import StateStore


@pytest.fixture
def store():
    return StateStore()


def test_get_set(store):
    """Test basic get and set operations."""
    assert store.get("key1") is None
    store.set("key1", "value1")
    assert store.get("key1") == "value1"


def test_set_overwrite(store):
    """Test that set overwrites existing values."""
    store.set("key", "old")
    store.set("key", "new")
    assert store.get("key") == "new"


def test_set_with_ttl_expiry(store):
    """Test that values with TTL expire after the TTL period."""
    store.set("expiring", "data", ttl=0.1)
    assert store.get("expiring") == "data"
    time.sleep(0.15)
    assert store.get("expiring") is None


def test_set_without_ttl_persists(store):
    """Test that values without TTL do not expire."""
    store.set("permanent", "data")
    time.sleep(0.1)
    assert store.get("permanent") == "data"


def test_increment_within_window(store):
    """Test that increment correctly counts within a window."""
    assert store.increment("counter1", 60) == 1
    assert store.increment("counter1", 60) == 2
    assert store.increment("counter1", 60) == 3


def test_increment_resets_after_window(store):
    """Test that increment resets count after the window expires."""
    store.increment("counter2", 0.1)
    store.increment("counter2", 0.1)
    assert store.increment("counter2", 0.1) == 3
    time.sleep(0.15)
    # After window, old entries should be pruned
    assert store.increment("counter2", 0.1) == 1
