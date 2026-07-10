"""Shared pytest fixtures for ThreatTracer tests."""

import pytest
from threattracer.utils.config import AppConfig


@pytest.fixture
def config() -> AppConfig:
    """Return a default test config (no real API keys)."""
    return AppConfig()
