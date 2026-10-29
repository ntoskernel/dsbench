"""Shared fixtures: a bench home, the fake scanner's command, and no real places. Every value is synthetic."""

import shlex
import sys
from pathlib import Path

import pytest

from dsbench.home import BenchHome
from helpers import FAKE_SCANNER


@pytest.fixture
def home(tmp_path: Path) -> BenchHome:
    return BenchHome(tmp_path / 'home').ensure()


@pytest.fixture
def fake_cmd() -> str:
    return shlex.join([sys.executable, str(FAKE_SCANNER)])


@pytest.fixture(autouse=True)
def no_places(monkeypatch):
    """Tests never see the developer's real places."""
    for var in ('DSBENCH_DATA', 'DSBENCH_HOME', 'DSBENCH_TOOL_CWD', 'DSBENCH_CACHE'):
        monkeypatch.delenv(var, raising=False)
