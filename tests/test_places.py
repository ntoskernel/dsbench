from pathlib import Path

import pytest

from dsbench.home import HomeError, resolve_home
from dsbench.places import DSBENCH_ROOT, Places, PlacesError, resolve_places


def test_separate_places_pass(tmp_path: Path):
    places = Places(
        data=tmp_path / 'data', home=tmp_path / 'home', tool_cwd=tmp_path / 'tool', cache=tmp_path / 'cache'
    )
    assert places.overlaps() == []
    assert places.require_apart() is places


@pytest.mark.parametrize('inner', ['home', 'tool_cwd', 'cache'])
def test_a_place_inside_another_is_refused(tmp_path: Path, inner: str):
    paths = {name: tmp_path / name for name in ('data', 'home', 'tool_cwd', 'cache')}
    paths[inner] = paths['data'] / inner
    problems = Places(**paths).overlaps()
    assert len(problems) == 1 and 'data' in problems[0] and inner in problems[0]
    with pytest.raises(PlacesError):
        Places(**paths).require_apart()


def test_nothing_may_sit_inside_dsbench():
    assert Places(data=None, home=DSBENCH_ROOT / 'home', tool_cwd=None, cache=None).overlaps()


def test_arguments_win_over_the_environment(tmp_path: Path, monkeypatch):
    monkeypatch.setenv('DSBENCH_DATA', str(tmp_path / 'from-env'))
    monkeypatch.delenv('DSBENCH_CACHE', raising=False)
    places = resolve_places(data=str(tmp_path / 'given'))
    assert places.data == tmp_path / 'given' and places.cache is None


def test_the_bench_home_is_never_a_repository(tmp_path: Path, monkeypatch):
    for var in ('DSBENCH_DATA', 'DSBENCH_TOOL_CWD', 'DSBENCH_CACHE'):
        monkeypatch.delenv(var, raising=False)
    (tmp_path / 'repo' / '.git').mkdir(parents=True)
    with pytest.raises(HomeError):
        resolve_home(str(tmp_path / 'repo'))
    home = resolve_home(str(tmp_path / 'home'))
    assert home.runs_dir.is_dir() and home.legacy_dir.is_dir() and home.overlays_dir.is_dir()
