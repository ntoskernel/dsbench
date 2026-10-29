"""gitleaks and Betterleaks adapters, against stand-ins; every value is synthetic."""

import hashlib
import io
import json
import sys
import tarfile
import tomllib
from pathlib import Path

import pytest

from dsbench import dataset, matcher, metrics, runner, store, thirdparty
from dsbench.home import BenchHome
from dsbench.tool import resolve_thirdparty
from helpers import csv_row, write_corpus

FAKE = Path(__file__).with_name('fake_leaks.py')

GITLEAKS_CONFIG = """title = "gitleaks config"

[allowlist]
description = "global allow lists"
paths = [
    '''gitleaks\\.toml''',
    '''(?:^|/)node_modules(?:/.*)?$''',
]
regexes = [
    '''(?i)^true|false|null$''',
]

[[rules]]
id = "generic-api-key"
regex = '''x'''
[[rules.allowlists]]
paths = ['''(?i)\\.md$''']
"""


def test_only_the_global_path_allowlists_are_stripped():
    stripped = tomllib.loads(thirdparty.strip_path_allowlist('gitleaks', GITLEAKS_CONFIG))
    assert 'paths' not in stripped['allowlist'] and stripped['allowlist']['regexes']
    assert stripped['rules'][0]['allowlists'][0]['paths']  # a rule's own scope stays
    better = "title = 'x'\nprefilter = '''\nmatchesAny(attributes[\"path\"], [`a`])\n'''\nfilter = '''\ntrue\n'''\n"
    assert tomllib.loads(thirdparty.strip_path_allowlist('betterleaks', better)) == {'title': 'x', 'filter': 'true\n'}
    with pytest.raises(thirdparty.ThirdPartyError):
        thirdparty.strip_path_allowlist('betterleaks', "title = 'x'\n")


@pytest.mark.parametrize(
    'entry, shift, region',
    [
        # gitleaks: columns one more than 1-based; the secret sits inside the match
        ({'StartLine': 3, 'StartColumn': 9, 'Match': 'token = "Tq7XbR2m"', 'Secret': 'Tq7XbR2m'}, 1,
         {'start_line': 3, 'end_line': 3, 'start_col': 17, 'end_col': 25, 'value': 'Tq7XbR2m'}),
        # a secret on the match's second line
        ({'StartLine': 3, 'StartColumn': 1, 'Match': 'key:\n  Tq7Xb\nR2m', 'Secret': 'Tq7Xb\nR2m'}, 0,
         {'start_line': 4, 'end_line': 5, 'start_col': 3, 'end_col': 4, 'value': 'Tq7Xb\nR2m'}),
        # a decoded secret is not in the match: the match is located instead
        ({'StartLine': 1, 'StartColumn': 5, 'Match': 'VHE3WGJS', 'Secret': 'Tq7XbR'}, 0,
         {'start_line': 1, 'end_line': 1, 'start_col': 5, 'end_col': 13, 'value': 'VHE3WGJS'}),
    ],
)  # fmt: skip
def test_the_secret_is_placed_inside_its_match(entry, shift, region):
    assert thirdparty._region(entry, shift) == region


def fake_release(tmp_path: Path, name: str, monkeypatch) -> thirdparty.Release:
    """A release whose archive holds the stand-in, pinned to the archive's digest."""
    script = tmp_path / f'{name}-bin'
    script.write_text(
        f'#!{sys.executable}\nimport runpy, sys\nsys.argv[0] = {str(FAKE)!r}\nrunpy.run_path({str(FAKE)!r}, run_name="__main__")\n'
    )
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        tar.add(script, arcname=name)
    archive = buffer.getvalue()
    config = GITLEAKS_CONFIG.encode()
    release = thirdparty.Release(
        name=name,
        version='8.30.1',
        url='https://example.invalid/archive.tar.gz',
        sha256=hashlib.sha256(archive).hexdigest(),
        binary=name,
        config_url='https://example.invalid/config.toml' if name == 'gitleaks' else None,
        config_sha256=hashlib.sha256(config).hexdigest(),
        column_shift=1 if name == 'gitleaks' else 0,
    )
    monkeypatch.setitem(thirdparty.RELEASES, name, release)
    monkeypatch.setenv('FAKE_LEAKS_SHIFT', '1' if name == 'gitleaks' else '0')
    files = {release.url: archive, 'https://example.invalid/config.toml': config}
    return release, (lambda url: files[url])


def test_a_release_is_fetched_once_and_checked(tmp_path: Path, monkeypatch):
    release, download = fake_release(tmp_path, 'gitleaks', monkeypatch)
    cache = tmp_path / 'cache'
    where = thirdparty.fetch('gitleaks', cache, download=download)
    marker = json.loads((where / thirdparty.MARKER).read_text())
    assert marker['sha256'] == release.sha256 and (where / 'all-files.toml').is_file()
    assert thirdparty.fetch('gitleaks', cache, download=lambda url: 1 / 0) == where  # not again
    bad = thirdparty.Release(**{**release.__dict__, 'sha256': '0' * 64})
    monkeypatch.setitem(thirdparty.RELEASES, 'gitleaks', bad)
    with pytest.raises(thirdparty.ThirdPartyError, match='SHA-256'):
        thirdparty.fetch('gitleaks', tmp_path / 'other', download=download)


@pytest.mark.parametrize('name', ['gitleaks', 'betterleaks'])
def test_a_run_of_another_scanner_is_located_and_counted(name, tmp_path: Path, home: BenchHome, monkeypatch):
    release, download = fake_release(tmp_path, name, monkeypatch)
    cache = tmp_path / 'cache'
    thirdparty.fetch(name, cache, download=download)
    files = {'acme-app_c0_node_modules__a.js': 'x = 1\ntoken = "Tq7XbR2mKp9L"\n', 'flat.txt': 'k = "Zx9Qm2Lp8Rt4"\n'}
    rows = [csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0_node_modules__a.js', 2, 'Y', start_column=10, end_column=22)]
    data = write_corpus(tmp_path / 'data', files, rows)
    with store.connect(home) as con:
        dataset_id, _ = dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files')
        tool = resolve_thirdparty(name, cache)
        r = runner.Runner.create(con, home, dataset_id, tool, runner.RunOptions(cores=2, poll_s=0.02))
        assert r.execute()['status'] == 'done'
        found = store.fetch_dicts(con, 'SELECT * FROM findings ORDER BY file_id')
        assert [f['tier'] for f in found] == (['none', 'none'] if name == 'gitleaks' else ['medium', 'medium'])
        assert con.execute("SELECT count(*) FROM artifacts WHERE status = 'ok'").fetchone()[0] == 2
        assert not any((home.run_dir(r.run_id) / 'shards').glob('*/target/*'))  # the copies are gone
        matcher.match_run(con, home, r.run_id, processes=1)
        m = metrics.compute(con, r.run_id, rows=[])
        assert m['located']['per_group']['very-high']['secrets_found'] == (1 if name == 'gitleaks' else 0)
        assert m['located']['per_group']['medium']['secrets_found'] == 1
        assert m['located']['tiered'] is (name == 'betterleaks')
        assert store.get_run(con, r.run_id)['params']['tool_kind'] == name
        resumed = runner.Runner.resume(con, home, r.run_id, runner.RunOptions(cores=1, poll_s=0.02))
        assert resumed.tool.kind == name and resumed.total_files == 2
