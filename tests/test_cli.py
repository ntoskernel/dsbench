from pathlib import Path

from dsbench.cli import main
from helpers import csv_row, write_corpus


def test_prepare_run_match_metrics_status(tmp_path: Path, fake_cmd: str, capsys):
    data = write_corpus(
        tmp_path / 'data',
        {'acme-app_c0_src__a.py': 'token = "Tq7XbR2mKp9L"\n', 'flat.txt': 'name = "hello"  # conf=2\n'},
        [csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0_src__a.py', 1, 'Y')],
    )
    (tmp_path / 'tool').mkdir()
    home = ['--home', str(tmp_path / 'home')]

    assert main([*home, '--data', str(data), 'prepare']) == 0
    out = capsys.readouterr().out
    assert 'rows      1 (1 Y, 0 N)' in out and 'files     2 (1 labelled, 1 not)' in out

    args = ['run', '--tool-cwd', str(tmp_path / 'tool'), '--tool-cmd', fake_cmd, '--cores', '2', '--label', 'c1']
    assert main([*home, *args]) == 0
    out = capsys.readouterr().out
    assert '[run] done: 2 files, 2 findings' in out and '[match] legacy (legacy-1): 1 pairs' in out
    assert 'June view: not applicable' in out
    run_id = next((tmp_path / 'home' / 'runs').iterdir()).name
    assert (tmp_path / 'home' / 'runs' / run_id / 'summary.md').is_file()

    assert main([*home, 'match', '--run', run_id]) == 0
    assert main([*home, 'metrics', '--run', run_id]) == 0
    capsys.readouterr()
    assert main([*home, 'status']) == 0
    out = capsys.readouterr().out
    assert run_id in out and 'done' in out and '[c1]' in out and '2 files, 2 findings' in out


def test_errors_are_one_line_and_exit_1(tmp_path: Path, capsys):
    home = ['--home', str(tmp_path / 'home')]
    assert main([*home, 'metrics', '--run', 'nope']) == 1
    assert 'dsbench: No run nope' in capsys.readouterr().err
    assert main([*home, 'run', '--tool-cwd', str(tmp_path), '--cores', '1']) == 1
    assert 'holds no deepsecrets/ package' in capsys.readouterr().err


def test_watch_shows_progress_and_an_eta_from_shards():
    from collections import deque

    from dsbench.cli import watch_lines

    p = {
        'run_id': 'r',
        'status': 'running',
        'updated_at': '2026-10-28T12:00:00',
        'elapsed_s': 600,
        'cores': 30,
        'files': {'done': 500, 'total': 1000},
        'shards': {'done': 40, 'running': 20, 'queued': 60, 'split': 0, 'retried': 1, 'failed': 0},
        'findings': 7,
        'cpu_s': 7200,
        'statuses': {'ok': 500},
    }
    lines = watch_lines(p, deque([(0.0, 300, 20), (60.0, 500, 40)]))
    assert '50.0%' in lines[1] and '500 of 1,000' in lines[1]
    assert '40 of 120 done' in lines[2] and '1 retried' in lines[2]
    # 20 shards a minute; 20 / 2 running plus 60 queued left: about 4 minutes
    assert lines[-1].endswith('ETA ~4 min')
    assert watch_lines({**p, 'status': 'interrupted'}, deque([(0.0, 1, 1)]))[-1] == 'stopped: interrupted'
