import json
from pathlib import Path

import pytest

from dsbench import dataset, runner, store
from dsbench.home import BenchHome
from dsbench.tool import resolve_tool
from helpers import csv_row, write_corpus

FILES = {
    'acme-app_c0_src__a.py': 'token = "Tq7XbR2mKp9L"\nname = "hello"  # conf=2\n',
    'acme-app_c0_src__b.py': 'key = "Zx9Qm2Lp8Rt4"  # conf=7\n',
    'acme-app_c0_tests__c.py': 'pad = "' + 'x' * 120 + '"  # conf=4\nNOTE\n',
    'flat.txt': 'nothing here\n',
}


def file(name: str, size: int) -> dict:
    return {'file_id': name, 'view_path': f'v/{name}', 'size': size}


def test_plan_puts_big_files_alone_and_the_most_expensive_shards_first():
    files = [file('big', 9_000_000), file('mid', 6_000_000)] + [file(f's{i}', 1_000 * i) for i in range(50)]
    groups = runner.plan(files, cores=2, solo_bytes=5_000_000, max_files=10)
    assert groups[0] == [files[0]] and groups[1] == [files[1]]
    assert all(len(g) <= 10 for g in groups)
    assert sorted(f['file_id'] for g in groups for f in g) == sorted(f['file_id'] for f in files)
    costs = [sum(runner.cost(f['size']) for f in g) for g in groups]
    assert costs == sorted(costs, reverse=True)
    # within the size tier a byte costs more: the lexer runs
    assert runner.cost(200_000) > runner.cost(300_000)


def test_split_halves_cover_the_shard():
    files = [file(f'f{i}', 100 * i) for i in range(7)]
    halves = runner.split(files)
    assert len(halves) == 2 and sorted(f['file_id'] for h in halves for f in h) == [f['file_id'] for f in files]
    assert runner.split([files[0]]) == [[files[0]]]


@pytest.fixture
def bench(tmp_path: Path, home: BenchHome, fake_cmd: str):
    """A prepared dataset, a stand-in scanner checkout (a package to digest) and a store connection."""
    rows = [
        csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0_src__a.py', 1, 'Y'),
        csv_row(2, 'hello', 'acme-app_c0_src__a.py', 2, 'N'),
        csv_row(3, 'Zx9Qm2Lp8Rt4', 'acme-app_c0_src__b.py', 1, 'Y'),
    ]

    def make(files=FILES):
        data = write_corpus(tmp_path / 'data', files, rows)
        (tmp_path / 'tool' / 'deepsecrets').mkdir(parents=True)
        (tmp_path / 'tool' / 'deepsecrets' / '__init__.py').write_text('')
        con = store.connect(home)
        dataset_id, _ = dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files')
        tool = resolve_tool(tmp_path / 'tool', fake_cmd)
        return con, dataset_id, tool

    yield make


def fast(**kw) -> runner.RunOptions:
    return runner.RunOptions(cores=2, poll_s=0.02, **kw)


def test_a_run_scans_every_file_and_stores_what_the_report_says(bench, home: BenchHome):
    con, dataset_id, tool = bench()
    r = runner.Runner.create(con, home, dataset_id, tool, fast(), label='b19 trial')
    assert r.run_id.endswith('-all-files') and r.total_files == 4
    result = r.execute()
    assert result['status'] == 'done' and result['files_done'] == 4 and result['findings'] == 4

    run = store.get_run(con, r.run_id)
    assert run['status'] == 'done' and run['params']['label'] == 'b19 trial' and run['params']['cores'] == 2
    assert run['tool_version'] == '9.9.9' and len(run['params']['segments']) == 1  # the version from the report
    artifacts = {
        a['file_id']: a for a in store.fetch_dicts(con, 'SELECT * FROM artifacts WHERE run_id = ?', [r.run_id])
    }
    assert {a['status'] for a in artifacts.values()} == {'ok'} and len(artifacts) == 4
    assert artifacts['acme-app_c0_tests__c.py']['depth'] == 'shallow' and artifacts['flat.txt']['depth'] == 'deep'
    assert artifacts['acme-app_c0_tests__c.py']['errors'] == 1
    assert con.execute('SELECT file_id, level FROM errors').fetchall() == [('acme-app_c0_tests__c.py', 'error')]
    findings = store.fetch_dicts(con, 'SELECT * FROM findings WHERE run_id = ? ORDER BY finding_id', [r.run_id])
    assert len({f['finding_id'] for f in findings}) == 4
    b = next(f for f in findings if f['file_id'] == 'acme-app_c0_src__b.py')
    assert (b['rule_id'], b['rule_base'], b['confidence'], b['start_line']) == ('S105-HIGH', 'S105', 7, 1)
    assert (b['start_col'], b['end_col'], b['value']) == (8, 20, 'Zx9Qm2Lp8Rt4')
    assert con.execute("SELECT count(*) FROM shards WHERE status <> 'done'").fetchone()[0] == 0
    progress = json.loads((home.run_dir(r.run_id) / 'progress.json').read_text())
    assert progress['status'] == 'done' and progress['files'] == {'done': 4, 'total': 4}
    shard = next((home.run_dir(r.run_id) / 'shards').iterdir())
    assert (shard / 'report.sarif').is_file() and (shard / 'scanner.log').is_file() and (shard / 'target').is_dir()


def test_a_failing_file_is_split_out_retried_and_recorded(bench, home: BenchHome, monkeypatch):
    monkeypatch.setattr(runner, 'SHARDS_PER_CORE', 0)  # one packed shard for everything
    con, dataset_id, tool = bench({**FILES, 'boom.txt': 'CRASH\n'})
    r = runner.Runner.create(con, home, dataset_id, tool, fast())
    assert len(r.queue) == 1
    result = r.execute()
    assert result['status'] == 'incomplete' and result['failed'] == 1 and result['split'] >= 1
    statuses = dict(con.execute('SELECT file_id, status FROM artifacts').fetchall())
    assert statuses.pop('boom.txt') == 'tool_error' and set(statuses.values()) == {'ok'} and len(statuses) == 4
    failed = store.fetch_dicts(con, "SELECT * FROM shards WHERE status = 'failed'")
    assert len(failed) == 1 and failed[0]['attempts'] == 2 and failed[0]['note'] == 'exit 3'
    assert con.execute('SELECT count(*) FROM findings').fetchone()[0] == 4


def test_a_hanging_file_times_out(bench, home: BenchHome, monkeypatch):
    monkeypatch.setattr(runner, 'SHARDS_PER_CORE', 0)
    con, dataset_id, tool = bench({'stuck.txt': 'HANG\n', 'flat.txt': 'x = "y"\n'})
    r = runner.Runner.create(con, home, dataset_id, tool, fast(shard_timeout=1, solo_timeout=1, attempts=1))
    result = r.execute()
    assert result['status'] == 'incomplete'
    assert dict(con.execute('SELECT file_id, status FROM artifacts').fetchall()) == {
        'stuck.txt': 'timeout',
        'flat.txt': 'ok',
    }


def test_an_interrupted_run_resumes_with_only_the_files_left(bench, home: BenchHome, monkeypatch):
    con, dataset_id, tool = bench()
    r = runner.Runner.create(con, home, dataset_id, tool, fast())
    assert len(r.queue) >= 2
    finish = runner.Runner._finish
    calls = []

    def interrupt_on_second(self, *args):
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return finish(self, *args)

    monkeypatch.setattr(runner.Runner, '_finish', interrupt_on_second)
    with pytest.raises(KeyboardInterrupt):
        r.execute()
    monkeypatch.setattr(runner.Runner, '_finish', finish)
    assert store.get_run(con, r.run_id)['status'] == 'interrupted'
    done_before = con.execute('SELECT count(*) FROM artifacts').fetchone()[0]
    assert 0 < done_before < 4

    resumed = runner.Runner.resume(con, home, r.run_id, fast())
    assert resumed.total_files == 4 and resumed.tally.files_done == done_before
    assert resumed.execute()['status'] == 'done'
    run = store.get_run(con, r.run_id)
    assert run['status'] == 'done' and len(run['params']['resumed_with']) == 1 and len(run['params']['segments']) == 2
    assert con.execute('SELECT count(*), count(DISTINCT file_id) FROM artifacts').fetchone() == (4, 4)
    assert con.execute('SELECT count(*) FROM findings').fetchone()[0] == 4
    assert con.execute("SELECT count(*) FROM shards WHERE status = 'abandoned'").fetchone()[0] >= 1


def test_resume_refuses_a_changed_scanner(bench, home: BenchHome, tmp_path: Path):
    con, dataset_id, tool = bench()
    r = runner.Runner.create(con, home, dataset_id, tool, fast())
    (tmp_path / 'tool' / 'deepsecrets' / '__init__.py').write_text('changed = True\n')
    with pytest.raises(runner.RunError):
        runner.Runner.resume(con, home, r.run_id, fast())


def test_run_ids_name_the_time_and_profile_and_never_repeat(bench, home: BenchHome):
    con, dataset_id, tool = bench()
    from datetime import datetime

    assert runner.new_run_id('all-files', datetime(2026, 9, 11, 17, 50, 31)) == '20260911-175031-all-files'
    runner.Runner.create(con, home, dataset_id, tool, fast(), run_id='20260911-175031-all-files')
    with pytest.raises(runner.RunError):
        runner.Runner.create(con, home, dataset_id, tool, fast(), run_id='20260911-175031-all-files')


def test_tiers_of_findings_stored_without_them_are_filled_from_suffixes_and_reports(bench, home: BenchHome):
    con, dataset_id, tool = bench()
    r = runner.Runner.create(con, home, dataset_id, tool, fast())
    r.execute()
    shard_id = con.execute('SELECT min(shard_id) FROM findings').fetchone()[0]
    report = home.run_dir(r.run_id) / 'shards' / shard_id / 'report.sarif'
    document = json.loads(report.read_text())
    document['runs'][0]['tool']['driver']['rules'] = [{'id': 'S1', 'properties': {'precision': 'high'}}]
    report.write_text(json.dumps(document))
    con.execute("UPDATE findings SET tier = NULL, rule_id = 'S1' WHERE shard_id = ?", [shard_id])
    con.execute("UPDATE findings SET tier = NULL WHERE shard_id <> ?", [shard_id])
    con.execute(
        "INSERT INTO findings (run_id, finding_id, shard_id, rule_id) VALUES (?, 99, ?, 'S2')", [r.run_id, shard_id]
    )
    assert runner.fill_tiers(con, home, r.run_id) == 1  # S2 has neither a suffix nor a descriptor
    tiers = dict(con.execute('SELECT rule_id, tier FROM findings WHERE rule_id IN (\'S1\', \'S2\')').fetchall())
    assert tiers == {'S1': 'high', 'S2': None}
    assert con.execute("SELECT count(*) FROM findings WHERE rule_id LIKE '%-HIGH' AND tier = 'high'").fetchone()[0] >= 1


def test_the_sample_rule_is_a_seeded_draw_from_the_sorted_labelled_ids():
    ids = [f'f{i:02d}' for i in range(40)]
    assert runner.draw_sample(list(reversed(ids)), 5, 11) == runner.draw_sample(ids, 5, 11)
    assert runner.draw_sample(ids, 5, 11) == __import__('random').Random(11).sample(ids, 5)
    assert runner.draw_sample(ids, 5, 12) != runner.draw_sample(ids, 5, 11)
    with pytest.raises(runner.RunError):
        runner.draw_sample(ids, 41, 11)


def test_a_sample_run_scans_and_resumes_only_its_files(bench, home: BenchHome, monkeypatch):
    con, dataset_id, tool = bench()
    files, described = runner.select_files(con, dataset_id, sample=(1, 3))
    assert len(files) == 1 and described['n'] == 1 and described['seed'] == 3 and described['files'] == 1
    assert runner.select_files(con, dataset_id, labelled_only=True)[0] and 'flat.txt' not in {
        f['file_id'] for f in runner.select_files(con, dataset_id, labelled_only=True)[0]
    }
    r = runner.Runner.create(con, home, dataset_id, tool, fast(), sample=(2, 3))
    assert r.total_files == 2 and store.get_run(con, r.run_id)['params']['sample']['rule'] == runner.SAMPLE_RULE
    finish = runner.Runner._finish
    monkeypatch.setattr(runner.Runner, '_finish', lambda self, *a: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        r.execute()
    monkeypatch.setattr(runner.Runner, '_finish', finish)
    resumed = runner.Runner.resume(con, home, r.run_id, fast())
    assert resumed.total_files == 2 and resumed.execute()['status'] == 'done'
    assert con.execute('SELECT count(*) FROM artifacts WHERE run_id = ?', [r.run_id]).fetchone()[0] == 2
