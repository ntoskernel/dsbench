"""`diagnose` against a stand-in tracer; every value is synthetic."""

import json
import sys
from pathlib import Path

import pytest

from dsbench import dataset, diagnose, matcher, store
from dsbench.home import BenchHome
from dsbench.tool import source_digest
from helpers import csv_row, write_corpus

# a tracer with DeepSecrets' command line: one trace per case, its verdict chosen by the case's kind
FAKE_TRACER = '''
import argparse, json, os, sys
p = argparse.ArgumentParser()
sub = p.add_subparsers(dest='command')
t = sub.add_parser('trace')
for flag in ('--cases', '--out', '--processes', '--max-file-mb', '--deep-max-size'):
    t.add_argument(flag)
t.add_argument('--no-path-exclusions', action='store_true')
a = p.parse_args()
assert a.no_path_exclusions and a.deep_max_size == '250000'
with open(a.cases) as f, open(a.out, 'w') as out:
    for line in f:
        c = json.loads(line)
        assert os.path.exists(c['path']) and c['path'].endswith(c['relative_path'])
        kind = c['case_id'].split(':')[0]
        trace = {'schema': 5, 'case_id': c['case_id'], 'selection': {'excluded_by': None}}
        if kind == 'miss':
            trace['verdict'] = {'stage': 'detection', 'component': 'variable_detection', 'detail': 'in a comment'}
            trace['evaluations'] = [{'dangerous': False, 'dangerous_without': {'SEM_X': True}}]
        elif kind == 'lookalike':
            trace['verdict'] = {'stage': 'reported', 'component': 'regex_engine', 'detail': 'S4'}
            trace['candidate_evaluation'] = [{'span': [1, 5], 'rule': 'S4', 'reason': 'RC_A'}] * 3
        else:
            trace['verdict'] = {'stage': 'reported', 'component': 'semantic_engine', 'detail': 'S105'}
            trace['evaluations'] = [{'dangerous': True, 'dangerous_without': {'SEM_Y': False, 'SEM_Z': True}}]
        out.write(json.dumps(trace) + '\\n')
print('traced', file=sys.stderr)
'''


@pytest.fixture
def tool(tmp_path: Path) -> Path:
    root = tmp_path / 'tool'
    (root / 'deepsecrets' / 'diagnostics').mkdir(parents=True)
    (root / 'deepsecrets' / '__init__.py').write_text('')
    (root / 'deepsecrets' / 'diagnostics' / '__init__.py').write_text('')
    (root / 'deepsecrets' / 'diagnostics' / '__main__.py').write_text(FAKE_TRACER)
    return root


@pytest.fixture
def run(tmp_path: Path, home: BenchHome, tool: Path):
    files = {
        'acme-app_c0_src__a.py': 'token = "Tq7XbR2mKp9L"\nname = "hello"\n',
        'acme-app_c0_tests__b.py': 'key = "Zx9Qm2Lp8Rt4"\n',
        'flat.txt': 'x = "Mk3Vb8Qw1Zr5"\n',
    }
    rows = [
        csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0_src__a.py', 1, 'Y', start_column=10, end_column=22),
        csv_row(2, 'hello', 'acme-app_c0_src__a.py', 2, 'N', start_column=9, end_column=14),
        csv_row(3, 'Zx9Qm2Lp8Rt4', 'acme-app_c0_tests__b.py', 1, 'Y', start_column=8, end_column=20),
    ]
    data = write_corpus(tmp_path / 'data', files, rows)
    con = store.connect(home)
    dataset_id, _ = dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files')
    cmd = json.dumps([sys.executable, '-W', 'ignore', '-m', 'deepsecrets'])
    con.execute(
        '''INSERT INTO runs (run_id, dataset_id, tool_cmd, tool_cwd, tool_digest, profile, params, status)
           VALUES ('r', ?, ?, ?, ?, 'all-files', '{}', 'done')''',
        [dataset_id, cmd, str(tool), source_digest(tool)],
    )
    # found: row 1; charged: row 2; missed: row 3; one finding outside the labels
    for fid, file_id, line, sc, ec, value in [
        (1, 'acme-app_c0_src__a.py', 1, 10, 22, 'Tq7XbR2mKp9L'),
        (2, 'acme-app_c0_src__a.py', 2, 9, 14, 'hello'),
        (3, 'flat.txt', 1, 6, 18, 'Mk3Vb8Qw1Zr5'),
    ]:
        con.execute(
            '''INSERT INTO findings (run_id, finding_id, file_id, start_line, end_line, start_col, end_col, value, tier)
               VALUES ('r', ?, ?, ?, ?, ?, ?, ?, 'high')''',
            [fid, file_id, line, line, sc, ec, value],
        )
    matcher.match_run(con, home, 'r', ('located',), processes=1)
    yield con
    con.close()


def test_diagnose_traces_every_kind_of_case_and_keeps_only_aggregates(run, home: BenchHome):
    d = diagnose.diagnose(run, home, 'r', processes=1, contrast=5, extras=5)
    assert d['traced'] == {'miss': 1, 'lookalike': 1, 'contrast': 1, 'extra': 1}
    assert d['verdicts']['miss'] == {'detection: in a comment': 1}
    assert d['verdicts']['lookalike'] == {'reported by the regex engine': 1}
    # one candidate recorded by three passes counts once
    assert d['rejected_by_candidate_rule'] == {'lookalike': {'RC_A': 1}}
    assert d['ledger'] == {'carried': {'SEM_Y': 1}, 'blamed': {}, 'blocked': {'SEM_X': 1}}
    out = diagnose.diagnosis_dir(home, 'r')
    assert {'cases.jsonl', 'traces.jsonl', 'diagnosis.json', 'meta.json'} <= {p.name for p in out.iterdir()}
    written = (out / 'diagnosis.json').read_text()
    for value in ('Tq7XbR2mKp9L', 'hello', 'Zx9Qm2Lp8Rt4', 'Mk3Vb8Qw1Zr5', 'acme-app'):
        assert value not in written
    again = diagnose.diagnose(run, home, 'r', reuse_traces=True)
    assert again['verdicts'] == d['verdicts'] and again['tracer_digest'] == d['tracer_digest']


def test_a_changed_tree_a_tree_without_the_tracer_or_a_custom_command_is_refused(run, home: BenchHome, tool: Path):
    (tool / 'deepsecrets' / '__init__.py').write_text('changed = True\n')
    with pytest.raises(diagnose.DiagnoseError, match='no longer has the digest'):
        diagnose.diagnose(run, home, 'r', processes=1)
    run.execute('UPDATE runs SET tool_digest = ?', [source_digest(tool)])
    (tool / 'deepsecrets' / 'diagnostics' / '__main__.py').unlink()
    (tool / 'deepsecrets' / 'diagnostics' / '__init__.py').unlink()
    (tool / 'deepsecrets' / 'diagnostics').rmdir()
    with pytest.raises(diagnose.DiagnoseError, match='no deepsecrets/diagnostics tracer'):
        diagnose.diagnose(run, home, 'r', processes=1)
    run.execute('''UPDATE runs SET tool_cmd = '["scanner"]' ''')
    with pytest.raises(diagnose.DiagnoseError):
        diagnose.recorded_tool(store.get_run(run, 'r'))


def test_a_trace_schema_dsbench_does_not_read_is_refused():
    with pytest.raises(diagnose.DiagnoseError, match='schema'):
        diagnose.analyse([{'schema': 4, 'case_id': 'miss:1', 'verdict': {}}], {'miss:1': 'miss'})
    six = diagnose.analyse([{'schema': 6, 'case_id': 'miss:1', 'verdict': {'stage': 'tier'}}], {'miss:1': 'miss'})
    assert six['verdicts'] == {'miss': {'size tier': 1}}


@pytest.mark.parametrize(
    'verdict, name',
    [
        ({'stage': 'tier', 'detail': '300000 bytes, ..., which would have detected the variable'}, 'size tier, the lexer would have found it'),
        ({'stage': 'evaluation', 'component': 'regex_candidate_evaluator', 'detail': 'S35: rejected at -9'}, 'regex candidate rejected'),
        ({'stage': 'evaluation', 'component': 'variable_evaluator'}, 'scored not dangerous'),
        ({'stage': 'gate', 'detail': 'contains_space'}, 'gate: contains_space'),
        ({'stage': 'label', 'detail': 'value not found where the label points'}, 'label: value not found where the label points'),
        ({'stage': 'selection', 'detail': 'node_modules'}, 'excluded path'),
    ],
)  # fmt: skip
def test_categories_drop_case_specific_detail(verdict, name):
    assert diagnose.category(verdict) == name
