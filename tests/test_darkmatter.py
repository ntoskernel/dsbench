"""The dark-matter pipeline up to judging; every value is synthetic."""

import base64
import csv
import json
import zlib
from pathlib import Path

import pytest

from dsbench import darkmatter, dataset, matcher, store
from dsbench.home import BenchHome
from dsbench.metrics import rank_sql
from helpers import csv_row, write_corpus

RANDOM = 'Wq2Er4Ty6Ui8Op0As1Df3Gh'
FILES = {
    'acme-app_c0_src__a.py': (
        'token = "Tq7XbR2mKp9L"\n'  # 1: labelled Y
        'copy = "Tq7XbR2mKp9L"\n'  # 2: the same value, unlabelled: a copy of a labelled secret
        'colour = "hello-world"\n'  # 3: a value labelled N elsewhere
        'version = "1.2.3"\n'  # 4: a version
        f'api_key = "{RANDOM}"\n'  # 5: to judge
    ),
    'acme-app_c0_src__b.py': 'name = "hello-world"\n',
}
ROWS = [
    csv_row(1, 'Tq7XbR2mKp9L', 'acme-app_c0_src__a.py', 1, 'Y', start_column=10, end_column=22),
    csv_row(2, 'hello-world', 'acme-app_c0_src__b.py', 1, 'N', start_column=9, end_column=20),
]
# run -> (finding_id, line, start_col, end_col, value)
FINDINGS = {
    'a': [(1, 1, 10, 22, 'Tq7XbR2mKp9L'), (2, 2, 9, 21, 'Tq7XbR2mKp9L'), (3, 3, 11, 22, 'hello-world'), (4, 4, 12, 17, '1.2.3'), (5, 5, 12, 34, RANDOM)],
    # another tool reports the assignment around the same value: one unit with run a's
    'b': [(1, 5, 1, 35, f'api_key = "{RANDOM}"'), (2, 2, 1, 22, 'copy = "Tq7XbR2mKp9L"')],
}  # fmt: skip


@pytest.fixture
def con(tmp_path: Path, home: BenchHome):
    data = write_corpus(tmp_path / 'data', FILES, ROWS)
    with store.connect(home) as con:
        dataset_id, _ = dataset.prepare(con, home, data / 'secretbench.csv', data / 'Files')
        for run_id, findings in FINDINGS.items():
            con.execute(
                "INSERT INTO runs (run_id, dataset_id, profile, params, status) VALUES (?, ?, 'all-files', '{}', 'done')",
                [run_id, dataset_id],
            )
            for fid, line, sc, ec, value in findings:
                con.execute(
                    '''INSERT INTO findings (run_id, finding_id, file_id, start_line, end_line, start_col, end_col,
                           value, tier, rule_base) VALUES (?, ?, 'acme-app_c0_src__a.py', ?, ?, ?, ?, ?, 'high', 'R')''',
                    [run_id, fid, line, line, sc, ec, value],
                )
            matcher.match_run(con, home, run_id, ('located',), processes=1)
        yield con


def test_export_settles_the_clear_cases_and_masks_the_rest(con, home: BenchHome):
    s = darkmatter.export(con, home, ['a', 'b'], rank_sql('x.tier'), name='t', per_sheet=10)
    assert s['units'] == 4 and s['units_per_run'] == {'a': 4, 'b': 2}
    assert s['settled'] == {
        'rule:labelled_y_elsewhere': 1,
        'rule:labelled_n_elsewhere': 1,
        'rule:file_name_or_version': 1,
        'to_judge': 1,
    }
    out = Path(s['written_to'])
    units = [json.loads(line) for line in (out / 'units.jsonl').read_text().splitlines()]
    judged = next(u for u in units if 'verdict' not in u)
    assert judged['runs'] == ['a', 'b'] and judged['name'] == 'api_key' and judged['value'] == darkmatter.mask(RANDOM)
    assert judged['labels_in_file'] == {'Y': 1} and judged['path_class'] == 'code'
    sheet = (out / 'sheets' / 'sheet-001.jsonl').read_text().splitlines()
    assert 'test_credential' in json.loads(sheet[0])['rubric'] and len(sheet) == 2
    for path in out.rglob('*'):
        if path.is_file():
            text = path.read_text()
            for value in (RANDOM, 'Tq7XbR2mKp9L', 'hello-world'):
                assert value not in text, f'{value} in {path.name}'


def test_rule_verdicts_and_judged_units_go_into_the_overlay(con, home: BenchHome):
    s = darkmatter.export(con, home, ['a'], rank_sql('x.tier'), name='t')
    out = Path(s['written_to'])
    result = darkmatter.import_verdicts(home, out / 'rules.csv', 'rules')
    assert result == {'imported': {'copy_of_labelled': 1, 'not_secret': 2}, 'overlay_units': 3}
    template = out / 'verdicts-template.csv'
    rows = list(csv.DictReader(open(template)))
    with open(template, 'w', newline='') as f:
        writer = csv.DictWriter(f, ['unit_id', 'verdict', 'note'])
        writer.writeheader()
        writer.writerows([{**r, 'verdict': 'live'} for r in rows])
    result = darkmatter.import_verdicts(home, template, 'annotator-1', out / 'units.jsonl')
    assert result['overlay_units'] == 4 and set(darkmatter.load_overlay(home).values()) >= {'live', 'copy_of_labelled'}
    again = darkmatter.export(con, home, ['a'], rank_sql('x.tier'), name='t2')
    assert again['settled'] == {'in_overlay': 4}
    with open(template, 'w', newline='') as f:
        f.write('unit_id,verdict,note\nu000000,maybe,\n')
    with pytest.raises(darkmatter.DarkMatterError):
        darkmatter.import_verdicts(home, template, 'x', out / 'units.jsonl')


def test_a_rule_verdict_covers_every_key_of_its_unit(con, home: BenchHome):
    # run b's assignment around the copy merges into the copy's unit with a key of its own
    s = darkmatter.export(con, home, ['a', 'b'], rank_sql('x.tier'), name='t')
    out = Path(s['written_to'])
    settled = [json.loads(line) for line in (out / 'units.jsonl').read_text().splitlines()]
    copy = next(u for u in settled if u.get('verdict_source') == 'rule:labelled_y_elsewhere')
    assert len(copy['keys']) == 2
    darkmatter.import_verdicts(home, out / 'rules.csv', 'rules')
    overlay = darkmatter.load_overlay(home)
    assert all(overlay.get(tuple(k)) == 'copy_of_labelled' for k in copy['keys'])


def _github_token(body: str) -> str:
    crc, digits, alphabet = zlib.crc32(body.encode()), '', darkmatter._BASE62
    while crc:
        crc, r = divmod(crc, 62)
        digits = alphabet[r] + digits
    return f'ghp_{body}{digits.rjust(6, "0")}'


def test_offline_format_checks():
    token = _github_token('Tq7XbR2mKp9LZx9Qm2Lp8Rt4Mk3Vb8')
    assert darkmatter.formats(token) == {'github_token_checksum_ok': True}
    assert darkmatter.formats(token[:-1] + ('A' if token[-1] != 'A' else 'B'))['github_token_checksum_ok'] is False
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip('=')
    claims = base64.urlsafe_b64encode(b'{"sub":"1","exp":2}').decode().rstrip('=')
    assert darkmatter.formats(f'{header}.{claims}.c2ln')['jwt'] == {
        'decodes': True,
        'alg': 'HS256',
        'claims': ['exp', 'sub'],
    }
    der = base64.b64encode(b'\x30\x82' + b'\x01' * 40).decode()
    assert darkmatter.formats(f'-----BEGIN RSA PRIVATE KEY-----\\n{der}\\n-----END RSA PRIVATE KEY-----')['pem']['der']
    assert darkmatter.formats('AKIAZ7XQ4M2LP8RT4WEN') == {'aws_key_id': True}
    body = ('Tq7XbR2mKp9LZx9Qm2Lp8Rt4Mk3Vb8' * 4)[:107]
    assert darkmatter.formats(f'xprv{body}') == {'bip32_private': True}
    assert darkmatter.formats(f'tpub{body}') == {'bip32_public': True}
    assert darkmatter.formats('02' + 'a7' * 32) == {'ec_public_key_hex': True}
    assert darkmatter.formats('a7' * 32) == {'hex_digest': True}


@pytest.mark.parametrize(
    'value, settled',
    [('app.min.js', 'file_name_or_version'), ('v2.10.4-beta', 'file_name_or_version'), ('src/lib/x', 'file_name_or_version'), (RANDOM, None)],
)  # fmt: skip
def test_shapes_that_settle_a_unit(value, settled):
    found = darkmatter.settled_by_rule(value, value, set(), set())
    assert (found[1] if found else None) == settled


def test_masks_hide_every_random_token_but_keep_the_words():
    line = f'api_key = "{RANDOM}"  # see Zx9Qm2Lp8Rt4Mk3Vb8 and the docs'
    masked = darkmatter.masked_line(line, RANDOM)
    assert RANDOM not in masked and 'Zx9Qm2Lp8Rt4Mk3Vb8' not in masked
    assert masked.startswith(f'api_key = "<VALUE {darkmatter.mask(RANDOM)}>"') and 'the docs' in masked
