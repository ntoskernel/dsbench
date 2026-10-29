import json
from pathlib import Path

import pytest

from dsbench import sarif


def location(uri, **region):
    return [{'physicalLocation': {'artifactLocation': {'uri': uri, 'uriBaseId': '%SRCROOT%'}, 'region': region}}]


# the shape DeepSecrets writes with --disable-masking --report-diagnostics; synthetic values
DOCUMENT = {
    'runs': [
        {
            'tool': {'driver': {'name': 'DeepSecrets', 'semanticVersion': '2.2.0', 'rules': []}},
            'artifacts': [
                {
                    'location': {'uri': 'r_1/src/app.py', 'uriBaseId': '%SRCROOT%'},
                    'length': 120,
                    'properties': {'status': 'ok', 'scanTimeMs': 12.3, 'depth': 'deep'},
                },
                {'location': {'uri': 'r_1/empty.txt'}, 'length': 0, 'properties': {'status': 'unreadable'}},
                {'location': {'uri': 'r_1/node_modules/x.js'}, 'properties': {'status': 'skipped', 'skipReason': 'x'}},
            ],
            'invocations': [
                {
                    'executionSuccessful': True,
                    'toolExecutionNotifications': [
                        {
                            'message': {'text': 'Unable to open the file'},
                            'level': 'error',
                            'locations': location('r_1/empty.txt'),
                        }
                    ],
                }
            ],
            'results': [
                {
                    'ruleId': 'S105-VERY-HIGH',
                    'properties': {'confidence': 10},
                    'partialFingerprints': {'dsfpx/v1': 'ab' * 32},
                    'locations': location(
                        'r_1/src/app.py',
                        startLine=3,
                        endLine=3,
                        startColumn=8,
                        endColumn=20,
                        snippet={'text': 'Zx9Qm2Lp8Rt4'},
                    ),
                },
                {
                    'ruleId': 'S4',
                    'properties': {'confidence': 10},
                    'locations': location(
                        'r_1/src/app.py',
                        startLine=5,
                        endLine=7,
                        startColumn=1,
                        endColumn=4,
                        snippet={'text': 'a\nb\nc'},
                    ),
                },
                {'ruleId': 'S35-HIGH', 'properties': {'confidence': 7}, 'locations': location('r_1/src/app.py')},
                {'ruleId': 'S19-INFO', 'properties': {'confidence': 0, 'rejected': True}, 'locations': location('x')},
            ],
        }
    ],
    'version': '2.1.0',
}


@pytest.mark.parametrize(
    'rule_id, base',
    [
        ('S105-VERY-HIGH', 'S105'),
        ('S106-HIGH', 'S106'),
        ('S35-MEDIUM', 'S35'),
        ('S41-LOW', 'S41'),
        ('S19-INFO', 'S19'),
        ('S1', 'S1'),
        ('S107', 'S107'),
    ],
)
def test_the_tier_suffix_comes_off(rule_id, base):
    assert sarif.rule_base(rule_id) == base


def test_results_artifacts_and_notifications_are_read():
    report = sarif.parse(DOCUMENT)
    assert (report.tool_name, report.tool_version, report.has_diagnostics) == ('DeepSecrets', '2.2.0', True)
    first, multi, no_region, rejected = report.results
    assert (first.uri, first.rule_id, first.rule_base, first.confidence) == (
        'r_1/src/app.py',
        'S105-VERY-HIGH',
        'S105',
        10,
    )
    assert (first.start_line, first.end_line, first.start_col, first.end_col) == (3, 3, 8, 20)
    assert first.value == 'Zx9Qm2Lp8Rt4' and first.fingerprint == 'ab' * 32 and not first.rejected
    assert multi.value == 'a\nb\nc' and (multi.start_line, multi.end_line) == (5, 7) and multi.fingerprint is None
    assert no_region.start_line is None and no_region.value is None
    assert rejected.rejected and rejected.rule_base == 'S19'

    ok, empty, skipped = report.artifacts
    assert (ok.uri, ok.status, ok.scan_time_ms, ok.depth, ok.length) == ('r_1/src/app.py', 'ok', 12.3, 'deep', 120)
    assert empty.status == 'unreadable' and empty.length == 0 and empty.scan_time_ms is None and empty.depth is None
    assert skipped.skip_reason == 'x' and skipped.length is None
    assert [(n.uri, n.level, n.message) for n in report.notifications] == [
        ('r_1/empty.txt', 'error', 'Unable to open the file')
    ]


def test_a_report_without_diagnostics_says_so():
    run = {'tool': {'driver': {'name': 'DeepSecrets'}}, 'results': []}
    report = sarif.parse({'runs': [run]})
    assert not report.has_diagnostics and report.artifacts == [] and report.notifications == []


def test_unreadable_reports_raise(tmp_path: Path):
    with pytest.raises(sarif.SarifError):
        sarif.read_report(tmp_path / 'missing.sarif')
    (tmp_path / 'cut.sarif').write_text('{"runs": [')
    with pytest.raises(sarif.SarifError):
        sarif.read_report(tmp_path / 'cut.sarif')
    (tmp_path / 'two.sarif').write_text(json.dumps({'runs': [{}, {}]}))
    with pytest.raises(sarif.SarifError):
        sarif.read_report(tmp_path / 'two.sarif')
