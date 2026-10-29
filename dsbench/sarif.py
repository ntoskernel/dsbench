"""Reading the one thing dsbench takes from the scanner: its SARIF report.

From each result: `ruleId` (its base without the tier suffix too), `properties.confidence`, `properties.rejected`, the
artifact URI (a view path relative to the shard's target), the 1-based region (`endColumn` exclusive, columns in code
points) and its `snippet.text`, which is the raw detection when the scan ran with `--disable-masking`, and
`partialFingerprints['dsfpx/v1']`. With `--report-diagnostics`, every discovered file in `run.artifacts` with its
`status`, `scanTimeMs`, `depth` and `skipReason`, and every error notification in `run.invocations`."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# the scanner's tier suffixes, longest first so `-VERY-HIGH` is not read as `-HIGH`
TIER_SUFFIXES = ('-VERY-HIGH', '-MEDIUM', '-HIGH', '-LOW', '-INFO')


class SarifError(Exception):
    pass


@dataclass
class Result:
    uri: str
    rule_id: str
    rule_base: str
    confidence: Optional[int]
    start_line: Optional[int]
    end_line: Optional[int]
    start_col: Optional[int]
    end_col: Optional[int]
    value: Optional[str]
    fingerprint: Optional[str]
    rejected: bool = False


@dataclass
class Artifact:
    uri: str
    status: Optional[str]
    scan_time_ms: Optional[float]
    skip_reason: Optional[str]
    depth: Optional[str]
    length: Optional[int]


@dataclass
class Notification:
    uri: Optional[str]
    level: Optional[str]
    message: str


@dataclass
class Report:
    tool_name: Optional[str]
    tool_version: Optional[str]
    results: List[Result] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    notifications: List[Notification] = field(default_factory=list)
    has_diagnostics: bool = False


def rule_base(rule_id: str) -> str:
    for suffix in TIER_SUFFIXES:
        if rule_id.endswith(suffix):
            return rule_id[: -len(suffix)]
    return rule_id


def _physical(location: dict) -> dict:
    return (location or {}).get('physicalLocation') or {}


def _result(raw: dict) -> Result:
    physical = _physical((raw.get('locations') or [{}])[0])
    region = physical.get('region') or {}
    properties = raw.get('properties') or {}
    rule_id = raw.get('ruleId') or ''
    confidence = properties.get('confidence')
    return Result(
        uri=(physical.get('artifactLocation') or {}).get('uri') or '',
        rule_id=rule_id,
        rule_base=rule_base(rule_id),
        confidence=int(confidence) if confidence is not None else None,
        start_line=region.get('startLine'),
        end_line=region.get('endLine'),
        start_col=region.get('startColumn'),
        end_col=region.get('endColumn'),
        value=(region.get('snippet') or {}).get('text'),
        fingerprint=(raw.get('partialFingerprints') or {}).get('dsfpx/v1'),
        rejected=bool(properties.get('rejected', False)),
    )


def _artifact(raw: dict) -> Artifact:
    properties = raw.get('properties') or {}
    length = raw.get('length')
    return Artifact(
        uri=(raw.get('location') or {}).get('uri') or '',
        status=properties.get('status'),
        scan_time_ms=properties.get('scanTimeMs'),
        skip_reason=properties.get('skipReason'),
        depth=properties.get('depth'),
        length=length if isinstance(length, int) and length >= 0 else None,
    )


def _notification(raw: dict) -> Notification:
    locations = raw.get('locations') or [{}]
    uri = (_physical(locations[0]).get('artifactLocation') or {}).get('uri')
    return Notification(uri=uri, level=raw.get('level'), message=(raw.get('message') or {}).get('text') or '')


def parse(document: dict) -> Report:
    runs = document.get('runs')
    if not isinstance(runs, list) or len(runs) != 1:
        raise SarifError('expected exactly one run')
    run = runs[0]
    driver = (run.get('tool') or {}).get('driver') or {}
    report = Report(tool_name=driver.get('name'), tool_version=driver.get('semanticVersion') or driver.get('version'))
    report.results = [_result(r) for r in run.get('results') or []]
    report.has_diagnostics = 'artifacts' in run
    report.artifacts = [_artifact(a) for a in run.get('artifacts') or []]
    for invocation in run.get('invocations') or []:
        report.notifications += [_notification(n) for n in invocation.get('toolExecutionNotifications') or []]
    return report


def read_report(path: Path) -> Report:
    try:
        with open(path, encoding='utf-8') as f:
            document = json.load(f)
    except (OSError, ValueError) as e:
        raise SarifError(f'{path}: {e.__class__.__name__}') from None
    return parse(document)
