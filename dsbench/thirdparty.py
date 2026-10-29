"""Other scanners under the same harness: gitleaks and Betterleaks, as released binaries.

Each is pinned to one release: `dsbench tools fetch` downloads it into `$DSBENCH_CACHE/tools/<name>-<version>/` and
refuses an archive whose SHA-256 differs from the one pinned here. Their default rules are kept as released: gitleaks'
from its source at the release tag (pinned too), Betterleaks' as its binary prints them (`config show`). A benchmark
scans every file, so the `all-files` profile strips each tool's global path allowlist and nothing else: gitleaks'
`[allowlist] paths` (images, lock files, `node_modules/`, `vendor/` and so on) and Betterleaks' `prefilter`, the same
patterns as a CEL expression. Rule-level path conditions are part of the rules and stay. `scanner-defaults` runs the
default config. Validation of found secrets against live services is never enabled: Betterleaks does it only with
`--validation`, gitleaks not at all.

The tools read a shard of files and write a JSON report. dsbench copies each shard's files to their view paths rather
than linking them, because both tools resolve a symlink and give their path-aware rules the corpus's flat file name; the
copies are deleted once the shard is stored. Each tool process gets `GOMAXPROCS=1`, so `--cores` is the number of busy
CPUs, as with DeepSecrets.

A report entry gives the rule, the match (`Match`), the secret inside it (`Secret`, the part a rule captures) and the
match's line and columns. The columns are not the same convention in both tools (gitleaks' are one more), so a
finding's region is estimated from them and the secret's place in the match, and the `located` matcher then finds the
secret itself on those lines. A secret not in its match (decoded from base64, say) is located as the match. Betterleaks
grades each finding `low`, `medium` or `high`, which becomes its tier; gitleaks has no grades, so its findings carry
the tier `none` and count at every level."""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from dsbench.sarif import Report, Result

MARKER = '.dsbench-tool.json'
UNTIERED = 'none'


class ThirdPartyError(Exception):
    pass


@dataclass(frozen=True)
class Release:
    name: str
    version: str
    url: str
    sha256: str
    binary: str
    config_url: Optional[str] = None
    config_sha256: Optional[str] = None
    # the columns a report gives are this much more than 1-based ones
    column_shift: int = 0


RELEASES: Dict[str, Release] = {
    'gitleaks': Release(
        name='gitleaks',
        version='8.30.1',
        url='https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
        sha256='551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
        binary='gitleaks',
        config_url='https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml',
        config_sha256='e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf',
        column_shift=1,
    ),
    'betterleaks': Release(
        name='betterleaks',
        version='1.8.1',
        url='https://github.com/betterleaks/betterleaks/releases/download/v1.8.1/betterleaks_1.8.1_linux_x64.tar.gz',
        sha256='efa407244e1ea8e35f582b8a42becdeac08bdead04f68eb752adda722d583c2a',
        binary='betterleaks',
    ),
}


def tool_dir(cache: Path, release: Release) -> Path:
    return cache / 'tools' / f'{release.name}-{release.version}'


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=300) as response:
            return response.read()
    except OSError as e:
        raise ThirdPartyError(f'cannot download {url}: {e}') from None


def strip_path_allowlist(name: str, config: str) -> str:
    """The config with its global path allowlist removed, and nothing else."""
    if name == 'gitleaks':
        start = config.index('[allowlist]')
        end = config.find('\n[', start + 1)
        end = len(config) if end == -1 else end
        section, n = re.subn(r"(?ms)^paths = \[\n.*?^\]\n", '', config[start:end], count=1)
        stripped = config[:start] + section + config[end:]
        if n != 1 or 'paths' in tomllib.loads(stripped).get('allowlist', {}):
            raise ThirdPartyError('gitleaks config: no global path allowlist where one was expected')
    else:
        stripped, n = re.subn(r"(?ms)^prefilter = '''\n.*?^'''\n", '', config, count=1)
        if n != 1 or 'prefilter' in tomllib.loads(stripped):
            raise ThirdPartyError('betterleaks config: no global prefilter where one was expected')
    return stripped


def fetch(name: str, cache: Path, download=_download) -> Path:
    """The release unpacked into the cache, checked against its pinned digests; once."""
    release = RELEASES[name]
    target = tool_dir(cache, release)
    if (target / MARKER).is_file():
        return target
    archive = download(release.url)
    if _sha256(archive) != release.sha256:
        raise ThirdPartyError(f'{release.url}: SHA-256 {_sha256(archive)} is not the pinned {release.sha256}')
    staging = target.with_name(target.name + '.partial')
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        member = tar.getmember(release.binary)
        tar.extract(member, staging, filter='data')
    binary = staging / release.binary
    binary.chmod(0o755)
    if release.config_url:
        config = download(release.config_url)
        if _sha256(config) != release.config_sha256:
            raise ThirdPartyError(f'{release.config_url}: SHA-256 is not the pinned {release.config_sha256}')
        default = config.decode('utf-8')
    else:
        done = subprocess.run([str(binary), 'config', 'show'], capture_output=True, text=True, timeout=120)
        if done.returncode:
            raise ThirdPartyError(f'{release.name} config show exited {done.returncode}')
        default = done.stdout
    (staging / 'default.toml').write_text(default)
    (staging / 'all-files.toml').write_text(strip_path_allowlist(release.name, default))
    version = subprocess.run([str(binary), 'version'], capture_output=True, text=True, timeout=60).stdout.strip()
    if version.lstrip('v') != release.version:
        raise ThirdPartyError(f'{release.name} reports version {version!r}, not {release.version}')
    marker = {
        'name': release.name,
        'version': release.version,
        'url': release.url,
        'sha256': release.sha256,
        'binary_sha256': _sha256(binary.read_bytes()),
        'default_config_sha256': _sha256((staging / 'default.toml').read_bytes()),
        'all_files_config_sha256': _sha256((staging / 'all-files.toml').read_bytes()),
        'fetched_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    }
    (staging / MARKER).write_text(json.dumps(marker, indent=2) + '\n')
    if target.exists():
        shutil.rmtree(target)
    staging.rename(target)
    return target


def config_for(profile: str) -> str:
    return 'all-files.toml' if profile == 'all-files' else 'default.toml'


def args(binary: str, config: Path, target: Path, report: Path) -> List[str]:
    return [
        binary,
        'dir',
        str(target),
        '--config',
        str(config),
        '--report-format',
        'json',
        '--report-path',
        str(report),
        '--exit-code',
        '0',
        '--no-banner',
        '--log-level',
        'error',
    ]


def _region(entry: Dict, shift: int) -> Dict:
    """The secret's estimated region and text: its place inside the match, from the match's line and column."""
    match, secret = entry.get('Match') or '', entry.get('Secret') or ''
    line, col = entry.get('StartLine'), (entry.get('StartColumn') or 1) - shift
    at = match.find(secret) if secret else -1
    value = secret if at >= 0 else match
    before = match[:at] if at >= 0 else ''
    if '\n' in before:
        line += before.count('\n')
        col = len(before) - before.rindex('\n')
    else:
        col += len(before)
    end_line = line + value.count('\n')
    end_col = len(value) - value.rindex('\n') if '\n' in value else col + len(value)
    return {'start_line': line, 'end_line': end_line, 'start_col': col, 'end_col': end_col, 'value': value}


def read_report(path: Path, target: Path, release: Release) -> Report:
    try:
        entries = json.loads(path.read_text(encoding='utf-8')) or []
    except (OSError, ValueError) as e:
        from dsbench.sarif import SarifError

        raise SarifError(f'{path}: {e.__class__.__name__}') from None
    report = Report(tool_name=release.name, tool_version=release.version)
    for entry in entries:
        location = entry.get('File') or ''
        uri = os.path.relpath(location, target) if os.path.isabs(location) else location
        region = _region(entry, release.column_shift)
        confidence = ((entry.get('Attributes') or {}).get('confidence') or '').lower()
        report.results.append(
            Result(
                uri=uri,
                rule_id=entry.get('RuleID') or '',
                rule_base=entry.get('RuleID') or '',
                confidence=None,
                fingerprint=entry.get('Fingerprint'),
                tier=confidence if confidence in ('low', 'medium', 'high') else UNTIERED,
                **region,
            )
        )
    return report
