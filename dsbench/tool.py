"""The scanner under test, as a subprocess. Nothing here imports DeepSecrets.

By default the scanner is `python -W ignore -m deepsecrets` run from its checkout (`--tool-cwd`, else
`$DSBENCH_TOOL_CWD`) with `places.tool_python()`; `--tool-cmd` replaces the command. `--tool-ref REF` runs a ref's
committed tree instead: `git archive REF` extracted once into `$DSBENCH_CACHE/trees/<REF>/`, with a marker recording
the commit and the digest it had when extracted. Such a tree runs with the same interpreter as the checkout, so that
interpreter must hold the dependencies the ref's `poetry.lock` pins; DeepSecrets 2.2.0 and later share one lock.

A run records what it measured: the scanner's version (its `pyproject.toml`), the commit (suffixed `-dirty` when
anything under `deepsecrets/` differs from it) and a digest of the package source that leaves out
`deepsecrets/diagnostics/`, which no scan imports. The profile decides the scope: `all-files` (the default, and the
only profile whose numbers are quoted) passes `--excluded-paths disable`, `scanner-defaults` passes nothing."""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dsbench.places import tool_python

PROFILES: Dict[str, List[str]] = {
    # every file is scanned: SecretBench labels secrets in node_modules/ and vendor/ too
    'all-files': ['--excluded-paths', 'disable'],
    # DeepSecrets' own defaults, built-in path exclusions included; a scope, never a benchmark result
    'scanner-defaults': [],
}
DEFAULT_PROFILE = 'all-files'
PROFILE_ALIASES = {'default': 'scanner-defaults'}
PACKAGE = 'deepsecrets'
DIGEST_EXCLUDE = ('deepsecrets/diagnostics/',)
TREE_MARKER = '.dsbench-tree.json'


class ToolError(Exception):
    pass


def resolve_profile(name: str) -> str:
    profile = PROFILE_ALIASES.get(name, name)
    if profile not in PROFILES:
        raise ToolError(f'unknown profile {name!r}; known: {", ".join(PROFILES)}')
    return profile


def profile_scans_every_file(name: str) -> bool:
    return '--excluded-paths' in PROFILES[resolve_profile(name)]


def _git(cwd: Path, *args: str) -> Optional[str]:
    try:
        done = subprocess.run(['git', '-C', str(cwd), *args], capture_output=True, text=True, timeout=120)
    except OSError:
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def source_digest(cwd: Path) -> Optional[str]:
    """sha256 over the package's files (paths and bytes), the diagnostics package and bytecode left out."""
    package = cwd / PACKAGE
    if not package.is_dir():
        return None
    digest = hashlib.sha256()
    paths = []
    for root, dirs, names in os.walk(package):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in names:
            if name.endswith(('.pyc', '.pyo')):
                continue
            rel = Path(root, name).relative_to(cwd).as_posix()
            if not rel.startswith(DIGEST_EXCLUDE):
                paths.append(rel)
    for rel in sorted(paths):
        digest.update(rel.encode('utf-8', 'surrogateescape') + b'\0')
        digest.update((cwd / rel).read_bytes())
        digest.update(b'\0')
    return digest.hexdigest()


def tool_version(cwd: Path) -> Optional[str]:
    try:
        meta = tomllib.loads((cwd / 'pyproject.toml').read_text(encoding='utf-8'))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return (meta.get('project') or {}).get('version') or ((meta.get('tool') or {}).get('poetry') or {}).get('version')


def tool_commit(cwd: Path, digest: Optional[str] = None) -> Optional[str]:
    """The checkout's short commit, `-dirty` when its package differs; for an extracted tree, the ref's commit,
    `-dirty` when its digest no longer equals the one recorded at extraction."""
    marker = cwd / TREE_MARKER
    toplevel = _git(cwd, 'rev-parse', '--show-toplevel')
    if toplevel and Path(toplevel).resolve() == cwd.resolve():
        head = _git(cwd, 'rev-parse', '--short', 'HEAD')
        if head is None:
            return None
        status = _git(cwd, 'status', '--porcelain', '--', PACKAGE)
        return head + ('-dirty' if status else '')
    if marker.is_file():
        recorded = json.loads(marker.read_text())
        changed = digest is not None and digest != recorded.get('digest')
        return recorded['commit'][:7] + ('-dirty' if changed else '')
    return None


@dataclass(frozen=True)
class Tool:
    cmd: Tuple[str, ...]
    cwd: Path
    profile: str
    version: Optional[str]
    commit: Optional[str]
    digest: Optional[str]
    ref: Optional[str] = None

    def args(self, target: Path, report: Path, process_count: int) -> List[str]:
        return [
            *self.cmd,
            '--target-dir',
            str(target),
            '--outfile',
            str(report),
            '--outformat',
            'sarif',
            '--report-diagnostics',
            '--disable-masking',
            '--process-count',
            str(process_count),
            *PROFILES[self.profile],
        ]

    def env(self) -> Dict[str, str]:
        """The caller's environment without dsbench's own venv, so the scanner gets its interpreter's packages."""
        env = dict(os.environ)
        venv = env.pop('VIRTUAL_ENV', None)
        if venv:
            bin_dir = str(Path(venv) / 'bin')
            env['PATH'] = os.pathsep.join(d for d in env.get('PATH', '').split(os.pathsep) if d and d != bin_dir)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONHOME', None)
        return env

    def describe(self) -> Dict:
        return {
            'cmd': shlex.join(self.cmd),
            'cwd': str(self.cwd),
            'profile': self.profile,
            'version': self.version,
            'commit': self.commit,
            'digest': self.digest,
            'ref': self.ref,
        }


def resolve_tool(
    cwd: Path, cmd: Optional[str] = None, profile: str = DEFAULT_PROFILE, ref: Optional[str] = None
) -> Tool:
    cwd = cwd.resolve()
    if not cwd.is_dir():
        raise ToolError(f'tool directory {cwd} does not exist')
    if cmd:
        argv = tuple(shlex.split(cmd))
    else:
        if not (cwd / PACKAGE).is_dir():
            raise ToolError(f'{cwd} holds no {PACKAGE}/ package; pass --tool-cwd or --tool-cmd')
        argv = (tool_python(), '-W', 'ignore', '-m', PACKAGE)
    digest = source_digest(cwd)
    return Tool(
        cmd=argv,
        cwd=cwd,
        profile=resolve_profile(profile),
        version=tool_version(cwd),
        commit=tool_commit(cwd, digest),
        digest=digest,
        ref=ref,
    )


def check_module(tool: Tool) -> Optional[str]:
    """Where the scanner's interpreter imports the package from, in a child process; None for a custom command.
    A scan of a tree must not silently run another installation."""
    if tool.cmd[1:] != ('-W', 'ignore', '-m', PACKAGE):
        return None
    done = subprocess.run(
        [tool.cmd[0], '-c', f'import os, {PACKAGE}; print(os.path.dirname({PACKAGE}.__file__))'],
        cwd=tool.cwd,
        env=tool.env(),
        capture_output=True,
        text=True,
        timeout=300,
    )
    if done.returncode:
        raise ToolError(f'{tool.cmd[0]} cannot import {PACKAGE} in {tool.cwd}')
    where = Path(done.stdout.strip().splitlines()[-1]).resolve()
    if where != (tool.cwd / PACKAGE).resolve():
        raise ToolError(f'{tool.cmd[0]} imports {PACKAGE} from {where}, not from {tool.cwd}')
    return str(where)


def tree_dir(cache: Path, ref: str) -> Path:
    return cache / 'trees' / re.sub(r'[^A-Za-z0-9._-]', '_', ref)


def extract_ref(repo: Path, ref: str, cache: Path) -> Path:
    """The committed tree of `ref`, extracted once with `git archive`; later calls reuse it."""
    target = tree_dir(cache, ref)
    if (target / TREE_MARKER).is_file():
        return target
    commit = _git(repo, 'rev-parse', '--verify', f'{ref}^{{commit}}')
    if not commit:
        raise ToolError(f'{ref} is not a commit in {repo}')
    staging = target.with_name(target.name + '.partial')
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    with subprocess.Popen(['git', '-C', str(repo), 'archive', '--format=tar', commit], stdout=subprocess.PIPE) as proc:
        with tarfile.open(fileobj=proc.stdout, mode='r|') as archive:
            archive.extractall(staging, filter='data')
    if proc.returncode:
        raise ToolError(f'git archive {ref} exited {proc.returncode}')
    marker = {
        'ref': ref,
        'commit': commit,
        'repo': str(repo),
        'digest': source_digest(staging),
        'extracted_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    }
    (staging / TREE_MARKER).write_text(json.dumps(marker, indent=2) + '\n')
    if target.exists():
        shutil.rmtree(target)
    staging.rename(target)
    return target
