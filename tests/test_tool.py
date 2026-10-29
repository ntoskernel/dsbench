import json
import subprocess
from pathlib import Path

import pytest

from dsbench import tool


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A stand-in scanner checkout: a package, its diagnostics package and a pyproject, committed and tagged."""
    root = tmp_path / 'scanner'
    (root / 'deepsecrets' / 'diagnostics').mkdir(parents=True)
    (root / 'deepsecrets' / '__init__.py').write_text('VERSION = 1\n')
    (root / 'deepsecrets' / 'rules.json').write_text('[]\n')
    (root / 'deepsecrets' / 'diagnostics' / 'trace.py').write_text('SCHEMA = 5\n')
    (root / 'pyproject.toml').write_text('[project]\nname = "deepsecrets"\nversion = "9.1.0"\n')
    git(root, 'init', '-q')
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'first')
    git(root, 'tag', 'v9.1.0')
    return root


def test_profiles():
    assert tool.PROFILES['all-files'] == ['--excluded-paths', 'disable']
    assert tool.PROFILES['scanner-defaults'] == []
    assert tool.resolve_profile('default') == 'scanner-defaults'
    assert tool.profile_scans_every_file('all-files') and not tool.profile_scans_every_file('default')
    with pytest.raises(tool.ToolError):
        tool.resolve_profile('fast')


def test_the_digest_follows_the_package_but_not_its_diagnostics_or_bytecode(repo: Path):
    before = tool.source_digest(repo)
    (repo / 'deepsecrets' / 'diagnostics' / 'trace.py').write_text('SCHEMA = 6\n')
    (repo / 'deepsecrets' / '__pycache__').mkdir()
    (repo / 'deepsecrets' / '__pycache__' / 'x.cpython-313.pyc').write_bytes(b'\0')
    (repo / 'README.md').write_text('outside the package\n')
    assert tool.source_digest(repo) == before
    (repo / 'deepsecrets' / 'rules.json').write_text('[{}]\n')
    assert tool.source_digest(repo) != before
    assert tool.source_digest(repo / 'deepsecrets') is None


def test_commit_and_dirty(repo: Path):
    head = git(repo, 'rev-parse', '--short', 'HEAD')
    assert tool.tool_commit(repo) == head
    (repo / 'deepsecrets' / 'new.py').write_text('')
    assert tool.tool_commit(repo) == f'{head}-dirty'
    assert tool.tool_version(repo) == '9.1.0'


def test_a_ref_is_extracted_once_with_its_commit(repo: Path, tmp_path: Path):
    cache = tmp_path / 'cache'
    tree = tool.extract_ref(repo, 'v9.1.0', cache)
    assert tree == cache / 'trees' / 'v9.1.0'
    assert (tree / 'deepsecrets' / '__init__.py').read_text() == 'VERSION = 1\n'
    assert not (tree / '.git').exists()
    marker = json.loads((tree / tool.TREE_MARKER).read_text())
    assert marker['commit'] == git(repo, 'rev-parse', 'v9.1.0^{commit}') and marker['ref'] == 'v9.1.0'
    assert tool.source_digest(tree) == tool.source_digest(repo) == marker['digest']
    assert tool.tool_commit(tree, tool.source_digest(tree)) == marker['commit'][:7]

    (repo / 'deepsecrets' / '__init__.py').write_text('VERSION = 2\n')
    git(repo, 'commit', '-qam', 'second')
    assert tool.extract_ref(repo, 'v9.1.0', cache) == tree  # reused, not re-extracted
    (tree / 'deepsecrets' / '__init__.py').write_text('VERSION = 3\n')
    assert tool.tool_commit(tree, tool.source_digest(tree)).endswith('-dirty')
    with pytest.raises(tool.ToolError):
        tool.extract_ref(repo, 'no-such-ref', cache)
    assert tool.tree_dir(cache, 'feature/x') == cache / 'trees' / 'feature_x'


def test_the_command_line_and_environment(repo: Path, monkeypatch):
    t = tool.resolve_tool(repo, cmd='scanner --flag', profile='all-files')
    assert t.cmd == ('scanner', '--flag') and t.version == '9.1.0' and t.digest == tool.source_digest(repo)
    args = t.args(Path('/t'), Path('/r.sarif'), 1)
    assert args[:2] == ['scanner', '--flag']
    for flag in ('--report-diagnostics', '--disable-masking'):
        assert flag in args
    assert args[args.index('--target-dir') + 1] == '/t' and args[args.index('--outfile') + 1] == '/r.sarif'
    assert args[args.index('--process-count') + 1] == '1' and args[args.index('--outformat') + 1] == 'sarif'
    assert args[-2:] == ['--excluded-paths', 'disable']
    assert '--excluded-paths' not in tool.resolve_tool(repo, cmd='scanner', profile='default').args(
        Path('/t'), Path('/r'), 1
    )

    monkeypatch.setenv('VIRTUAL_ENV', '/venvs/dsbench')
    monkeypatch.setenv('PATH', '/venvs/dsbench/bin:/usr/bin')
    monkeypatch.setenv('PYTHONPATH', '/somewhere')
    env = t.env()
    assert 'VIRTUAL_ENV' not in env and 'PYTHONPATH' not in env and env['PATH'] == '/usr/bin'


def test_the_default_command_runs_the_package_from_the_tool_directory(repo: Path):
    t = tool.resolve_tool(repo)
    assert t.cmd[1:] == ('-W', 'ignore', '-m', 'deepsecrets')
    assert tool.check_module(t) == str(repo / 'deepsecrets')
    assert tool.check_module(tool.resolve_tool(repo, cmd='other')) is None
    with pytest.raises(tool.ToolError):
        tool.resolve_tool(repo / 'deepsecrets')
