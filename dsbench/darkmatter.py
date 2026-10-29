"""Dark matter: what scanners report outside the labels, and the verdicts that say what it is.

A finding paired with no label is an extra. Extras are counted per unit: one unit per repository and normalised value
(`counting.unit_value`), so a secret copied into many files of a repository is one unit. A file the dataset records
no repository for is its own pseudo-repository (`file:<id>`), so the same value in several such files is several
units.

The overlay is the judged part: `overlays/dark_matter_labels.csv` in the bench home, one verdict per unit, keyed by
the repository and the SHA-256 of the normalised value, so it holds no value and carries to every later run; only
units it does not know need judging. Its classes:

    live              a credential for a real system                                  secret in kind
    test_credential   real-looking, serves tests, examples, docs, local development   secret in kind
    copy_of_labelled  the same value is labelled Y elsewhere in the dataset          secret in kind
    publishable       public by design, or shipped inside client software            not a secret
    placeholder       a dummy or default value                                       not a secret
    not_secret        an identifier, hash, public key, data, UI text                 not a secret
    unclear           undecidable offline                                            left out"""

import csv
import hashlib
import json as _json
import math
import re
import zlib
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import duckdb

from dsbench import counting
from dsbench.home import BenchHome
from dsbench.located import read_text

OVERLAY = 'dark_matter_labels.csv'
OVERLAY_FIELDS = ['repo', 'value_sha256', 'verdict', 'source', 'judged_at']
SECRET = ('live', 'test_credential', 'copy_of_labelled')
NOISE = ('publishable', 'placeholder', 'not_secret')
CLASSES = SECRET + NOISE + ('unclear',)

Unit = Tuple[str, str]


class DarkMatterError(Exception):
    pass


def value_sha256(normalised: str) -> str:
    return hashlib.sha256(normalised.encode('utf-8', 'surrogatepass')).hexdigest()


def unit_key(repo: Optional[str], file_id: str, value: Optional[str]) -> Unit:
    """A unit beyond the labels: its repository (or the file's pseudo-repository) and the hash of its value."""
    return (repo or f'file:{file_id}', value_sha256(counting.unit_value(value)))


def overlay_path(home: BenchHome) -> Path:
    return home.overlays_dir / OVERLAY


def load_overlay(home: BenchHome) -> Optional[Dict[Unit, str]]:
    """The judged units, or None when the bench home holds no overlay."""
    path = overlay_path(home)
    if not path.is_file():
        return None
    verdicts = {}
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row['verdict'] not in CLASSES:
                raise DarkMatterError(f"{path}: unknown verdict {row['verdict']!r}")
            verdicts[(row['repo'], row['value_sha256'])] = row['verdict']
    return verdicts


def write_overlay(home: BenchHome, rows: Iterable[Dict]) -> int:
    path = overlay_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_suffix('.tmp')
    count = 0
    with open(staged, 'w', newline='', encoding='utf-8') as f:
        out = csv.DictWriter(f, OVERLAY_FIELDS)
        out.writeheader()
        for row in sorted(rows, key=lambda r: (r['repo'], r['value_sha256'])):
            out.writerow({k: row.get(k) for k in OVERLAY_FIELDS})
            count += 1
    staged.replace(path)
    return count


def extra_units(
    con: duckdb.DuckDBPyConnection, run: Dict, rank_sql: str, scope: Optional[Set[str]] = None
) -> Dict[Unit, int]:
    """The run's units beyond the labels: each unpaired finding's unit, at the best tier rank that reports it."""
    rows = con.execute(
        f'''SELECT x.file_id, fl.repo, x.value, {rank_sql} FROM findings x
            JOIN files fl ON fl.dataset_id = ? AND fl.file_id = x.file_id
            WHERE x.run_id = ? AND x.finding_id NOT IN
                (SELECT finding_id FROM matches WHERE run_id = ? AND matcher = 'located')''',
        [run['dataset_id'], run['run_id'], run['run_id']],
    ).fetchall()
    units: Dict[Unit, int] = {}
    for file_id, repo, value, rank in rows:
        if rank is None or (scope is not None and file_id not in scope):
            continue
        key = unit_key(repo, file_id, value)
        units[key] = max(units.get(key, -1), rank)
    return units


def classify(units: Dict[Unit, int], overlay: Dict[Unit, str]) -> Dict[str, List[Unit]]:
    """The units in the overlay's terms: secret, noise, unclear or unjudged."""
    out: Dict[str, List[Unit]] = {'secret': [], 'noise': [], 'unclear': [], 'unjudged': []}
    for key in units:
        verdict = overlay.get(key)
        side = (
            'unjudged'
            if verdict is None
            else 'secret' if verdict in SECRET else 'noise' if verdict in NOISE else 'unclear'
        )
        out[side].append(key)
    return out


# ---------------------------------------------------------------- the pipeline up to judging

RUBRIC = """Judge each unit from its evidence alone, offline: never look a value up or try it. Give one class:

live              a credential for a real system: production, staging or a real test environment someone runs
test_credential   real-looking but serving tests, examples, documentation, local development or benchmarks
copy_of_labelled  the same value is labelled a secret elsewhere in the dataset (rules settle most of these)
publishable       public by design or shipped inside client software: reCAPTCHA site keys, Algolia search-only
                  keys, Stripe pk_ keys, Firebase and Maps web keys, keys inside distributed apps
placeholder       a dummy or default value: example, changeme, xxxx, your-key-here, sequences
not_secret        an identifier, hash, digest, public key, UUID, version, file name, data or UI text
unclear           cannot be decided offline from this evidence

Policies: framework secrets committed as a project's defaults (a Django SECRET_KEY, session secrets) and shipped
product defaults are test_credential unless there is evidence of production use. Book and tutorial sample code is
test_credential; a deployment of a real test or staging environment is live. An AWS secret stays live even inside a
desktop app: it is never public by design.

Placeholder or test_credential: a value that is visibly fake or trivial (words, repeated or sequential characters, a
short value of low entropy) is placeholder wherever it is. A random-looking value that serves tests, examples or
development is test_credential, with one exception that follows the dataset: an example in documentation or an API
specification (a README, docs pages, OpenAPI or Swagger files, SDK samples) in a file whose labels are only N, or that
has no labels, is placeholder however realistic it looks; in a file with a Y label it is test_credential. Crypto test
vectors in files labelled only N are not_secret. Data that is not a credential (pagination, continuation or skip
tokens, cursors, booking or order references, request signatures, public verification keys) is not_secret, in
examples too.

Keys whose kind the format shows: an extended public key (formats: bip32_public) or a hex public key
(ec_public_key_hex) is not_secret; an extended private key (bip32_private) is test_credential in tests and examples,
and live otherwise.

copy_of_labelled: rules settle the exact copies of labelled values before judging, and a sheet does not show labels
elsewhere. Do not give it on a sheet."""

# characters of the line shown on each side of a value
CONTEXT = 200
# the shapes that settle a unit without judging: a file name, a path or a version
_FILE_NAME = re.compile(
    r'^[\w.@~-]*\w\.(?:js|jsx|ts|tsx|py|rb|go|java|kt|php|cs|cpp|c|h|hpp|m|swift|scala|rs|sh|bat|ps1|json|ya?ml|xml|'
    r'toml|ini|cfg|conf|properties|env|txt|md|rst|html?|css|scss|less|svg|png|jpe?g|gif|ico|woff2?|ttf|eot|map|lock|'
    r'gz|zip|tar|jar|war|dll|so|exe|pdf|csv|sql|db|log|pem|crt|key|pub|p12|pfx|jks|keystore|gradle|plist)$',
    re.IGNORECASE,
)
_PATH = re.compile(r'^(?:\.{0,2}/)?(?:[\w.@~-]+/)+[\w.@~-]*$')
_VERSION = re.compile(r'^v?\d+(?:\.\d+){1,3}(?:[-+.][\w.]+)?$')
_PLACEHOLDER = re.compile(
    r'example|sample|dummy|placeholder|changeme|change_me|your[_-]?(?:api|key|secret|token|password)|xxxx|test|fake|'
    r'demo|default|secret|password|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}',
    re.IGNORECASE,
)
_PATH_CLASSES = [
    (
        'test',
        re.compile(
            r'(?:^|/)(?:tests?|spec|specs|__tests__|testing|fixtures?|mocks?|testdata)(?:/|$)|[._-](?:test|spec)\.',
            re.I,
        ),
    ),
    ('example', re.compile(r'(?:^|/)(?:examples?|samples?|demos?|tutorials?)(?:/|$)|example', re.I)),
    ('docs', re.compile(r'(?:^|/)(?:docs?|documentation)(?:/|$)|\.(?:md|rst|adoc|txt)$|readme', re.I)),
    (
        'vendor',
        re.compile(r'(?:^|/)(?:vendor|node_modules|third[_-]?party|bower_components|site-packages)(?:/|$)', re.I),
    ),
    ('ci', re.compile(r'(?:^|/)\.github/workflows/|\.travis\.yml$|\.gitlab-ci\.yml$|jenkinsfile|\.circleci/', re.I)),
    (
        'config',
        re.compile(r'\.(?:env|ya?ml|ini|cfg|conf|properties|toml|json|xml|plist)$|(?:^|/)(?:settings|config)', re.I),
    ),
]
_NAME = re.compile(r'([A-Za-z_][\w.-]{0,80})\W{0,3}\s*(?:[:=]|=>|:=)\s*\W{0,3}$')
_RANDOM_TOKEN = re.compile(r'[A-Za-z0-9+/=_-]{8,}')
_BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def charset(value: str) -> str:
    if re.fullmatch(r'[0-9]+', value):
        return 'digits'
    if re.fullmatch(r'[0-9a-f]+', value) or re.fullmatch(r'[0-9A-F]+', value):
        return 'hex'
    if re.fullmatch(r'[A-Za-z0-9]+', value):
        return 'alnum'
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value):
        return 'base64'
    if re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', value):
        return 'base64url'
    return 'mixed'


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def mask(value: str) -> str:
    """A value as an annotator sees it: its charset, length and entropy, never a character of it."""
    return f'<{charset(value)}:{len(value)}:{entropy(value):.1f}>'


def masked_line(line: str, value: str, others: Iterable[str] = ()) -> str:
    """The line with the value, every other known value (`others`, longest first: those reported or labelled in the
    file and every value labelled real) and every other random-looking token (8 characters or more, with a digit)
    replaced by its mask."""
    marks = {}

    def hold(text: str) -> str:
        marks[f'\x00{len(marks)}\x00'] = text
        return f'\x00{len(marks) - 1}\x00'

    if value:
        line = line.replace(value, hold(f'<VALUE {mask(value)}>'))
    for other in others:  # longest first
        if other != value and other in line:
            line = line.replace(other, hold(mask(other)))
    line = _RANDOM_TOKEN.sub(lambda m: mask(m.group()) if re.search(r'\d', m.group()) else m.group(), line)
    for placeholder, text in marks.items():
        line = line.replace(placeholder, text)
    return line[: 2 * CONTEXT + 100]


def _github_checksum_ok(value: str) -> Optional[bool]:
    m = re.fullmatch(r'gh[pousr]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})', value)
    if not m:
        return None
    crc, digits = zlib.crc32(m.group(1).encode()), ''
    while crc:
        crc, r = divmod(crc, 62)
        digits = _BASE62[r] + digits
    return digits.rjust(6, '0') == m.group(2)


def _jwt(value: str) -> Optional[Dict]:
    import base64

    parts = value.split('.')
    if len(parts) != 3 or not value.startswith('ey'):
        return None
    try:
        header = _json.loads(base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4)))
        claims = _json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
    except ValueError:
        return {'decodes': False}
    return {
        'decodes': True,
        'alg': header.get('alg'),
        'claims': sorted(claims)[:12] if isinstance(claims, dict) else [],
    }


def _pem(value: str) -> Optional[Dict]:
    import base64

    m = re.search(r'-----BEGIN ([A-Z ]+)-----(.*?)-----END', value.replace('\\n', '\n'), re.S)
    if not m:
        return None
    body = re.sub(r'[^A-Za-z0-9+/=]', '', m.group(2))
    try:
        der = base64.b64decode(body + '=' * (-len(body) % 4))
    except ValueError:
        return {'kind': m.group(1), 'der': False}
    return {'kind': m.group(1), 'der': der[:1] == b'\x30', 'bytes': len(der)}


def formats(value: str) -> Dict:
    """Provider formats a value has, with the offline checks they allow."""
    out = {}
    checks = {
        'aws_key_id': r'(?:AKIA|ASIA)[A-Z0-9]{16}',
        'slack_token': r'xox[abposr]-[A-Za-z0-9-]{10,}',
        'stripe_secret': r'(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}',
        'stripe_publishable': r'pk_(?:live|test)_[A-Za-z0-9]{10,}',
        'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
        'uuid': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'hex_digest': r'[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}',
        # the mask hides the prefix that tells a private extended key from a public one, and a public key from a secret
        'bip32_private': r'[xyztuvYZUV]prv[1-9A-HJ-NP-Za-km-z]{107,108}',
        'bip32_public': r'[xyztuvYZUV]pub[1-9A-HJ-NP-Za-km-z]{107,108}',
        'ec_public_key_hex': r'0[23][0-9a-fA-F]{64}|04[0-9a-fA-F]{128}',
        'url_with_credentials': r'[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@\S+',
    }
    for name, pattern in checks.items():
        if re.fullmatch(pattern, value):
            out[name] = True
    github = _github_checksum_ok(value)
    if github is not None:
        out['github_token_checksum_ok'] = github
    for name, check in (('jwt', _jwt), ('pem', _pem)):
        found = check(value)
        if found is not None:
            out[name] = found
    return out


def settled_by_rule(
    normalised: str, value: str, labelled_y: Set[str], labelled_n: Set[str]
) -> Optional[Tuple[str, str]]:
    """(verdict, rule) for a unit the dataset or its shape already decides."""
    if normalised in labelled_y and normalised not in labelled_n:
        return 'copy_of_labelled', 'labelled_y_elsewhere'
    if normalised in labelled_n and normalised not in labelled_y:
        return 'not_secret', 'labelled_n_elsewhere'
    stripped = value.strip('\'"`')
    if _FILE_NAME.match(stripped) or (_PATH.match(stripped) and '/' in stripped) or _VERSION.match(stripped):
        return 'not_secret', 'file_name_or_version'
    return None


def path_class(view_path: str) -> str:
    for name, pattern in _PATH_CLASSES:
        if pattern.search(view_path or ''):
            return name
    return 'code'


def _line(cache: Dict[str, List[str]], path: str, number: Optional[int]) -> str:
    if path not in cache:
        try:
            cache.clear()  # one file at a time: findings come sorted by file
            cache[path] = read_text(path).split('\n')
        except OSError:
            cache[path] = []
    lines = cache[path]
    return lines[number - 1] if number and 0 < number <= len(lines) else ''


def build_units(con: duckdb.DuckDBPyConnection, run_ids: List[str], rank_sql: str) -> Tuple[List[Dict], Dict]:
    """Every finding of the runs that matches no label, grouped into units: one per repository and normalised value,
    merged where findings of the runs overlap on a line. Values stay in memory only."""
    runs = [con.execute('SELECT run_id, dataset_id FROM runs WHERE run_id = ?', [r]).fetchone() for r in run_ids]
    if any(r is None for r in runs) or len({r[1] for r in runs}) > 1:
        raise DarkMatterError('the runs must exist and be of one dataset')
    dataset_id = runs[0][1]
    findings = con.execute(
        f'''SELECT x.run_id, x.finding_id, x.file_id, fl.repo, fl.view_path, x.start_line, x.end_line, x.start_col,
                   x.end_col, x.value, x.rule_base, {rank_sql}
            FROM findings x JOIN files fl ON fl.dataset_id = ? AND fl.file_id = x.file_id
            WHERE x.run_id IN (SELECT unnest(?)) AND x.tier IS DISTINCT FROM 'info'
              AND NOT EXISTS (SELECT 1 FROM matches m WHERE m.run_id = x.run_id AND m.finding_id = x.finding_id
                              AND m.matcher = 'located')
            ORDER BY x.file_id, x.start_line, x.start_col''',
        [dataset_id, run_ids],
    ).fetchall()
    parent: Dict[Unit, Unit] = {}

    def find(k: Unit) -> Unit:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    keyed = []
    by_file_line: Dict[Tuple[str, int], List[Tuple[Tuple, Unit]]] = defaultdict(list)
    for f in findings:
        run_id, fid, file_id, repo, view, sl, el, sc, ec, value, rule, rank = f
        key = unit_key(repo, file_id, value)
        parent.setdefault(key, key)
        span = ((sl or 0, sc or 0), (el or sl or 0, ec or 0))
        for other_span, other in by_file_line[(file_id, sl)]:
            if span[0] < other_span[1] and other_span[0] < span[1]:
                parent[find(key)] = find(other)
        by_file_line[(file_id, sl)].append((span, key))
        keyed.append((key, f))
    units: Dict[Unit, Dict] = {}
    for key, f in keyed:
        root = find(key)
        unit = units.setdefault(root, {'keys': set(), 'findings': []})
        unit['keys'].add(key)
        unit['findings'].append(f)
    return list(units.values()), {'findings': len(findings), 'dataset_id': dataset_id}


def export(
    con: duckdb.DuckDBPyConnection,
    home: BenchHome,
    run_ids: List[str],
    rank_sql: str,
    name: Optional[str] = None,
    per_sheet: int = 100,
) -> Dict:
    """Units, their evidence and the rule-settled verdicts into `darkmatter/<date>-<name>/`, and masked review sheets
    of every unit neither the overlay nor a rule decides. Stops where judging starts."""
    units, info = build_units(con, run_ids, rank_sql)
    dataset_id = info['dataset_id']
    files_dir = con.execute('SELECT files_dir FROM datasets WHERE dataset_id = ?', [dataset_id]).fetchone()[0]
    labels = con.execute(
        '''SELECT coalesce(f.scan_file_id, l.file_id), l.start_line, l.value, l.label
           FROM labels l LEFT JOIN files f ON f.dataset_id = l.dataset_id AND f.file_id = l.file_id
           WHERE l.dataset_id = ?''',
        [dataset_id],
    ).fetchall()
    labelled_y = {counting.unit_value(v) for _, _, v, y in labels if y}
    labelled_n = {counting.unit_value(v) for _, _, v, y in labels if not y}
    # every value known in a file, to keep it out of the context shown for another unit
    known_in: Dict[str, Set[str]] = defaultdict(set)
    for file_id, _, value, _ in labels:
        known_in[file_id].add(value)
    for file_id, value in con.execute(
        'SELECT file_id, value FROM findings WHERE run_id IN (SELECT unnest(?))', [run_ids]
    ).fetchall():
        known_in[file_id].add(value)
    # and every value labelled real anywhere: a copy of one may sit on the line of another unit
    real_values = {v for _, _, v, y in labels if y and v and len(v) >= 4}
    masks_for: Dict[str, List[str]] = {}
    in_file: Dict[str, Counter] = defaultdict(Counter)
    on_line: Dict[Tuple[str, int], Counter] = defaultdict(Counter)
    for file_id, line, _, y in labels:
        in_file[file_id]['Y' if y else 'N'] += 1
        on_line[(file_id, line)]['Y' if y else 'N'] += 1
    repos_of: Dict[str, Set[str]] = defaultdict(set)
    for unit in units:
        for repo, sha in unit['keys']:
            repos_of[sha].add(repo)
    overlay = load_overlay(home) or {}
    out_dir = home.root / 'darkmatter' / f"{date.today().isoformat()}-{name or 'units'}"
    (out_dir / 'sheets').mkdir(parents=True, exist_ok=True)
    tally = Counter()
    rules_rows, review, records = [], [], []
    cache: Dict[str, List[str]] = {}
    ordered = sorted(units, key=lambda u: min(u['keys']))
    for unit in ordered:
        # the shortest report is the secret itself; another tool may report the assignment around it
        unit['first'] = min(unit['findings'], key=lambda f: (len(f[9] or ''), run_ids.index(f[0])))
    # each file is read once: the evidence is gathered in file order, and written in unit order
    by_file = sorted(range(len(ordered)), key=lambda i: (ordered[i]['first'][2], ordered[i]['first'][5] or 0))
    for n in by_file:
        unit = ordered[n]
        first = unit['first']
        run_id, fid, file_id, repo, view, sl, el, sc, ec, value, rule, rank = first
        value = value or ''
        normalised = counting.unit_value(value)
        key = min(unit['keys'])
        unit_id = f'u{n:06d}'
        line = _line(cache, f'{files_dir}/{file_id}', sl)
        # a window around the value: minified lines run to megabytes
        at = max((sc or 1) - 1, 0)
        before = line[max(at - CONTEXT, 0) : at]
        line = before + line[at : at + len(value) + CONTEXT]
        name_match = _NAME.search(before) if before else None
        if file_id not in masks_for:
            masks_for.clear()
            known = {v for v in known_in.get(file_id, ()) if v and len(v) >= 4} | real_values
            masks_for[file_id] = sorted(known, key=len, reverse=True)
        name = name_match.group(1) if name_match else None
        if name is not None and (name in known_in.get(file_id, ()) or name in real_values):
            name = mask(name)
        evidence = {
            'unit_id': unit_id,
            'repo': key[0],
            'value_sha256': key[1],
            'keys': sorted(map(list, unit['keys'])),
            'runs': sorted({f[0] for f in unit['findings']}),
            'findings': len(unit['findings']),
            'rules': sorted({f[10] for f in unit['findings'] if f[10]}),
            'best_tier_rank': max((f[11] for f in unit['findings'] if f[11] is not None), default=None),
            'path_class': path_class(view),
            'view_path': view,
            'line': sl,
            'name': name,
            'value': mask(value),
            'context': masked_line(line, value, masks_for[file_id]),
            'charset': charset(value),
            'length': len(value),
            'entropy': round(entropy(value), 2),
            'placeholder_words': bool(_PLACEHOLDER.search(value)),
            'formats': formats(value),
            'repositories_with_value': len(repos_of[key[1]]),
            'labels_in_file': dict(in_file.get(file_id, {})),
            'labels_on_line': dict(on_line.get((file_id, sl), {})),
            'labelled_elsewhere': {'Y': normalised in labelled_y, 'N': normalised in labelled_n},
        }
        settled = settled_by_rule(normalised, value, labelled_y, labelled_n)
        known = overlay.get(key)
        if known:
            evidence['verdict'], evidence['verdict_source'] = known, 'overlay'
            tally['in_overlay'] += 1
        elif settled:
            evidence['verdict'], evidence['verdict_source'] = settled[0], f'rule:{settled[1]}'
            tally[f'rule:{settled[1]}'] += 1
            rules_rows.append(
                {'repo': key[0], 'value_sha256': key[1], 'verdict': settled[0], 'source': f'rule:{settled[1]}'}
            )
        else:
            tally['to_judge'] += 1
            review.append(evidence)
        records.append(evidence)
    records.sort(key=lambda e: e['unit_id'])
    review.sort(key=lambda e: e['unit_id'])
    with open(out_dir / 'units.jsonl', 'w', encoding='utf-8') as out:
        for evidence in records:
            out.write(_json.dumps(evidence) + '\n')
    with open(out_dir / 'rules.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, OVERLAY_FIELDS)
        writer.writeheader()
        for row in rules_rows:
            writer.writerow({**row, 'judged_at': date.today().isoformat()})
    sheet_fields = ['unit_id', 'path_class', 'view_path', 'name', 'value', 'context', 'length', 'entropy', 'charset',
                    'placeholder_words', 'formats', 'repositories_with_value', 'labels_in_file', 'labels_on_line',
                    'rules', 'runs']  # fmt: skip
    for start in range(0, len(review), per_sheet):
        sheet = out_dir / 'sheets' / f'sheet-{start // per_sheet + 1:03d}.jsonl'
        with open(sheet, 'w', encoding='utf-8') as f:
            f.write(_json.dumps({'rubric': RUBRIC, 'classes': list(CLASSES)}) + '\n')
            for unit in review[start : start + per_sheet]:
                f.write(_json.dumps({k: unit[k] for k in sheet_fields}) + '\n')
    with open(out_dir / 'verdicts-template.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['unit_id', 'verdict', 'note'])
        for unit in review:
            writer.writerow([unit['unit_id'], '', ''])
    summary = {
        'runs': run_ids,
        'findings': info['findings'],
        'units': len(units),
        'units_per_run': {r: sum(1 for u in units if any(f[0] == r for f in u['findings'])) for r in run_ids},
        'settled': dict(tally),
        'sheets': -(-len(review) // per_sheet),
        'written_at': datetime.now().isoformat(timespec='seconds'),
    }
    (out_dir / 'summary.json').write_text(_json.dumps(summary, indent=2) + '\n')
    summary['written_to'] = str(out_dir)
    return summary


def import_verdicts(home: BenchHome, path: Path, source: str, units_file: Optional[Path] = None) -> Dict:
    """Merges verdicts into the overlay: a rules.csv as export wrote it, or a filled verdicts template (unit ids,
    resolved to keys through the export's units.jsonl). A unit judged again keeps the newer verdict."""
    overlay_rows = {}
    if overlay_path(home).is_file():
        with open(overlay_path(home), newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                overlay_rows[(row['repo'], row['value_sha256'])] = row
    keys_of = {}
    if units_file is not None:
        with open(units_file, encoding='utf-8') as f:
            for line in f:
                unit = _json.loads(line)
                keys_of[unit['unit_id']] = [tuple(k) for k in unit['keys']]
    added = Counter()
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            verdict = (row.get('verdict') or '').strip()
            if not verdict:
                continue
            if verdict not in CLASSES:
                raise DarkMatterError(f'{path}: unknown verdict {verdict!r}')
            if 'unit_id' in row:
                if row['unit_id'] not in keys_of:
                    raise DarkMatterError(f"{path}: unit {row['unit_id']} is not in {units_file}")
                keys = keys_of[row['unit_id']]
            else:
                keys = [(row['repo'], row['value_sha256'])]
            for repo, sha in keys:
                overlay_rows[(repo, sha)] = {
                    'repo': repo,
                    'value_sha256': sha,
                    'verdict': verdict,
                    'source': row.get('source') or source,
                    'judged_at': row.get('judged_at') or date.today().isoformat(),
                }
                added[verdict] += 1
    write_overlay(home, overlay_rows.values())
    return {'imported': dict(added), 'overlay_units': len(overlay_rows)}
