"""Locating labels and findings in the text of the file the scanner read, for the `located` matcher.

The text is read as DeepSecrets reads it: UTF-8 with undecodable bytes replaced, universal newlines, and a final
newline added when the file lacks one. Lines are 1-based. A label's columns follow SecretBench (1-based
`start_column`, exclusive `end_column`); a finding's region follows SARIF as DeepSecrets writes it (1-based columns
counted in code points from the line's start, `endColumn` exclusive). Both become character offsets in that text.

A label is located by its value, in this order, and the first that succeeds says how (`kind`):

    exact      the value starts at the labelled line and column
    moved      the value is on the labelled lines at another column, or there only in another form: without a
               trailing newline, without the quotes around it, with its escaped newlines (a literal `\\n`) real;
               the occurrence nearest the labelled column wins
    reformed   on the labelled lines with whitespace ignored (a key re-indented or re-wrapped, CRLF endings)
    elsewhere  the value, in any of those forms, on other lines of the file; the occurrence nearest the labelled line
    material   on the labelled lines, its material: the characters `[A-Za-z0-9+/=]` of label and file alike, with
               escape sequences dropped and an extra escaping layer undone, so quotes, `+` and other string syntax
               between the pieces do not matter (a private key written as a string literal, or concatenated from one
               literal per line); at least 16 characters of it
    span       the value is nowhere in the file in any form: the labelled span itself, the dataset's own coordinates
    none       the labelled span is not in the file either

A finding is located at its region; when the region does not hold its snippet, at the snippet's occurrence on the
region's lines nearest the region. A finding and a label pair when their spans overlap, by at least one character.

How labels whose value sits away from their span are handled is a choice of this matcher, made on the data. Of
SecretBench's 97,479 rows, 96,163 are exact, 376 moved and 681 reformed on their own lines, 49 elsewhere, and 210 are
in none of those forms in the file. Nearly all of the 210 are private keys, and for about half of them the file holds
a different key at that place. Falling back to the span is needed: without it DeepSecrets 2.2.0 scores 13,442 real
groups against the published 13,483. It also keeps crediting a different key reported at the labelled place.

Versions. `located-1` gave the 47 labels that transcribe source syntax (an escaped newline, a leading quote or bracket)
neither the material search nor the span, so the keys inside string literals went uncredited (27 groups on 2.2.0,
13,489 real groups). `located-2` locates them by their material where it is on their lines, and lets every other label
fall back to its span; on 2.2.0 that credits those 27 groups."""

import bisect
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

QUOTES = '"\'`'
# a label value that copies source syntax: an escaped newline, or a leading quote or bracket (counted only)
TRANSCRIBED = re.compile(r'\\n|^["\'\[]')
MATERIAL = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
MIN_MATERIAL = 16
# how far around the labelled place the material search reads, beyond the value's own length
MATERIAL_SLACK = 65_536
# how far past the labelled lines a value found with whitespace ignored may run, beyond its own length
REFORM_SLACK = 4096
# how many occurrences of a value are weighed when picking the nearest
MAX_OCCURRENCES = 1000

Span = Tuple[int, int]


def read_text(path: str) -> str:
    with open(path, encoding='utf-8', errors='replace') as f:
        text = f.read()
    return text if text.endswith('\n') else text + '\n'


class Text:
    """A file's text with its line starts."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0]
        at = text.find('\n')
        while at != -1:
            self.starts.append(at + 1)
            at = text.find('\n', at + 1)

    @property
    def lines(self) -> int:
        return len(self.starts)

    def offset(self, line: Optional[int], column: Optional[int]) -> Optional[int]:
        if line is None or column is None or not 1 <= line <= self.lines:
            return None
        return min(self.starts[line - 1] + max(column, 1) - 1, len(self.text))

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def lines_span(self, first: int, last: int) -> Span:
        """From the start of line `first` to the end of line `last`, both clamped to the file."""
        first = min(max(first, 1), self.lines)
        last = min(max(last, first), self.lines)
        return self.starts[first - 1], self.starts[last] if last < self.lines else len(self.text)


def value_forms(value: str) -> List[str]:
    """The value as labelled, then with each export transformation undone; cheapest first."""
    forms = [value]

    def add(text: str) -> None:
        if text and text not in forms:
            forms.append(text)

    add(value.strip('\r\n'))
    for text in list(forms):
        if len(text) > 2 and text[0] == text[-1] and text[0] in QUOTES:
            add(text[1:-1])
    for text in list(forms):
        if '\\n' in text:
            add(text.replace('\\r\\n', '\n').replace('\\n', '\n'))
    return forms


def _spaced(form: str) -> Optional['re.Pattern']:
    """The form with any whitespace allowed between its characters, or None when nothing is left of it."""
    chars = [c for c in form if not c.isspace()]
    return re.compile(r'\s*'.join(re.escape(c) for c in chars)) if chars else None


def _nearest(occurrences, key) -> Optional[Tuple[int, int]]:
    best = None
    for n, (start, end) in enumerate(occurrences):
        if n >= MAX_OCCURRENCES:
            break
        if best is None or key(start) < key(best[0]):
            best = (start, end)
    return best


def _finds(text: str, form: str, lo: int, hi: int):
    at = text.find(form, lo, hi)
    while at != -1:
        yield at, at + len(form)
        at = text.find(form, at + 1, hi)


def _matches(pattern: 're.Pattern', text: str, lo: int, hi: int):
    for m in pattern.finditer(text, lo, hi):
        yield m.start(), m.end()


@dataclass(frozen=True)
class LabelSpan:
    kind: str
    start: Optional[int] = None
    end: Optional[int] = None
    line_delta: int = 0


def locate_label(t: Text, value: str, start_line: int, end_line: int, start_col: int, end_col: int) -> LabelSpan:
    labelled = t.offset(start_line, start_col)
    if value and labelled is not None and t.text.startswith(value, labelled):
        return LabelSpan('exact', labelled, labelled + len(value))
    if value and 1 <= start_line <= t.lines:
        lo, hi = t.lines_span(start_line, end_line)
        target = labelled if labelled is not None else lo
        forms = value_forms(value)
        for form in forms:
            # an occurrence must start on the labelled lines; it may run past them
            hit = _nearest(_finds(t.text, form, lo, hi + len(form)), lambda s: abs(s - target))
            if hit and hit[0] < hi:
                return LabelSpan('moved', *hit)
        for form in forms:
            pattern = _spaced(form)
            reach = min(len(t.text), hi + 2 * len(form) + REFORM_SLACK)
            hit = pattern and _nearest(_matches(pattern, t.text, lo, reach), lambda s: abs(s - target))
            if hit and hit[0] < hi:
                return LabelSpan('reformed', *hit)
    if value:
        by_line = lambda s: abs(t.line_of(s) - start_line)  # noqa: E731
        for occurrences in (
            *(_finds(t.text, form, 0, len(t.text)) for form in value_forms(value)),
            *(_matches(p, t.text, 0, len(t.text)) for p in map(_spaced, value_forms(value)) if p),
        ):
            hit = _nearest(occurrences, by_line)
            if hit:
                return LabelSpan('elsewhere', *hit, line_delta=t.line_of(hit[0]) - start_line)
    if value and 1 <= start_line <= t.lines:
        hit = _locate_material(t, value, start_line, end_line, labelled)
        if hit:
            return LabelSpan('material', *hit)
    end = t.offset(end_line, end_col)
    if value and labelled is not None and end is not None and end > labelled:
        return LabelSpan('span', labelled, end)
    return LabelSpan('none')


def material(text: str, base: int = 0) -> Tuple[str, List[int]]:
    """The characters a key is made of, with escape sequences dropped (a run of backslashes counts as one, so a value
    escaped once more than the file still matches), and each one's offset in the text."""
    chars, offsets = [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '\\':
            while i < n and text[i] == '\\':
                i += 1
            i += 1  # the escaped character
            continue
        if c in MATERIAL:
            chars.append(c)
            offsets.append(base + i)
        i += 1
    return ''.join(chars), offsets


def _locate_material(t: Text, value: str, start_line: int, end_line: int, labelled: Optional[int]) -> Optional[Span]:
    wanted, _ = material(value)
    if len(wanted) < MIN_MATERIAL:
        return None
    lo, hi = t.lines_span(start_line, end_line)
    anchor = labelled if labelled is not None else lo
    lo = max(lo, anchor - MATERIAL_SLACK)
    reach = min(len(t.text), max(hi, anchor) + 2 * len(value) + MATERIAL_SLACK)
    found, offsets = material(t.text[lo:reach], lo)
    at = found.find(wanted)
    if at == -1 or offsets[at] >= hi:
        return None
    return offsets[at], offsets[at + len(wanted) - 1] + 1


def locate_finding(
    t: Text, start_line: Optional[int], end_line: Optional[int], start_col, end_col, snippet: Optional[str]
) -> Optional[Span]:
    start, end = t.offset(start_line, start_col), t.offset(end_line, end_col)
    if start is None or end is None:
        return None
    if snippet and t.text[start:end] != snippet:
        lo, hi = t.lines_span(start_line, end_line or start_line)
        hit = _nearest(_finds(t.text, snippet, lo, hi + len(snippet)), lambda s: abs(s - start))
        if hit and hit[0] < hi:
            return hit
    return (start, end) if end > start else None


def overlap(a: Span, b: Span) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def encloses(finding: Span, label: Span) -> bool:
    """The finding covers the label and more: it reports a larger secret the label is a piece of."""
    return finding[0] <= label[0] and finding[1] >= label[1] and finding[1] - finding[0] > label[1] - label[0]


# ---------------------------------------------------------------- one file, in a worker process
# a label: (row_id, value, start_line, end_line, start_col, end_col), or (row_id, kind, start, end) once located
# a finding: (finding_id, start_line, end_line, start_col, end_col, snippet)


def match_file(job: Tuple[str, Sequence[tuple], Sequence[tuple], bool]) -> Tuple[List[tuple], List[tuple]]:
    """Locates a file's labels (when `locate` is set; else they come located) and pairs its findings with them.
    Returns the label spans as (row_id, kind, start, end, line_delta) and the pairs as
    (finding_id, row_id, kind, line_delta, encloses)."""
    path, labels, findings, locate = job
    try:
        t = Text(read_text(path))
    except OSError:
        spans = [(row[0], 'none', None, None, 0) for row in labels] if locate else []
        return spans, []
    if locate:
        spans = []
        for row_id, value, start_line, end_line, start_col, end_col in labels:
            s = locate_label(t, value or '', start_line, end_line, start_col, end_col)
            spans.append((row_id, s.kind, s.start, s.end, s.line_delta))
    else:
        spans = list(labels)
    located = [(row_id, kind, start, end, delta) for row_id, kind, start, end, delta in spans if start is not None]
    located.sort(key=lambda x: x[2])
    starts = [x[2] for x in located]
    longest = max((x[3] - x[2] for x in located), default=0)
    pairs = []
    for finding_id, start_line, end_line, start_col, end_col, snippet in findings:
        span = locate_finding(t, start_line, end_line, start_col, end_col, snippet)
        if span is None:
            continue
        # labels starting before the finding ends and no more than the longest label before it starts
        first = bisect.bisect_left(starts, span[0] - longest)
        last = bisect.bisect_left(starts, span[1])
        for row_id, kind, start, end, delta in located[first:last]:
            if overlap(span, (start, end)):
                pairs.append((finding_id, row_id, kind, delta, encloses(span, (start, end))))
    return (spans if locate else []), pairs
