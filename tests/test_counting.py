"""Counting `located` pairs per group, per unit and per row; synthetic labels only."""

from dsbench import counting

# (row_id, group_id, label, fragment, repo, value)
ROWS = [
    (1, 1, True, False, 'r1', 'xoxb-Tq7XbR2mKp9L'),  # a real token ...
    (2, 1, False, True, 'r1', 'Tq7XbR2mKp9L'),  # ... and its fragment, in one group
    (3, 3, False, True, 'r1', 'Mk3Vb8Qw'),  # a fragment alone: charged only by a finding that is it
    (4, 4, False, False, 'r1', 'Zx9Qm2Lp8Rt4'),  # a look-alike
    (5, 5, False, False, 'r2', 'Zx9Qm2Lp8Rt4'),  # the same value in another repository: another unit
    (6, 6, True, False, 'r1', '"xoxb-Tq7X\\nbR2mKp9L"'),  # another copy of row 1's value, written differently
    (7, 7, False, False, 'r1', 'Wq2Er4Ty6Ui8'),  # a look-alike a real finding also overlaps
    (8, 8, True, False, 'r2', 'Pp0Oo9Ii8Uu7'),  # never found
]
LOW, MEDIUM, HIGH, VERY_HIGH = 1, 2, 3, 4
# (finding_id, row_id, encloses, tier rank)
PAIRS = [
    (10, 1, False, VERY_HIGH),
    (10, 2, True, VERY_HIGH),
    (11, 3, True, MEDIUM),  # encloses the lone fragment: no charge
    (12, 3, False, LOW),  # is the fragment: a charge, at low only
    (13, 4, False, HIGH),
    (14, 5, False, MEDIUM),
    (15, 6, False, LOW),
    (15, 7, False, LOW),  # finding 15 reports a real secret: row 7 is not charged by it
]


def test_groups_units_rows_and_tiers():
    c = counting.count(counting.Labels(ROWS), PAIRS)
    group = {level: (v['secrets_found'], v['lookalikes_found']) for level, v in c['per_group'].items()}
    assert c['per_group']['low']['secrets'] == 3 and c['per_group']['low']['lookalikes'] == 4
    assert group == {'low': (2, 3), 'medium': (1, 2), 'high': (1, 1), 'very-high': (1, 0)}
    # units: r1's token (rows 1, 6), r2's never-found value; look-alikes r1:Zx9.., r2:Zx9.., r1:Mk3.., r1:Wq2..
    unit = c['per_repository_and_value']
    assert (unit['low']['secrets'], unit['low']['lookalikes']) == (2, 5)
    assert (unit['low']['secrets_found'], unit['low']['lookalikes_found']) == (1, 3)
    assert (unit['very-high']['secrets_found'], unit['high']['lookalikes_found']) == (1, 1)
    row = c['per_row']['low']
    assert (row['secrets'], row['secrets_found'], row['lookalikes'], row['lookalikes_found']) == (3, 2, 5, 3)
    assert c['reliability']['low'] == {'real_groups': 1, 'lookalike_groups': 1, 'secret_share': 0.5}
    assert c['reliability']['very-high']['real_groups'] == 1 and c['paired_findings'] == 6


def test_unit_values_merge_the_forms_of_one_secret():
    assert counting.unit_value('"xoxb-Tq7X\\nbR2mKp9L"') == counting.unit_value('xoxb-Tq7XbR2mKp9L')
    assert counting.unit_value(' a.b/c+d ') == 'abcd' and counting.unit_value(None) == ''


def test_pairs_outside_the_scope_are_ignored():
    labels = counting.Labels(r for r in ROWS if r[0] != 1)
    c = counting.count(labels, PAIRS)
    # row 1 is out of scope: finding 10 now pairs only fragment row 2, which it encloses
    assert c['per_group']['low']['secrets'] == 2 and c['per_group']['very-high']['secrets_found'] == 0


def test_numeric_cuts_count_pairs_by_their_confidence():
    # the same pairs scored by confidence: 10 for the very-high finding, and so on
    confidence = {VERY_HIGH: 9, HIGH: 7, MEDIUM: 4, LOW: 1}
    pairs = [(f, row, enc, confidence[rank]) for f, row, enc, rank in PAIRS] + [(16, 8, False, None)]
    c = counting.count(counting.Labels(ROWS), pairs, counting.CONFIDENCE_CUTS)
    assert set(c) == {'per_group', 'per_repository_and_value', 'per_row'} and len(c['per_group']) == 11
    group = {cut: (v['secrets_found'], v['lookalikes_found']) for cut, v in c['per_group'].items()}
    assert group['0'] == group['1'] == (2, 3) and group['5'] == (1, 1) and group['10'] == (0, 0)


def test_tag_views_count_what_a_tag_reaches_and_the_scores_without_it():
    tags = {13: frozenset({'test-context'}), 15: frozenset({'test-context', 'publishable'})}
    views = counting.tag_views(counting.Labels(ROWS), PAIRS, tags)
    assert list(views) == ['publishable', 'test-context', 'all']
    tc = views['test-context']
    assert tc['findings'] == 2
    # finding 15 finds real row 6; finding 13 is charged for row 4
    assert tc['reach']['per_group']['low'] == {'real': 1, 'lookalike': 1}
    # without them: group 6 is lost, group 4 no longer charged; and row 7, which finding 15 overlapped, still uncharged
    without = tc['without']['per_group']['low']
    assert (without['secrets_found'], without['lookalikes_found']) == (1, 2)
    assert views['all']['findings'] == 2 and counting.tag_views(counting.Labels(ROWS), PAIRS, {}) == {}
