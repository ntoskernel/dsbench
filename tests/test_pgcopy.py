import pytest

from dsbench.legacy.pgcopy import PgRestoreError, decode_field, parse_copy


@pytest.mark.parametrize(
    'raw, decoded',
    [
        ('plain', 'plain'),
        (r'\N', None),
        (r'a\tb', 'a\tb'),
        (r'line\nnext\r', 'line\nnext\r'),
        ('back\\\\slash', 'back\\slash'),
        (r'\b\f\v', '\b\f\v'),
        (r'\101\x42', 'AB'),
        (r'\q', 'q'),
        ('', ''),
    ],
)
def test_fields_are_decoded_as_copy_text(raw, decoded):
    assert decode_field(raw) == decoded


def test_rows_come_from_every_copy_block_with_their_own_columns():
    stream = [
        '--\n',
        '-- Data for Name: FileReports\n',
        'COPY public."FileReports" (file, sb_secrets_cnt) FROM stdin;\n',
        'a.py\t3\n',
        'b.py\t\\N\n',
        '\\.\n',
        'COPY public.secretbench (id, secret) FROM stdin;\n',
        '7\tx\\ty\n',
        '\\.\n',
    ]
    assert list(parse_copy(stream)) == [
        (['file', 'sb_secrets_cnt'], ['a.py', '3']),
        (['file', 'sb_secrets_cnt'], ['b.py', None]),
        (['id', 'secret'], ['7', 'x\ty']),
    ]


def test_a_row_with_the_wrong_number_of_fields_stops_the_export():
    with pytest.raises(PgRestoreError):
        list(parse_copy(['COPY t (a, b) FROM stdin;\n', 'only-one\n']))
