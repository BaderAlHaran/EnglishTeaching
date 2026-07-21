import improve_routes


PDF_LIKE = """The Impact of Study Habits
Introduction
Regular study habits improve academic outcomes for most students. Research
conducted across several universities supports this conclusion.
Figure 1: Average grades by study hours per week
Table 2: Survey results from 300 participants
Hours | Grade | Count
2.5   | 71%   | 45
5.0   | 83%   | 120
7.5   | 89%   | 135
12
Students who planned their week performed better than those who did not. The
difference was largest during examination periods.
GPA
$1,200.00
Conclusion
Consistent routines matter more than total hours studied."""


def test_prose_sentences_are_kept():
    result = improve_routes._filter_non_prose(PDF_LIKE)
    assert "Regular study habits improve academic outcomes" in result
    assert "Students who planned their week performed better" in result
    assert "Consistent routines matter more than total hours studied." in result


def test_captions_removed():
    result = improve_routes._filter_non_prose(PDF_LIKE)
    assert "Figure 1" not in result
    assert "Table 2" not in result


def test_table_rows_and_numbers_removed():
    result = improve_routes._filter_non_prose(PDF_LIKE)
    assert "71%" not in result
    assert "| Grade |" not in result
    assert "$1,200.00" not in result
    assert "\n12\n" not in result


def test_stray_headers_removed_but_wrapped_lines_kept():
    result = improve_routes._filter_non_prose(PDF_LIKE)
    # One-word headers/labels are dropped
    assert "GPA" not in result
    assert "Introduction" not in result
    # Mid-sentence wrapped lines survive (end without punctuation but are long)
    assert "Research" in result


def test_table_only_document_falls_back():
    table_only = "Hours | Grade\n2 | 70%\n4 | 80%"
    assert improve_routes._filter_non_prose(table_only) == ""


def test_empty_and_none_safe():
    assert improve_routes._filter_non_prose("") == ""
    assert improve_routes._filter_non_prose(None) is None
