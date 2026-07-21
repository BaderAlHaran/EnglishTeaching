import mechanics_report


SAMPLE = (
    "The results were surprising. The data was collected carefully. The team analyzed everything twice.\n\n"
    "However, this very long sentence keeps going and going with many extra words piled on top of each "
    "other so that it easily crosses the thirty word threshold that the clarity check is looking for today. "
    "The findings were important. Very important results appeared. Very good data was very clearly shown "
    "because the important findings were very important to the important stakeholders.\n\n"
    "In conclusion, the study worked."
)


def test_empty_text_returns_none():
    assert mechanics_report.build_report("") is None
    assert mechanics_report.build_report("   ") is None


def test_report_has_all_four_categories():
    report = mechanics_report.build_report(SAMPLE)
    assert set(report.keys()) == {"sentenceClarity", "repetitionVariety", "structuralSignals", "readability"}


def test_long_sentence_detected():
    report = mechanics_report.build_report(SAMPLE)
    clarity = report["sentenceClarity"]
    assert clarity["longSentenceCount"] >= 1
    assert len(clarity["examples"]) >= 1
    assert "words" in clarity["summary"]


def test_repeated_words_and_fillers():
    report = mechanics_report.build_report(SAMPLE)
    variety = report["repetitionVariety"]
    repeated = {item["word"] for item in variety["repeatedWords"]}
    assert "important" in repeated
    fillers = {item["phrase"] for item in variety["overusedFillers"]}
    assert "very" in fillers


def test_repetitive_starters_detected():
    report = mechanics_report.build_report(SAMPLE)
    starters = report["structuralSignals"]["repetitiveStarters"]
    assert any('"The"' in s for s in starters)


def test_readability_grade_reasonable():
    report = mechanics_report.build_report(SAMPLE)
    grade = report["readability"]["gradeLevel"]
    assert 0 <= grade <= 20
    assert report["readability"]["label"].startswith("Grade")


def test_passive_percent_uses_provided_ids():
    sentences = [
        {"id": 1, "text": "The data was collected."},
        {"id": 2, "text": "We analyzed it."},
        {"id": 3, "text": "Results were published."},
        {"id": 4, "text": "Everyone celebrated."},
    ]
    report = mechanics_report.build_report(
        "The data was collected. We analyzed it. Results were published. Everyone celebrated.",
        sentences=sentences,
        passive_sentence_ids=[1, 3],
    )
    assert report["sentenceClarity"]["passiveVoicePercent"] == 50
