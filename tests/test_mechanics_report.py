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


def test_report_has_all_categories():
    report = mechanics_report.build_report(SAMPLE)
    assert set(report.keys()) == {"sentenceClarity", "repetitionVariety", "academicStyle",
                                  "structuralSignals", "readability"}


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


# ---- academic style checks ----

TURGID = (
    "The implementation of the policy was slow. "
    "The examination of the data took months. "
    "There is a need for further work. "
    "It is important that we continue. "
    "The situation is one that is difficult and is not easily resolved."
)


def test_nominalisations_detected_with_verb_suggestions():
    style = mechanics_report.build_report(TURGID)["academicStyle"]
    found = {item["noun"]: item["verb"] for item in style["nominalisations"]}
    assert "implementation" in found and found["implementation"] == "implement"
    assert "examination" in found and found["examination"] == "examine"


def test_legitimate_nouns_are_not_flagged_as_nominalisations():
    """"government" and "environment" end in -ment but are ordinary nouns."""
    text = ("The government announced the policy. The environment is changing. "
            "The department published the document.")
    style = mechanics_report.build_report(text)["academicStyle"]
    assert style["nominalisations"] == []


def test_expletive_openers_counted():
    style = mechanics_report.build_report(TURGID)["academicStyle"]
    assert style["expletiveOpeners"] >= 2


def test_to_be_density_reported():
    style = mechanics_report.build_report(TURGID)["academicStyle"]
    assert style["toBePercent"] > mechanics_report.TO_BE_MAX_PERCENT
    assert "to be" in style["summary"]


def test_clean_prose_gets_a_clean_style_summary():
    text = ("Regular practice sharpens writing. Students who revise their drafts "
            "notice patterns they repeat. Teachers can then focus on argument "
            "rather than grammar, which benefits everyone involved in the process.")
    style = mechanics_report.build_report(text)["academicStyle"]
    assert style["nominalisations"] == []
    assert style["expletiveOpeners"] == 0


# ---- sentence variety ----

def test_monotonous_sentences_flagged():
    text = " ".join(["The cat sat down quietly today."] * 8)
    clarity = mechanics_report.build_report(text)["sentenceClarity"]
    assert clarity["sentenceLengthSD"] is not None
    assert clarity["sentenceLengthSD"] < mechanics_report.SENTENCE_VARIETY_MIN_SD
    assert "similar length" in clarity["summary"]


def test_varied_sentences_not_flagged():
    text = ("Rain fell. "
            "The long afternoon stretched on while the students worked steadily through "
            "their revisions, pausing only to compare notes with one another. "
            "Nobody complained. "
            "By evening the room had emptied and only the quiet hum of the air "
            "conditioning remained to keep the caretaker company. "
            "It was done.")
    clarity = mechanics_report.build_report(text)["sentenceClarity"]
    assert "similar length" not in clarity["summary"]


def test_sentence_variety_skipped_on_short_text():
    clarity = mechanics_report.build_report("One. Two. Three.")["sentenceClarity"]
    assert clarity["sentenceLengthSD"] is None


# ---- lexical diversity ----

def test_repetitive_vocabulary_flagged():
    text = " ".join(["Social media is bad for students because social media distracts students."] * 6)
    variety = mechanics_report.build_report(text)["repetitionVariety"]
    assert variety["lexicalDiversity"] < mechanics_report.LEXICAL_DIVERSITY_MIN
    assert "Vocabulary variety" in variety["summary"]


def test_lexical_diversity_is_length_independent():
    """A moving-average ratio should not collapse purely because text is long."""
    rich = ("Careful revision reveals patterns invisible during drafting. Writers who "
            "reread their arguments discover gaps between evidence and claim, then "
            "restructure paragraphs accordingly. Precision emerges through iteration, "
            "not inspiration, and clarity rewards patience above cleverness. Every "
            "discipline prizes readers who follow reasoning without effort.")
    variety = mechanics_report.build_report(rich)["repetitionVariety"]
    assert variety["lexicalDiversity"] >= mechanics_report.LEXICAL_DIVERSITY_MIN


# ---- style penalty folded into the score ----

def _penalty(text):
    report = mechanics_report.build_report(text)
    words = len(mechanics_report._words(text))
    return mechanics_report.style_penalty(report, words)


def test_turgid_prose_is_penalised():
    penalty, breakdown = _penalty(TURGID)
    assert penalty > 0
    reasons = {reason for reason, _ in breakdown}
    assert "buried verbs" in reasons
    assert "empty sentence openers" in reasons


def test_good_prose_is_not_penalised():
    """The control case: varied sentences, no buried verbs, no empty openers."""
    text = ("Social media shapes how students study, but not in the way most schools "
            "assume. Teachers usually blame distraction during lessons. The evidence "
            "points elsewhere. Students who scroll late at night sleep badly, and poor "
            "sleep damages recall far more than a glance at a phone during class ever "
            "could. Banning devices therefore treats a symptom while ignoring the cause.")
    penalty, breakdown = _penalty(text)
    assert penalty == 0, "good prose was penalised for %s" % breakdown


def test_penalty_is_capped():
    """Piling on weaknesses cannot push the deduction past the cap."""
    text = (" ".join(["The implementation of the examination of the consideration of "
                      "the evaluation of the assessment of things is a thing."] * 6)
            + " There is a thing. There is a thing. It is a thing. It is a thing.")
    penalty, _ = _penalty(text)
    assert penalty <= mechanics_report.STYLE_PENALTY_CAP


def test_penalty_is_length_normalised():
    """The same *rate* of buried verbs should score alike in a short and a long
    text. Counts are per 100 words, so length alone must not change the result."""
    filler = ("Students revise drafts and compare notes with classmates before the "
              "deadline arrives, which helps them notice weak paragraphs early. ")
    nom = "The implementation of the policy mattered. "

    short_text = nom * 2 + filler * 3          # 2 buried verbs, ~70 words
    long_text = nom * 8 + filler * 12          # 8 buried verbs, ~280 words

    short_report = mechanics_report.build_report(short_text)
    long_report = mechanics_report.build_report(long_text)
    short_pen, _ = mechanics_report.style_penalty(
        short_report, len(mechanics_report._words(short_text)))
    long_pen, _ = mechanics_report.style_penalty(
        long_report, len(mechanics_report._words(long_text)))

    # Same density of the same fault -> comparable deduction despite 4x length.
    assert abs(short_pen - long_pen) <= 3


def test_penalty_zero_without_word_count():
    assert mechanics_report.style_penalty({}, 0) == (0, [])
    assert mechanics_report.style_penalty(None, 100) == (0, [])
