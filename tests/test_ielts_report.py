import ielts_report


QUESTION = (
    "Some people believe that governments should spend more money on public transport "
    "than on building new roads. To what extent do you agree or disagree?"
)

CLEAN_TASK2 = "\n\n".join([
    "Traffic congestion has become a serious problem in many growing cities, and governments "
    "must decide how to divide limited transport budgets. In my view, public transport deserves "
    "the larger share of investment, although new roads are still necessary in some regions.",
    "The strongest argument for public transport is efficiency. A single train can carry several "
    "hundred passengers, while the same number of people travelling by car would fill an entire "
    "motorway lane. When cities such as Singapore expanded their metro networks, journey times fell "
    "and air quality improved, because fewer private vehicles were competing for space.",
    "Public transport also offers fairer access to opportunity. Many young people, elderly residents "
    "and low-income workers cannot afford to own a car. Reliable buses and trains allow them to reach "
    "jobs, hospitals and colleges that would otherwise be out of reach, which benefits the wider "
    "economy as well as the individuals themselves.",
    "Nevertheless, road building cannot be abandoned entirely. Rural communities often depend on roads "
    "because their populations are too small to support frequent rail services, and emergency vehicles "
    "and freight lorries need well-maintained routes. Spending on these roads should therefore continue, "
    "but it should be targeted rather than used to widen urban motorways that quickly fill with new traffic.",
    "In conclusion, I believe governments should direct most of their transport funding towards public "
    "systems, since they move more people, reduce pollution and widen access to work and education. Roads "
    "remain important where no realistic alternative exists, but they should no longer receive the "
    "majority of investment.",
])

TASK1 = (
    "The line graph compares the number of visitors to three London museums between 2000 and 2020.\n\n"
    "Overall, the Science Museum was the most popular throughout the period, while visitor numbers at "
    "the other two rose steadily.\n\n"
    "In 2000, the Science Museum received about 2 million visitors, compared with 1.2 million at the "
    "British Museum and 0.8 million at the Tate. By 2020, the British Museum had almost caught up."
)


def _status(report, title):
    return next(check["status"] for check in report["checks"] if check["title"] == title)


def _flagged(report, text):
    return {text[h["start"]:h["end"]]: h for h in report["highlights"]}


def test_empty_text_returns_none():
    assert ielts_report.build_report("") is None
    assert ielts_report.build_report("   \n ") is None


def test_unknown_task_falls_back_to_task2():
    report = ielts_report.build_report("Public transport matters.", task="task9")
    assert report["task"] == "task2"
    assert report["minimumWords"] == 250


def test_clean_task2_essay_passes_every_check():
    report = ielts_report.build_report(CLEAN_TASK2, task="task2", question=QUESTION)
    assert report["countedWords"] >= 250
    problems = [c for c in report["checks"] if c["status"] in ("warn", "fail")]
    assert problems == [], problems
    assert report["highlights"] == []


def test_short_answer_fails_word_count():
    report = ielts_report.build_report("Public transport is useful. " * 20, task="task2")
    assert _status(report, "Word count") == "fail"
    assert "250-word minimum" in report["checks"][0]["detail"]


def test_task1_minimum_is_150_words():
    text = "The chart shows sales in 2010. " * 27  # 162 words
    assert _status(ielts_report.build_report(text, task="task1"), "Word count") == "pass"
    assert _status(ielts_report.build_report(text, task="task2"), "Word count") == "fail"


def test_numbers_count_as_words():
    assert ielts_report.count_words("Sales rose to 45% in 2010.") == 6


def test_curly_apostrophe_keeps_a_contraction_as_one_word():
    assert ielts_report.count_words("It don’t matter") == 3


def test_copied_question_words_are_not_counted():
    opening = "Some people believe that governments should spend more money on public transport. "
    text = opening + CLEAN_TASK2
    report = ielts_report.build_report(text, task="task2", question=QUESTION)
    assert report["copiedWords"] == 12
    assert report["countedWords"] == report["wordCount"] - 12
    assert _status(report, "Copied wording") == "warn"
    copied = _flagged(report, text)["Some people believe that governments should spend more money on public transport"]
    assert "Copied from the question" in copied["message"]


def test_short_shared_phrases_are_not_copying():
    report = ielts_report.build_report(
        "Building new roads is costly. Cities differ.",
        question="Many cities are building new roads for cars.",
    )
    assert report["copiedWords"] == 0
    assert _status(report, "Copied wording") == "pass"


def test_missing_question_is_a_note_not_a_failure():
    report = ielts_report.build_report(CLEAN_TASK2)
    assert _status(report, "Copied wording") == "info"


def test_contractions_flagged_with_full_forms():
    text = "It's clear that students don't read. They can't focus and won't try."
    flagged = _flagged(ielts_report.build_report(text), text)
    assert flagged["It's"]["suggestions"] == ["It is", "It has"]
    assert flagged["don't"]["suggestions"] == ["do not"]
    assert flagged["can't"]["suggestions"] == ["cannot"]
    assert flagged["won't"]["suggestions"] == ["will not"]


def test_possessives_are_not_contractions():
    report = ielts_report.build_report("The government's plan and the students' results were published.")
    assert report["highlights"] == []
    assert _status(report, "Formal language") == "pass"


def test_informal_words_flagged_but_not_inside_longer_words():
    text = "A lot of kids like stuff. The kidney is an organ."
    flagged = _flagged(ielts_report.build_report(text), text)
    assert flagged["A lot of"]["suggestions"][0] == "Many"
    assert flagged["kids"]["suggestions"] == ["children"]
    assert "stuff" in flagged
    assert not any("kidney" in phrase for phrase in flagged)


def test_so_opener_flagged_but_not_so_far():
    text = "So, we must act. So far, results are good."
    report = ielts_report.build_report(text)
    so_hits = [h for h in report["highlights"] if text[h["start"]:h["end"]] == "So"]
    assert len(so_hits) == 1
    assert so_hits[0]["start"] == 0


def test_exclamation_marks_flagged():
    text = "This is shocking! We must act."
    flagged = _flagged(ielts_report.build_report(text), text)
    assert flagged["!"]["suggestions"] == ["."]


def test_overused_phrases_and_nowadays_opener():
    text = "Nowadays, technology matters. In this day and age, last but not least, it is key."
    report = ielts_report.build_report(text)
    flagged = _flagged(report, text)
    assert {"Nowadays", "In this day and age", "last but not least"} <= set(flagged)
    assert _status(report, "Overused phrases") == "warn"


def test_nowadays_mid_sentence_is_fine():
    report = ielts_report.build_report("Many people nowadays work from home.")
    assert report["highlights"] == []


def test_single_paragraph_fails_structure():
    report = ielts_report.build_report(CLEAN_TASK2.replace("\n\n", " "), question=QUESTION)
    assert _status(report, "Paragraphs") == "fail"
    assert not any(c["title"] == "Conclusion" for c in report["checks"])


def test_task2_conclusion_needs_a_concluding_opening():
    assert _status(ielts_report.build_report(CLEAN_TASK2), "Conclusion") == "pass"
    no_signal = CLEAN_TASK2.replace("In conclusion, I believe", "I believe")
    assert _status(ielts_report.build_report(no_signal), "Conclusion") == "warn"


def test_task1_missing_overview_is_flagged_for_checking():
    assert _status(ielts_report.build_report(TASK1, task="task1"), "Overview") == "pass"
    without = TASK1.replace("Overall, the Science Museum was", "The Science Museum was")
    report = ielts_report.build_report(without, task="task1")
    # A warning, not a failure: the student may have an overview worded differently.
    assert _status(report, "Overview") == "warn"
    assert "couldn't find" in next(c["detail"] for c in report["checks"] if c["title"] == "Overview")


def test_other_common_overview_openers_count():
    text = TASK1.replace("Overall, the Science Museum was", "Broadly speaking, the Science Museum was")
    assert _status(ielts_report.build_report(text, task="task1"), "Overview") == "pass"


def test_task1_flags_opinions_but_task2_does_not():
    text = "The graph shows sales.\n\nOverall, sales rose.\n\nI think this is surprising."
    task1 = ielts_report.build_report(text, task="task1")
    assert _status(task1, "Opinions") == "warn"
    assert "I think" in _flagged(task1, text)
    task2 = ielts_report.build_report(text, task="task2")
    assert not any(c["title"] == "Opinions" for c in task2["checks"])


def test_report_keeps_the_question_for_the_reviewer():
    report = ielts_report.build_report(CLEAN_TASK2, question="  " + QUESTION + "  ")
    assert report["question"] == QUESTION
