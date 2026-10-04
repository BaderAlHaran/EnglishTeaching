import ielts_report


TASK1_WITH_DATA = (
    "The chart shows how people travelled to work in one city.\n\n"
    "Overall, cars were the most popular choice throughout the period.\n\n"
    "In 2000, 45% of commuters drove, compared with 12% who cycled. By 2020 cycling had "
    "reached 30%."
)
TASK1_WITHOUT_DATA = (
    "The chart shows how people travelled to work in one city.\n\n"
    "Overall, cars were the most popular choice throughout the period.\n\n"
    "Car use stayed high, cycling grew steadily, and bus travel fell across the whole period."
)


def _status(report, title):
    return next((check["status"] for check in report["checks"] if check["title"] == title), None)


def _flagged(report, text):
    return {text[h["start"]:h["end"]]: h for h in report["highlights"]}


def test_memorised_template_sentences_are_flagged():
    text = ("It is often said that technology changes education. This essay will discuss both "
            "views and give my opinion.\n\n"
            "Tablets help pupils learn at their own pace.\n\n"
            "In conclusion, schools should use technology carefully.")
    report = ielts_report.build_report(text, task="task2")
    assert _status(report, "Template language") == "warn"
    flagged = _flagged(report, text)
    assert "It is often said that" in flagged
    assert "This essay will discuss" in flagged
    assert "Examiners discount" in flagged["It is often said that"]["message"]


def test_answers_in_the_students_own_words_pass():
    text = ("Technology has changed how children learn.\n\n"
            "Tablets let pupils work at their own pace.\n\n"
            "In conclusion, schools should set clear rules for devices.")
    report = ielts_report.build_report(text, task="task2")
    assert _status(report, "Template language") == "pass"
    assert report["highlights"] == []


def test_task1_without_figures_is_flagged():
    report = ielts_report.build_report(TASK1_WITHOUT_DATA, task="task1")
    assert _status(report, "Data") == "warn"
    detail = next(c["detail"] for c in report["checks"] if c["title"] == "Data")
    assert "support the description with data" in detail


def test_task1_with_figures_passes():
    assert _status(ielts_report.build_report(TASK1_WITH_DATA, task="task1"), "Data") == "pass"


def test_task2_is_not_asked_for_figures():
    report = ielts_report.build_report(TASK1_WITHOUT_DATA, task="task2")
    assert _status(report, "Data") is None
