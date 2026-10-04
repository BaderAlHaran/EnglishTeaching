import mechanics_report


WORDY = ("Due to the fact that funding is limited, the committee must make a decision regarding "
         "class sizes at this point in time, in order to protect teaching quality.")

CLEAN = ("Funding is limited, so the committee must decide about class sizes now to protect "
         "teaching quality. Smaller classes let teachers notice who is struggling, and that "
         "shows up in results within a term.")


def _flagged(report, text):
    return {text[h["start"]:h["end"]]: h for h in report["highlights"]}


def _penalty(text, language=None):
    report = mechanics_report.build_report(text, language=language)
    return mechanics_report.style_penalty(report, len(mechanics_report._words(text)))


def test_wordy_phrases_are_flagged_with_a_shorter_wording():
    report = mechanics_report.build_report(WORDY)
    flagged = _flagged(report, WORDY)
    assert flagged["Due to the fact that"]["suggestions"] == ["Because"]
    assert flagged["at this point in time"]["suggestions"] == ["now"]
    assert flagged["in order to"]["suggestions"] == ["to"]
    phrases = {item["phrase"] for item in report["concision"]["wordyPhrases"]}
    assert {"due to the fact that", "at this point in time", "in order to"} <= phrases


def test_buried_verb_phrases_are_flagged():
    report = mechanics_report.build_report(WORDY)
    flagged = _flagged(report, WORDY)
    assert flagged["make a decision"]["suggestions"] == ["decide"]
    assert "says it in one word" in flagged["make a decision"]["message"]


def test_filler_phrases_offer_no_replacement_just_removal():
    text = "It is important to note that the results were mixed."
    report = mechanics_report.build_report(text)
    flagged = _flagged(report, text)
    assert flagged["It is important to note that"]["suggestions"] == []
    assert "adds nothing" in flagged["It is important to note that"]["message"]


def test_highlight_offsets_point_at_the_flagged_words():
    report = mechanics_report.build_report(WORDY)
    for item in report["highlights"]:
        assert WORDY[item["start"]:item["end"]].strip(), item


def test_clean_prose_has_no_concision_findings():
    report = mechanics_report.build_report(CLEAN)
    assert report["concision"]["wordyPhrases"] == []
    assert report["concision"]["buriedVerbPhrases"] == []
    assert report["highlights"] == []
    penalty, breakdown = _penalty(CLEAN)
    assert penalty == 0, breakdown


def test_wordiness_now_costs_marks():
    penalty, breakdown = _penalty(WORDY)
    reasons = {reason for reason, _ in breakdown}
    assert "wordy phrases" in reasons
    assert penalty > 0


MIXED = ("We organised the data and then organized the results. The colour of the first chart "
         "differs from the color of the second.")


def test_mixed_spellings_are_flagged_against_the_chosen_variant():
    report = mechanics_report.build_report(MIXED, language="en-GB")
    pairs = {(m["british"], m["american"]) for m in report["spellingConsistency"]["mixed"]}
    assert {("organised", "organized"), ("colour", "color")} <= pairs
    flagged = _flagged(report, MIXED)
    assert flagged["organized"]["suggestions"] == ["organised"]
    assert flagged["color"]["suggestions"] == ["colour"]


def test_american_variant_flags_the_british_spellings_instead():
    report = mechanics_report.build_report(MIXED, language="en-US")
    flagged = _flagged(report, MIXED)
    assert flagged["organised"]["suggestions"] == ["organized"]
    assert "organized" not in flagged


def test_consistent_spelling_is_not_flagged():
    text = "We organised the data and then analysed the colour of every chart."
    report = mechanics_report.build_report(text, language="en-GB")
    assert report["spellingConsistency"]["mixed"] == []
    assert report["highlights"] == []
    # American spelling used consistently is also fine; it is the mixing that counts.
    american = "We organized the data and then analyzed the color of every chart."
    assert mechanics_report.build_report(american, language="en-GB")["spellingConsistency"]["mixed"] == []


def test_mixed_spelling_costs_marks():
    penalty, breakdown = _penalty(MIXED, language="en-GB")
    assert "mixed spelling" in {reason for reason, _ in breakdown}
    assert penalty > 0


def test_single_empty_opener_reads_as_opens():
    report = mechanics_report.build_report("There is a need for change. Teachers agree on that.")
    assert "1 sentence opens with" in report["academicStyle"]["summary"]


def test_wordy_phrases_become_clickable_fixes_on_the_results_page(client, app_module):
    routes = app_module.improve_routes
    job_id = routes._create_improve_job(WORDY, None)
    routes._process_improve_job(job_id, WORDY, None)

    body = client.get(f"/improve/result/{job_id}").data.decode("utf-8")
    assert "Concision" in body, "the report card is missing"
    assert "Wordy. Shorter:" in body, "the finding is not in the issue list"
    assert 'data-issue-id="style-' in body, "the finding is not clickable in the document"
