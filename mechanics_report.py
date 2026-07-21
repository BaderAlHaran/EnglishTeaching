"""Writing Mechanics Report: rule-based writing feedback (no AI/LLM).

Analyzes sentence clarity, repetition, structure, and readability using
counts, fixed word lists, and the standard Flesch-Kincaid formula. Reuses
sentence records and passive-voice detection from improve_analysis rather
than re-parsing the text.
"""

import os
import re
from collections import Counter

MECHANICS_REPORT_ENABLED = os.environ.get('MECHANICS_REPORT_ENABLED', 'true').lower() in {'1', 'true', 'yes', 'on'}

LONG_SENTENCE_WORDS = 30
PASSIVE_RECOMMENDED_PERCENT = 20
REPEATED_WORD_MIN_COUNT = 4
FILLER_MAX_USES = 3
PARAGRAPH_DEVIATION = 0.5
REPETITIVE_STARTER_RUN = 3

STOPWORDS = {
    'the', 'and', 'that', 'this', 'with', 'from', 'have', 'has', 'had', 'was', 'were', 'been',
    'are', 'is', 'be', 'being', 'will', 'would', 'could', 'should', 'can', 'may', 'might',
    'must', 'shall', 'a', 'an', 'in', 'on', 'at', 'to', 'of', 'for', 'by', 'as', 'or', 'but',
    'not', 'it', 'its', 'they', 'their', 'them', 'these', 'those', 'there', 'then', 'than',
    'when', 'which', 'while', 'where', 'who', 'whom', 'whose', 'what', 'how', 'why', 'also',
    'into', 'over', 'under', 'about', 'after', 'before', 'between', 'because', 'through',
    'during', 'each', 'more', 'most', 'much', 'many', 'some', 'such', 'both', 'other', 'only',
    'same', 'so', 'too', 'very', 'just', 'any', 'all', 'his', 'her', 'she', 'he', 'we', 'our',
    'you', 'your', 'i', 'my', 'me', 'us', 'him', 'do', 'does', 'did', 'done', 'if', 'no', 'nor',
    'own', 'out', 'up', 'down', 'off', 'again', 'further', 'once', 'here', 'now', 'even', 'still'
}

FILLER_PHRASES = [
    'very', 'really', 'basically', 'actually', 'literally', 'obviously', 'quite',
    'in conclusion', 'in order to', 'of course', 'kind of', 'sort of', 'a lot'
]

TRANSITION_OPENERS = [
    'however', 'therefore', 'additionally', 'furthermore', 'in contrast', 'for example',
    'as a result', 'moreover', 'consequently', 'on the other hand', 'in addition',
    'similarly', 'nevertheless', 'nonetheless', 'meanwhile', 'thus', 'finally',
    'first', 'firstly', 'second', 'secondly', 'third', 'thirdly', 'next', 'also',
    'in fact', 'for instance', 'on the contrary', 'in summary', 'in conclusion', 'to conclude', 'overall', 'ultimately'
]


def _words(text):
    return re.findall(r"[A-Za-z]+(?:'[A-Za-z]+)?", text)


def _fallback_sentences(text):
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [{'id': idx + 1, 'text': part.strip()} for idx, part in enumerate(parts) if part.strip()]


def _count_syllables(word):
    word = word.lower()
    groups = re.findall(r'[aeiouy]+', word)
    count = len(groups)
    if word.endswith('e') and not word.endswith(('le', 'ee', 'ye')) and count > 1:
        count -= 1
    return max(1, count)


def _truncate(sentence_text, limit=140):
    text = ' '.join(sentence_text.split())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(' ', 1)[0] + '...'


def _sentence_clarity(sentences, passive_ids, issues):
    long_examples = []
    long_count = 0
    for sentence in sentences:
        word_count = len(_words(sentence['text']))
        if word_count > LONG_SENTENCE_WORDS:
            long_count += 1
            if len(long_examples) < 3:
                long_examples.append(_truncate(sentence['text']))

    total = len(sentences)
    passive_percent = int(round(100 * len(passive_ids) / total)) if total else 0

    run_on_count = sum(
        1 for issue in issues
        if 'run-on' in (issue.get('message') or '').lower() or 'comma splice' in (issue.get('message') or '').lower()
    )

    parts = []
    if long_count:
        parts.append(f"{long_count} sentence{'s' if long_count != 1 else ''} exceed{'s' if long_count == 1 else ''} {LONG_SENTENCE_WORDS} words.")
    else:
        parts.append(f"No sentences exceed {LONG_SENTENCE_WORDS} words.")
    if passive_percent > PASSIVE_RECOMMENDED_PERCENT:
        parts.append(f"Passive voice is used in {passive_percent}% of sentences, above the recommended {PASSIVE_RECOMMENDED_PERCENT}%.")
    else:
        parts.append(f"Passive voice is used in {passive_percent}% of sentences.")
    if run_on_count:
        parts.append(f"{run_on_count} possible run-on sentence{'s' if run_on_count != 1 else ''} detected.")

    return {
        'longSentenceCount': long_count,
        'passiveVoicePercent': passive_percent,
        'runOnCount': run_on_count,
        'examples': long_examples,
        'summary': ' '.join(parts)
    }


def _repetition_variety(text):
    words = [w.lower() for w in _words(text)]
    counts = Counter(w for w in words if len(w) >= 4 and w not in STOPWORDS)
    repeated = [
        {'word': word, 'count': count}
        for word, count in counts.most_common()
        if count >= REPEATED_WORD_MIN_COUNT
    ][:3]

    lowered = text.lower()
    overused = []
    for phrase in FILLER_PHRASES:
        hits = len(re.findall(r'\b' + re.escape(phrase) + r'\b', lowered))
        if hits > FILLER_MAX_USES:
            overused.append({'phrase': phrase, 'count': hits})
    overused.sort(key=lambda item: -item['count'])

    parts = []
    if repeated:
        listed = ', '.join(f"\"{item['word']}\" ({item['count']}x)" for item in repeated)
        parts.append(f"Frequently repeated words: {listed}.")
    else:
        parts.append('Good word variety; no word is heavily repeated.')
    if overused:
        listed = ', '.join(f"\"{item['phrase']}\" ({item['count']}x)" for item in overused)
        parts.append(f"Overused filler: {listed}.")

    return {
        'repeatedWords': repeated,
        'overusedFillers': overused,
        'summary': ' '.join(parts)
    }


def _structural_signals(text, sentences):
    paragraphs = [p.strip() for p in re.split(r'\n\s*\n|\n', text) if p.strip()]
    para_word_counts = [len(_words(p)) for p in paragraphs]
    para_count = len(paragraphs)

    unbalanced = 0
    if para_count >= 2:
        average = sum(para_word_counts) / para_count
        for count in para_word_counts:
            if average and abs(count - average) / average > PARAGRAPH_DEVIATION:
                unbalanced += 1
        if unbalanced:
            balance = f"{unbalanced} of {para_count} paragraphs deviate notably from the average length."
        else:
            balance = f"All {para_count} paragraphs are reasonably balanced in length."
    else:
        balance = 'Single paragraph; paragraph balance not applicable.'

    transition_percent = None
    if para_count >= 2:
        openers = 0
        for paragraph in paragraphs[1:]:
            first = paragraph.lower().lstrip('"\'(')
            if any(first.startswith(t) for t in TRANSITION_OPENERS):
                openers += 1
        transition_percent = int(round(100 * openers / (para_count - 1)))

    repetitive = []
    run_start = 0
    starters = []
    for sentence in sentences:
        first_words = _words(sentence['text'])
        starters.append(first_words[0].lower() if first_words else '')
    idx = 0
    while idx < len(starters):
        end = idx
        while end + 1 < len(starters) and starters[end + 1] == starters[idx] and starters[idx]:
            end += 1
        run_length = end - idx + 1
        if run_length >= REPETITIVE_STARTER_RUN:
            word = starters[idx].capitalize()
            repetitive.append(f"Sentences {sentences[idx]['id']}-{sentences[end]['id']} all start with \"{word}\"")
        idx = end + 1

    parts = [balance]
    if transition_percent is not None:
        parts.append(f"{transition_percent}% of paragraphs open with a transition word.")
    if repetitive:
        parts.append(f"{len(repetitive)} run{'s' if len(repetitive) != 1 else ''} of sentences share the same opening word.")

    return {
        'paragraphBalance': balance,
        'transitionOpenerPercent': transition_percent,
        'repetitiveStarters': repetitive,
        'summary': ' '.join(parts)
    }


def _readability(text, sentences):
    words = _words(text)
    word_count = len(words)
    sentence_count = max(1, len(sentences))
    if not word_count:
        return {'gradeLevel': 0, 'label': 'Not enough text to measure readability.'}

    syllables = sum(_count_syllables(w) for w in words)
    grade = 0.39 * (word_count / sentence_count) + 11.8 * (syllables / word_count) - 15.59
    grade = max(0, round(grade, 1))
    grade_int = int(round(grade))

    if grade_int <= 5:
        note = 'simple and easy to read'
    elif grade_int <= 9:
        note = 'clear and accessible'
    elif grade_int <= 13:
        note = 'appropriate for academic writing'
    else:
        note = 'very complex; consider simplifying'
    return {
        'gradeLevel': grade,
        'label': f"Grade {grade_int} — {note}"
    }


def build_report(text, sentences=None, passive_sentence_ids=None, issues=None):
    """Build the mechanics report. All inputs beyond text are optional; when
    the caller has analysis results (sentence records, passive ids, issues)
    they are reused instead of re-deriving them."""
    text = text or ''
    if not text.strip():
        return None
    if sentences is None:
        sentences = _fallback_sentences(text)
    passive_sentence_ids = passive_sentence_ids or []
    issues = issues or []

    return {
        'sentenceClarity': _sentence_clarity(sentences, passive_sentence_ids, issues),
        'repetitionVariety': _repetition_variety(text),
        'structuralSignals': _structural_signals(text, sentences),
        'readability': _readability(text, sentences)
    }
