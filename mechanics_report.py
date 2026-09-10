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

# Verb-derived nouns that bury the action in academic prose. Curated rather
# than pattern-matched so that legitimate nouns ("government", "environment")
# are never flagged, and so each one can suggest a real verb form.
NOMINALIZATIONS = {
    'implementation': 'implement', 'examination': 'examine', 'consideration': 'consider',
    'utilisation': 'use', 'utilization': 'use', 'investigation': 'investigate',
    'application': 'apply', 'evaluation': 'evaluate', 'development': 'develop',
    'improvement': 'improve', 'assessment': 'assess', 'measurement': 'measure',
    'comparison': 'compare', 'discussion': 'discuss', 'explanation': 'explain',
    'identification': 'identify', 'determination': 'determine', 'observation': 'observe',
    'demonstration': 'demonstrate', 'preparation': 'prepare', 'reduction': 'reduce',
    'creation': 'create', 'formation': 'form', 'establishment': 'establish',
    'achievement': 'achieve', 'requirement': 'require', 'involvement': 'involve',
    'acceptance': 'accept', 'performance': 'perform', 'occurrence': 'occur',
    'provision': 'provide', 'expansion': 'expand', 'introduction': 'introduce',
    'exploration': 'explore', 'interpretation': 'interpret', 'realisation': 'realise',
    'realization': 'realize', 'recognition': 'recognise', 'contribution': 'contribute',
}

TO_BE_FORMS = {'is', 'are', 'was', 'were', 'be', 'been', 'being', 'am'}

# Above this share of "to be" verbs the prose reads as static.
TO_BE_MAX_PERCENT = 12
# Below this standard deviation of sentence length the rhythm reads as monotonous.
SENTENCE_VARIETY_MIN_SD = 4.0
# Below this moving-average type-token ratio the vocabulary reads as repetitive.
LEXICAL_DIVERSITY_MIN = 0.65

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


def _sentence_variety(sentences):
    """Standard deviation of sentence length. Good prose varies; a low spread
    means every sentence is the same shape."""
    lengths = [len(_words(s['text'])) for s in sentences]
    lengths = [n for n in lengths if n > 0]
    if len(lengths) < 5:
        return None, None
    mean = sum(lengths) / len(lengths)
    sd = (sum((n - mean) ** 2 for n in lengths) / len(lengths)) ** 0.5
    return round(mean, 1), round(sd, 1)


def _lexical_diversity(words_lower):
    """Moving-average type-token ratio. Averaging fixed windows keeps the
    figure comparable between short and long texts, unlike a raw ratio."""
    window = 50
    if len(words_lower) < window:
        return round(len(set(words_lower)) / len(words_lower), 2) if words_lower else None
    ratios = [len(set(words_lower[i:i + window])) / window
              for i in range(len(words_lower) - window + 1)]
    return round(sum(ratios) / len(ratios), 2)


def _academic_style(text, sentences):
    """Wordiness patterns that weaken academic prose: buried verbs, empty
    sentence openers, and an over-reliance on forms of "to be"."""
    lowered = text.lower()

    # Nominalisations in the classic "the <noun> of" frame, which is
    # unambiguous, unlike a bare "the <noun>".
    found = []
    for noun, verb in NOMINALIZATIONS.items():
        hits = len(re.findall(r'\b(?:the|a|an)\s+' + noun + r'\s+of\b', lowered))
        if hits:
            found.append({'noun': noun, 'verb': verb, 'count': hits})
    found.sort(key=lambda item: -item['count'])

    # Empty openers: "There is a need for X" says less than "X is needed".
    expletives = len(re.findall(r'(?:^|[.!?]\s+)(?:there|it)\s+(?:is|are|was|were)\b',
                                text, flags=re.IGNORECASE))

    words = _words(text)
    to_be = sum(1 for w in words if w.lower() in TO_BE_FORMS)
    to_be_percent = int(round(100 * to_be / len(words))) if words else 0

    parts = []
    if found:
        listed = ', '.join('"the %s of" -> "%s"' % (f['noun'], f['verb']) for f in found[:3])
        parts.append('%d buried verb%s: %s.'
                     % (len(found), 's' if len(found) != 1 else '', listed))
    if expletives:
        parts.append('%d sentence%s open with "there is" or "it is".'
                     % (expletives, 's' if expletives != 1 else ''))
    if to_be_percent > TO_BE_MAX_PERCENT:
        parts.append('Forms of "to be" make up %d%% of your words, above the %d%% guideline \u2014 '
                     'try stronger verbs.' % (to_be_percent, TO_BE_MAX_PERCENT))
    elif not parts:
        parts.append('No buried verbs or empty sentence openers found.')

    return {
        'nominalisations': found[:5],
        'expletiveOpeners': expletives,
        'toBePercent': to_be_percent,
        'summary': ' '.join(parts)
    }


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

    mean_len, sd_len = _sentence_variety(sentences)
    if sd_len is not None and sd_len < SENTENCE_VARIETY_MIN_SD:
        parts.append('Your sentences are all a similar length (average %s words, spread %s) \u2014 '
                     'varying them would improve the rhythm.' % (mean_len, sd_len))

    return {
        'longSentenceCount': long_count,
        'passiveVoicePercent': passive_percent,
        'runOnCount': run_on_count,
        'meanSentenceLength': mean_len,
        'sentenceLengthSD': sd_len,
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

    diversity = _lexical_diversity([w.lower() for w in words])
    if diversity is not None and diversity < LEXICAL_DIVERSITY_MIN:
        parts.append('Vocabulary variety is low (%.2f) \u2014 you reuse the same words often.'
                     % diversity)

    return {
        'repeatedWords': repeated,
        'overusedFillers': overused,
        'lexicalDiversity': diversity,
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


# Style penalty weights. Counts are normalised per 100 words so a long essay
# is not punished simply for being long. Each component is capped so no single
# weakness can sink the score, and the total is capped too: grammar and
# spelling remain the primary signal.
PENALTY_PER_NOMINALIZATION = 1.5
PENALTY_PER_EXPLETIVE = 1.5
PENALTY_PER_TO_BE_POINT = 0.8
PENALTY_PER_PASSIVE_POINT = 0.3
PENALTY_MONOTONOUS = 4
PENALTY_LOW_DIVERSITY = 4
PENALTY_CAP_PER_COMPONENT = 6
STYLE_PENALTY_CAP = 25


def style_penalty(report, word_count):
    """Points to deduct from the writing score for style weaknesses that
    grammar checking cannot see. Returns (penalty, breakdown)."""
    if not report or not word_count:
        return 0, []

    def per_100(n):
        return 100.0 * n / word_count

    def capped(value):
        return min(value, PENALTY_CAP_PER_COMPONENT)

    style = report.get('academicStyle') or {}
    clarity = report.get('sentenceClarity') or {}
    variety = report.get('repetitionVariety') or {}

    breakdown = []

    noms = sum(item.get('count', 0) for item in (style.get('nominalisations') or []))
    if noms:
        pts = capped(PENALTY_PER_NOMINALIZATION * per_100(noms))
        breakdown.append(('buried verbs', round(pts, 1)))

    expl = style.get('expletiveOpeners') or 0
    if expl:
        pts = capped(PENALTY_PER_EXPLETIVE * per_100(expl))
        breakdown.append(('empty sentence openers', round(pts, 1)))

    to_be = style.get('toBePercent') or 0
    if to_be > TO_BE_MAX_PERCENT:
        pts = capped(PENALTY_PER_TO_BE_POINT * (to_be - TO_BE_MAX_PERCENT))
        breakdown.append(('"to be" overuse', round(pts, 1)))

    passive = clarity.get('passiveVoicePercent') or 0
    if passive > PASSIVE_RECOMMENDED_PERCENT:
        pts = min(PENALTY_PER_PASSIVE_POINT * (passive - PASSIVE_RECOMMENDED_PERCENT), 4)
        breakdown.append(('passive voice', round(pts, 1)))

    sd = clarity.get('sentenceLengthSD')
    if sd is not None and sd < SENTENCE_VARIETY_MIN_SD:
        breakdown.append(('monotonous sentence length', PENALTY_MONOTONOUS))

    diversity = variety.get('lexicalDiversity')
    if diversity is not None and diversity < LEXICAL_DIVERSITY_MIN:
        breakdown.append(('repetitive vocabulary', PENALTY_LOW_DIVERSITY))

    total = min(sum(pts for _, pts in breakdown), STYLE_PENALTY_CAP)
    return int(round(total)), breakdown


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
        'academicStyle': _academic_style(text, sentences),
        'structuralSignals': _structural_signals(text, sentences),
        'readability': _readability(text, sentences)
    }
