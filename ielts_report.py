"""IELTS checks for the IELTS writing checker page.

Every check is a plain rule, no language model: word count against the task
minimum (leaving out wording copied from the question, which examiners do not
count), paragraphing, the Task 1 overview, the Task 2 conclusion, formal
register, and phrases so common in IELTS answers that they add nothing.

It deliberately does not estimate a band score. That would need calibrating
against examiner-marked scripts, and an invented number would mislead the
students most likely to trust it.
"""
import re

TASKS = {
    'task2': {'label': 'Task 2 essay', 'minimum': 250, 'minutes': 40, 'criterion': 'Task Response'},
    'task1': {'label': 'Academic Task 1 report', 'minimum': 150, 'minutes': 20, 'criterion': 'Task Achievement'},
}
DEFAULT_TASK = 'task2'

# Five words in a row shared with the question counts as copying. Shorter
# runs ("the number of people") turn up by chance in any answer on the topic.
COPY_MIN_RUN = 5

# Numbers count as words in IELTS ("rose to 45% in 2010" is five words), so
# unlike the general checker this counts digits. The live counter in
# script.js uses the same pattern so the two numbers agree.
WORD_RE = re.compile(r"[A-Za-z0-9]+(?:['’][A-Za-z0-9]+)?")

_APOS = "['’]"
CONTRACTION_RE = re.compile(
    r"\b(?:[A-Za-z]+n" + _APOS + r"t"
    r"|[A-Za-z]+" + _APOS + r"(?:re|ve|ll|d|m)"
    r"|(?:it|that|there|here|what|who|he|she|where|how|let)" + _APOS + r"s)\b",
    re.IGNORECASE,
)
_NT_IRREGULAR = {"can't": 'cannot', "won't": 'will not', "shan't": 'shall not', "ain't": ''}
_SUFFIX_EXPANSIONS = {
    're': ['are'], 've': ['have'], 'll': ['will'], 'm': ['am'],
    'd': ['would', 'had'], 's': ['is', 'has'],
}

# (phrase, suggested replacements), matched as whole words in any case.
INFORMAL_PHRASES = [
    ('gonna', ['going to']),
    ('wanna', ['want to']),
    ('gotta', ['have to', 'must']),
    ('kinda', ['somewhat', 'rather']),
    ('sorta', ['somewhat', 'rather']),
    ('kids', ['children']),
    ('kid', ['child']),
    ('guys', ['people']),
    ('okay', ['acceptable']),
    ('ok', ['acceptable']),
    ('stuff', []),
    ('a lot of', ['many', 'much', 'a great deal of']),
    ('lots of', ['many', 'much']),
    ('totally', ['completely', 'entirely']),
]

OVERUSED_PHRASES = [
    'in this day and age', 'since the dawn of time', 'since the beginning of time',
    'from time immemorial', 'it goes without saying', 'needless to say',
    'last but not least', 'in a nutshell', 'a double-edged sword',
    'every coin has two sides', 'it is undeniable that', 'it cannot be denied that',
]

# Sentences lifted from coaching templates. Examiners are trained to
# discount memorised language, so it earns nothing.
MEMORISED_PHRASES = [
    'this essay will discuss', 'this essay will look at', 'in this essay i will',
    'i am going to discuss', 'it is often said that', 'it is often argued that',
    'as far as i am concerned', 'i will discuss both views',
    'there are both advantages and disadvantages',
]

# Academic Task 1 has to quote the figures it describes.
NUMBER_RE = re.compile(r'\b\d+(?:[.,]\d+)?\s*(?:%|per cent|percent)?\b', re.IGNORECASE)
TASK1_MIN_FIGURES = 3

OPINION_RE = re.compile(
    r"\b(?:I (?:think|believe|feel|agree|disagree)|in my (?:opinion|view)|personally)\b",
    re.IGNORECASE,
)
OVERVIEW_RE = re.compile(
    r"\b(?:overall|in general|generally speaking|broadly speaking|on the whole|at (?:a|first) glance"
    r"|it is (?:clear|evident|apparent) that|it can be seen that"
    r"|the (?:main|most (?:noticeable|striking|significant|obvious)) "
    r"(?:trend|feature|change|difference|point))\b",
    re.IGNORECASE,
)
CONCLUSION_OPENERS = (
    'in conclusion', 'to conclude', 'to sum up', 'in summary', 'to summarise',
    'to summarize', 'overall', 'all in all', 'in short', 'on balance',
    'all things considered', 'taking everything into account',
)
# "So," opening a sentence reads as speech; "So far" is fine.
SO_OPENER_RE = re.compile(r"(?:^|(?<=[.!?] ))So\b(?!\s+far\b)", re.MULTILINE)

MSG_CONTRACTION = 'Contraction. Use the full form in IELTS Writing.'
MSG_INFORMAL = 'Too informal for IELTS Writing.'
MSG_STUFF = 'Too informal for IELTS Writing. Name the actual thing instead.'
MSG_SO = '"So" at the start of a sentence sounds conversational.'
MSG_EXCLAMATION = 'Exclamation marks are too informal for IELTS Writing.'
MSG_OPINION = 'Task 1 asks you to describe the information, not give your opinion.'
MSG_OVERUSED = 'One of the most overused phrases in IELTS answers. Say it plainly or cut it.'
MSG_NOWADAYS = ('Starting with "Nowadays" is one of the most common IELTS openings. '
                'Try opening with the topic itself.')
MSG_MEMORISED = ('Memorised template sentence. Examiners discount these, so put it in '
                 'your own words.')
MSG_COPIED = "Copied from the question. Examiners don't count copied words, so put this in your own words."


def _phrase_re(phrase):
    return re.compile(r'\b' + r'\s+'.join(re.escape(part) for part in phrase.split()) + r'\b',
                      re.IGNORECASE)


_INFORMAL_RES = [(_phrase_re(phrase), suggestions) for phrase, suggestions in INFORMAL_PHRASES]
_OVERUSED_RES = [_phrase_re(phrase) for phrase in OVERUSED_PHRASES]
_MEMORISED_RES = [_phrase_re(phrase) for phrase in MEMORISED_PHRASES]


def _tokens(text):
    return [(m.group(0).lower().replace('’', "'"), m.start(), m.end())
            for m in WORD_RE.finditer(text or '')]


def count_words(text):
    return len(WORD_RE.findall(text or ''))


def _match_case(source, options):
    if source[:1].isupper():
        return [option[:1].upper() + option[1:] for option in options]
    return list(options)


def _expand_contraction(token):
    plain = token.replace('’', "'")
    lower = plain.lower()
    if lower == "let's":
        options = ['let us']
    elif lower in _NT_IRREGULAR:
        options = [_NT_IRREGULAR[lower]] if _NT_IRREGULAR[lower] else []
    elif lower.endswith("n't"):
        options = [lower[:-3] + ' not']
    else:
        stem, _, suffix = lower.rpartition("'")
        options = ['%s %s' % (stem, word) for word in _SUFFIX_EXPANSIONS.get(suffix, [])]
    return _match_case(plain, options)


def _plural(count, singular, plural=None):
    return '%d %s' % (count, singular if count == 1 else (plural or singular + 's'))


def _join(parts):
    if len(parts) <= 1:
        return ''.join(parts)
    return ', '.join(parts[:-1]) + ' and ' + parts[-1]


def _snippet(text, limit=70):
    piece = ' '.join((text or '').split())
    if len(piece) <= limit:
        return piece
    return piece[:limit].rsplit(' ', 1)[0] + '...'


def _check(status, title, detail):
    return {'status': status, 'title': title, 'detail': detail}


def _highlight(start, end, message, suggestions=None):
    return {'start': start, 'end': end, 'message': message, 'suggestions': suggestions or []}


def _copied_spans(text, question):
    """(start, end) spans of the answer copied from the question, and how
    many words they contain."""
    question_words = [word for word, _, _ in _tokens(question)]
    if len(question_words) < COPY_MIN_RUN:
        return [], 0
    grams = {tuple(question_words[i:i + COPY_MIN_RUN])
             for i in range(len(question_words) - COPY_MIN_RUN + 1)}
    words = _tokens(text)
    copied = [False] * len(words)
    for i in range(len(words) - COPY_MIN_RUN + 1):
        if tuple(word for word, _, _ in words[i:i + COPY_MIN_RUN]) in grams:
            for j in range(i, i + COPY_MIN_RUN):
                copied[j] = True
    spans = []
    i = 0
    while i < len(words):
        if not copied[i]:
            i += 1
            continue
        j = i
        while j + 1 < len(words) and copied[j + 1]:
            j += 1
        spans.append((words[i][1], words[j][2]))
        i = j + 1
    return spans, sum(copied)


def _word_count_check(total, copied, counted, minimum, criterion):
    if counted < minimum:
        if copied:
            detail = ("%d words, but %d are copied from the question and examiners don't count "
                      "those. That leaves %d, under the %d-word minimum." % (total, copied, counted, minimum))
        else:
            detail = ("%d words, under the %d-word minimum. Answers under the minimum lose marks "
                      "for %s." % (total, minimum, criterion))
        return _check('fail', 'Word count', detail)
    if copied:
        return _check('pass', 'Word count', '%d words, %d copied from the question, so %d count '
                      '(minimum %d).' % (total, copied, counted, minimum))
    return _check('pass', 'Word count', '%d words (minimum %d).' % (total, minimum))


def _paragraph_check(count, task):
    if count <= 1:
        return _check('fail', 'Paragraphs', 'Your answer is one block of text. Paragraphing counts towards '
                      'Coherence and Cohesion, so split it into paragraphs.')
    if task == 'task2':
        low, high, usual = 4, 6, 'four or five'
        shape = 'an introduction, two or three body paragraphs and a conclusion'
    else:
        low, high, usual = 3, 5, 'three or four'
        shape = 'an introduction, an overview and one or two paragraphs of detail'
    if count < low:
        task_name = 'Task 2' if task == 'task2' else 'Task 1'
        return _check('warn', 'Paragraphs', '%s. Most %s answers use %s: %s.'
                      % (_plural(count, 'paragraph'), task_name, usual, shape))
    if count > high:
        return _check('warn', 'Paragraphs', "%d paragraphs is a lot for one answer. Very short paragraphs "
                      "usually mean the ideas aren't developed." % count)
    return _check('pass', 'Paragraphs', '%d paragraphs, enough for %s.' % (count, shape))


def _overview_check(text):
    match = OVERVIEW_RE.search(text)
    if match:
        return _check('pass', 'Overview', 'Found one: "%s"' % _snippet(text[match.start():], 60))
    # Phrase matching can miss an overview worded another way, so a miss is a
    # prompt to check rather than a verdict.
    return _check('warn', 'Overview', "We couldn't find an overview. Examiners expect a summary of the "
                  'main trends or features, often starting with "Overall,". If you have one, make it easy '
                  'to spot. Without one, the Task Achievement mark is limited.')


def _conclusion_check(last_paragraph):
    opening = last_paragraph.lower().lstrip('"\'( ')
    if opening.startswith(CONCLUSION_OPENERS):
        return _check('pass', 'Conclusion', 'Your last paragraph opens as a conclusion.')
    return _check('warn', 'Conclusion', "Your last paragraph doesn't open like a conclusion. End by "
                  'restating your position clearly. Starting with "In conclusion," is fine.')


def _register_findings(text):
    """Contractions, informal words, conversational "So" and exclamation
    marks. Returns (highlights, summary parts for the checklist)."""
    contractions = [
        _highlight(m.start(), m.end(), MSG_CONTRACTION, _expand_contraction(m.group(0)))
        for m in CONTRACTION_RE.finditer(text)
    ]
    informal = []
    for pattern, suggestions in _INFORMAL_RES:
        for m in pattern.finditer(text):
            message = MSG_STUFF if m.group(0).lower() == 'stuff' else MSG_INFORMAL
            informal.append(_highlight(m.start(), m.end(), message, _match_case(m.group(0), suggestions)))
    so_openers = [_highlight(m.start(), m.end(), MSG_SO, ['Therefore', 'As a result'])
                  for m in SO_OPENER_RE.finditer(text)]
    exclamations = [_highlight(m.start(), m.end(), MSG_EXCLAMATION, ['.'])
                    for m in re.finditer(r'!', text)]

    parts = []
    if contractions:
        parts.append(_plural(len(contractions), 'contraction'))
    if informal:
        parts.append(_plural(len(informal), 'informal word'))
    if so_openers:
        parts.append(_plural(len(so_openers), 'sentence') + ' starting with "So"')
    if exclamations:
        parts.append(_plural(len(exclamations), 'exclamation mark'))
    return contractions + informal + so_openers + exclamations, parts


def _overused_findings(text):
    found = []
    for pattern in _OVERUSED_RES:
        found += [_highlight(m.start(), m.end(), MSG_OVERUSED) for m in pattern.finditer(text)]
    opener = re.match(r'\s*(Nowadays)\b', text, re.IGNORECASE)
    if opener:
        found.append(_highlight(opener.start(1), opener.end(1), MSG_NOWADAYS))
    found.sort(key=lambda item: item['start'])
    return found


def _memorised_findings(text):
    found = []
    for pattern in _MEMORISED_RES:
        found += [_highlight(m.start(), m.end(), MSG_MEMORISED) for m in pattern.finditer(text)]
    found.sort(key=lambda item: item['start'])
    return found


def _data_check(text):
    """Academic Task 1 answers have to support the description with figures."""
    figures = len(NUMBER_RE.findall(text))
    if figures >= TASK1_MIN_FIGURES:
        return _check('pass', 'Data', '%s quoted from the chart.' % _plural(figures, 'figure'))
    return _check('warn', 'Data', '%s quoted. Academic Task 1 asks you to support the description '
                  'with data from the chart, so include the numbers that matter.'
                  % _plural(figures, 'figure'))


def build_report(text, task=DEFAULT_TASK, question=None):
    """Checklist and highlights for one IELTS answer, or None for empty text.

    Each check has a status: 'pass', 'warn', 'fail', or 'info' (nothing to
    judge, e.g. no question was given). Highlights carry character offsets
    into `text` so they can be shown in the document view."""
    text = text or ''
    if not text.strip():
        return None
    if task not in TASKS:
        task = DEFAULT_TASK
    spec = TASKS[task]
    minimum = spec['minimum']
    question = (question or '').strip()

    total = count_words(text)
    copied_spans, copied = _copied_spans(text, question)
    counted = total - copied
    paragraphs = [p.strip() for p in text.split('\n') if p.strip()]

    checks = [
        _word_count_check(total, copied, counted, minimum, spec['criterion']),
        _paragraph_check(len(paragraphs), task),
    ]

    opinions = []
    if task == 'task1':
        checks.append(_overview_check(text))
        checks.append(_data_check(text))
        opinions = [_highlight(m.start(), m.end(), MSG_OPINION) for m in OPINION_RE.finditer(text)]
        if opinions:
            checks.append(_check('warn', 'Opinions', '%s found. Task 1 asks you to describe the '
                                 'information, not comment on it.' % _plural(len(opinions), 'personal opinion')))
        else:
            checks.append(_check('pass', 'Opinions', 'None found. Task 1 should only describe the information.'))
    elif len(paragraphs) >= 2:
        checks.append(_conclusion_check(paragraphs[-1]))

    register, register_parts = _register_findings(text)
    if register_parts:
        checks.append(_check('warn', 'Formal language',
                             '%s. They are highlighted in your text.' % _join(register_parts)))
    else:
        checks.append(_check('pass', 'Formal language', 'No contractions or informal words found.'))

    memorised = _memorised_findings(text)
    if memorised:
        checks.append(_check('warn', 'Template language', '%s. Examiners discount memorised '
                             'sentences, so they add nothing to your band.'
                             % _plural(len(memorised), 'memorised phrase')))
    else:
        checks.append(_check('pass', 'Template language', 'No memorised template sentences.'))

    overused = _overused_findings(text)
    if overused:
        first = text[overused[0]['start']:overused[0]['end']]
        checks.append(_check('warn', 'Overused phrases', '%s, for example "%s". Examiners see these '
                             'constantly, so say it plainly or cut it.' % (_plural(len(overused), 'overused phrase'), first)))
    else:
        checks.append(_check('pass', 'Overused phrases', 'None of the most overused IELTS phrases.'))

    if not question:
        checks.append(_check('info', 'Copied wording',
                             'Paste the question into the question box to check for wording copied from it.'))
    elif copied:
        start, end = copied_spans[0]
        checks.append(_check('warn', 'Copied wording', '%d words copied from the question, for example "%s". '
                             'Put them in your own words so they count.' % (copied, _snippet(text[start:end], 60))))
    else:
        checks.append(_check('pass', 'Copied wording', 'Nothing copied from the question.'))

    # Order matters: when two highlights overlap, the earlier one wins, so the
    # short, fixable findings come before long copied spans.
    highlights = (register + opinions + memorised + overused
                  + [_highlight(s, e, MSG_COPIED) for s, e in copied_spans])

    return {
        'task': task,
        'question': question,
        'taskLabel': spec['label'],
        'minimumWords': minimum,
        'minutes': spec['minutes'],
        'wordCount': total,
        'copiedWords': copied,
        'countedWords': counted,
        'paragraphCount': len(paragraphs),
        'checks': checks,
        'highlights': highlights,
    }
