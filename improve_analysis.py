import importlib.resources as importlib_resources
import logging
import math
import os
import re
import time

from markupsafe import Markup, escape

AI_CHECKER_ENABLED = os.environ.get('AI_CHECKER_ENABLED', 'true').lower() in {'1', 'true', 'yes', 'on'}
SPELLING_ALLOWLIST = {
    'Bader', 'Kuwait', 'GCC', 'MENA', 'SaaS', 'STEM', 'API', 'APIs', 'COVID', 'COVID-19',
    'Python', 'Flask', 'Postgres', 'PostgreSQL', 'SQL', 'NoSQL', 'GitHub', 'Render',
    'IELTS', 'TOEFL', 'SAT', 'GRE', 'GPA', 'UK', 'USA', 'UAE', 'EU', 'UN', 'UNESCO',
    'Arabic', 'Islam', 'Qatar', 'Oman', 'Bahrain', 'Riyadh', 'Jeddah', 'Dammam'
}
_IMPROVE_NLP = None
_IMPROVE_ALLOWLIST_CACHE = None
_IMPROVE_SYMSPELL = None

def run_local_analysis(text, progress_cb=None, timeout_seconds=20, start_time=None, logger=None):
    logger = logger or logging.getLogger(__name__)
    if not AI_CHECKER_ENABLED:
        return None, "Writing checker unavailable. Please use Human Review.", None

    text = text or ''

    global _IMPROVE_NLP
    global _IMPROVE_ALLOWLIST_CACHE
    global _IMPROVE_SYMSPELL

    warnings = []

    if start_time is None:
        start_time = time.time()

    def _timed_out():
        return (time.time() - start_time) > timeout_seconds

    def _time_guard():
        if _timed_out():
            if not warnings or 'partial' not in warnings[-1].lower():
                warnings.append('Returned partial results due to time limits.')
            return True
        return False

    if _IMPROVE_ALLOWLIST_CACHE is None:
        allowlist = set(SPELLING_ALLOWLIST)
        allowlist_path = os.path.join(os.path.dirname(__file__), 'data', 'allowlist.txt')
        try:
            with open(allowlist_path, 'r', encoding='utf-8') as handle:
                for line in handle:
                    word = line.strip()
                    if word:
                        allowlist.add(word)
        except Exception:
            pass
        _IMPROVE_ALLOWLIST_CACHE = {w.lower() for w in allowlist}

    allowlist_lower = _IMPROVE_ALLOWLIST_CACHE

    try:
        from spellchecker import SpellChecker
    except Exception as exc:
        SpellChecker = None
        warnings.append(f"Spelling checker unavailable: {exc}")

    try:
        from symspellpy import SymSpell, Verbosity
    except Exception as exc:
        SymSpell = None
        Verbosity = None
        warnings.append(f"SymSpell unavailable: {exc}")

    sym_spell = None
    symspell_verbosity = None
    if SymSpell:
        try:
            if _IMPROVE_SYMSPELL is None:
                sym_spell = SymSpell(max_dictionary_edit_distance=2, prefix_length=7)
                dict_loaded = False
                try:
                    with importlib_resources.path('symspellpy', 'frequency_dictionary_en_82_765.txt') as dict_path:
                        dict_loaded = sym_spell.load_dictionary(str(dict_path), 0, 1)
                except Exception:
                    dict_loaded = False
                if not dict_loaded:
                    fallback_path = os.path.join(os.path.dirname(__file__), 'data', 'frequency_dictionary_en_82_765.txt')
                    if os.path.exists(fallback_path):
                        dict_loaded = sym_spell.load_dictionary(fallback_path, 0, 1)
                if dict_loaded:
                    for word in allowlist_lower:
                        if word:
                            sym_spell.create_dictionary_entry(word, 1)
                    _IMPROVE_SYMSPELL = sym_spell
                else:
                    sym_spell = None
                    warnings.append("SymSpell dictionary unavailable.")
            else:
                sym_spell = _IMPROVE_SYMSPELL
            symspell_verbosity = Verbosity.TOP if sym_spell else None
        except Exception as exc:
            sym_spell = None
            symspell_verbosity = None
            warnings.append(f"SymSpell unavailable: {exc}")

    try:
        from proselint.tools import lint as proselint_lint
    except Exception as exc:
        proselint_lint = None
        warnings.append(f"Style checker unavailable: {exc}")

    try:
        from wordfreq import zipf_frequency
    except Exception:
        zipf_frequency = None

    nlp = None
    try:
        import spacy
        if _IMPROVE_NLP is None:
            _IMPROVE_NLP = spacy.load('en_core_web_sm', disable=['ner'])
        nlp = _IMPROVE_NLP
    except Exception as exc:
        warnings.append(f"NLP engine unavailable: {exc}")
        nlp = None

    issues = []

    if progress_cb:
        progress_cb(8, "Preparing checks...")

    email_pattern = re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w+\b')
    url_pattern = re.compile(r'\b(?:https?://|www\.)\S+\b')
    end_punct_count = len(re.findall(r'[.!?]', text))
    token_count = len(re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", text))
    ignored_spans = [(m.start(), m.end()) for m in email_pattern.finditer(text)]
    ignored_spans += [(m.start(), m.end()) for m in url_pattern.finditer(text)]

    def _overlaps_ignored(start, end):
        for s, e in ignored_spans:
            if start < e and end > s:
                return True
        return False

    def _sentence_id_for_span(start, end, sentences):
        for s in sentences:
            if start >= s['start'] and end <= s['end']:
                return s['id']
        return None

    def _add_issue(start, end, kind, message, suggestions=None, no_highlight=False, sentence_id=None, is_rewrite=False):
        if start is None or end is None:
            return
        if start < 0 or end <= start or start > len(text):
            return
        issues.append({
            'start': start,
            'end': end,
            'kind': kind,
            'message': message,
            'suggestions': suggestions or [],
            'sentence_id': sentence_id,
            'no_highlight': no_highlight,
            'is_rewrite': is_rewrite
        })

    def _is_code_like(word):
        return any(sym in word for sym in ('_', '/', '\\', '::', '->', '=>', '()')) or (word[:1].islower() and any(ch.isupper() for ch in word[1:]))

    def _preprocess_sentences(source_text):
        if not source_text.strip():
            return []
        end_punct = len(re.findall(r'[.!?]', source_text))
        words = re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", source_text)
        if end_punct >= 2 or len(words) <= 12:
            return []
        patterns = [
            r"\bhi\b",
            r"\bhello\b",
            r"\bhey\b",
            r"\bthis is\b",
            r"\bmy name is\b",
            r"\bhow are\b",
            r"\bhow is\b",
            r"\bi am\b",
            r"\bi'm\b"
        ]
        points = []
        for pattern in patterns:
            for match in re.finditer(pattern, source_text, flags=re.IGNORECASE):
                idx = match.start()
                if idx != 0:
                    points.append(idx)
        if not points:
            return []
        points = sorted(set(points))
        segments = []
        last = 0
        for idx in points:
            segment = source_text[last:idx].strip()
            if segment:
                segments.append(segment)
            last = idx
        tail = source_text[last:].strip()
        if tail:
            segments.append(tail)
        refined = []
        for segment in segments:
            seg_words = re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", segment)
            if len(seg_words) <= 15:
                refined.append(segment)
                continue
            split_match = re.search(r"\b(and|but|because|so|however|therefore|by contrast)\b", segment, flags=re.IGNORECASE)
            if split_match:
                idx = split_match.start()
                left = segment[:idx].strip()
                right = segment[idx:].strip()
                if left:
                    refined.append(left)
                if right:
                    refined.append(right)
            else:
                refined.append(segment)
        return refined

    def _rewrite_templates(sentence_text):
        base = sentence_text.strip()
        if not base:
            return []
        lowered = base.lower()
        name_match = re.search(r'\bthis is\s+([A-Za-z][\w-]*)', base, flags=re.IGNORECASE)
        name = name_match.group(1) if name_match else None
        if name:
            name = name.capitalize()
        casual = None
        formal = None
        if 'how are you' in lowered and 'this is' in lowered:
            casual = f"Hi, this is {name or 'your name'}. How are you doing today?"
            formal = f"Hello, this is {name or 'your name'}. How are you doing today?"
        return [s for s in (casual, formal) if s]

    def _apply_rewrite_rules(sentence_text):
        updated = sentence_text
        updated = re.sub(r"\b(i)(?=\b)", 'I', updated)
        updated = re.sub(r"\biI\b", 'I', updated)
        updated = re.sub(r"\bthis is\s+([A-Za-z][\w-]*)\s+how are\b", lambda m: f"this is {m.group(1)}. How are", updated, flags=re.IGNORECASE)
        updated = re.sub(r"\bthis is\s+([A-Za-z][\w-]*)", lambda m: f"this is {m.group(1).capitalize()}", updated, flags=re.IGNORECASE)
        updated = re.sub(r"\bmy name is\s+([A-Za-z][\w-]*)", lambda m: f"my name is {m.group(1).capitalize()}", updated, flags=re.IGNORECASE)
        updated = updated.strip()
        if updated and updated[0].islower():
            updated = updated[0].upper() + updated[1:]
        updated = re.sub(r"^(Hi|Hello|Hey)\b(?!,)", r"\1,", updated)
        return updated

    def _split_on_conjunction(sentence_text):
        match = re.search(r"\b(and|but|because|so|however|therefore|by contrast)\b", sentence_text, flags=re.IGNORECASE)
        if not match:
            return None
        idx = match.start()
        left = sentence_text[:idx].strip()
        right = sentence_text[idx:].strip()
        if left and right:
            return f"{left}. {right[0].upper() + right[1:] if right else right}"
        return None

    def _with_end_punct(sentence_text):
        stripped = sentence_text.rstrip()
        if not stripped:
            return sentence_text
        if stripped[-1] in '.!?':
            return stripped
        return stripped + '.'

    def _is_structural_rewrite(original_text, rewritten_text):
        if not rewritten_text or not original_text:
            return False
        original_end = original_text.rstrip().endswith(('.', '!', '?'))
        rewritten_end = rewritten_text.rstrip().endswith(('.', '!', '?'))
        split = bool(re.search(r'[.!?]\s+[A-Z]', rewritten_text))
        return split or (not original_end and rewritten_end)

    doc = None
    if nlp is not None:
        try:
            doc = nlp(text)
        except Exception as exc:
            doc = None
            warnings.append(f"NLP processing failed: {exc}")

    sentences = []
    sentence_flags = {}
    doc_sentences = {}

    if doc is not None:
        for sent in doc.sents:
            segment = sent.text
            if segment.strip():
                sent_id = len(sentences) + 1
                sentences.append({
                    'id': sent_id,
                    'start': sent.start_char,
                    'end': sent.end_char,
                    'text': segment.strip()
                })
                doc_sentences[sent_id] = sent
        sentence_flags = {s['id']: set() for s in sentences}
    else:
        s_start = 0
        for match in re.finditer(r'[.!?]+', text):
            s_end = match.end()
            segment = text[s_start:s_end]
            if segment.strip():
                sentences.append({
                    'id': len(sentences) + 1,
                    'start': s_start,
                    'end': s_end,
                    'text': segment.strip()
                })
            s_start = s_end
        if s_start < len(text):
            segment = text[s_start:]
            if segment.strip():
                sentences.append({
                    'id': len(sentences) + 1,
                    'start': s_start,
                    'end': len(text),
                    'text': segment.strip()
                })
        sentence_flags = {s['id']: set() for s in sentences}

    if end_punct_count < 2 and token_count > 12:
        pseudo = _preprocess_sentences(text)
        if pseudo:
            offset = 0
            sentences = []
            for segment in pseudo:
                start = text.find(segment, offset)
                if start == -1:
                    start = offset
                end = start + len(segment)
                sentences.append({
                    'id': len(sentences) + 1,
                    'start': start,
                    'end': end,
                    'text': segment.strip()
                })
                offset = end
            sentence_flags = {s['id']: set() for s in sentences}

    if progress_cb:
        progress_cb(18, "Checking grammar...")

    comparatives = {'more', 'less', 'rather', 'better', 'worse', 'higher', 'lower', 'greater', 'fewer'}
    greetings = {'hi', 'hello', 'dear'}
    obj_pronouns = {'me', 'him', 'her', 'us', 'them'}
    subj_pronouns = {'i', 'he', 'she', 'we', 'they'}
    determiners = {'a', 'an', 'the', 'this', 'that', 'these', 'those', 'my', 'your', 'his', 'her', 'our', 'their', 'its'}
    count_nouns = {
        'idea', 'problem', 'issue', 'result', 'study', 'case', 'factor', 'reason', 'example',
        'argument', 'method', 'solution', 'benefit', 'risk', 'model', 'approach', 'paper', 'essay',
        'work', 'research', 'analysis', 'assignment', 'project', 'thesis', 'conclusion', 'summary'
    }

    def _token_number(token):
        numbers = token.morph.get('Number')
        if numbers:
            return numbers[0]
        if token.lower_ in {'he', 'she', 'it', 'this', 'that', 'someone', 'everybody'}:
            return 'Sing'
        if token.lower_ in {'they', 'we', 'you'}:
            return 'Plur'
        return None

    def _verb_number(token):
        numbers = token.morph.get('Number')
        if numbers:
            return numbers[0]
        if token.tag_ == 'VBZ':
            return 'Sing'
        if token.tag_ == 'VBP':
            return 'Plur'
        return None

    if doc is not None:
        for token in doc:
            if _time_guard():
                break
            if token.is_space or token.is_punct:
                continue
            if _overlaps_ignored(token.idx, token.idx + len(token.text)):
                continue

            if token.pos_ == 'PROPN' and token.text and token.text[0].islower() and not token.text.isupper():
                sid = _sentence_id_for_span(token.idx, token.idx + len(token.text), sentences)
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Proper noun should be capitalized.', [token.text.capitalize()], sentence_id=sid)
                if sid is not None:
                    sentence_flags.setdefault(sid, set()).add('proper_noun')

            if token.lower_ in allowlist_lower and token.text and token.text[0].islower() and not token.text.isupper():
                sid = _sentence_id_for_span(token.idx, token.idx + len(token.text), sentences)
                proper = token.text.capitalize()
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Proper noun should be capitalized.', [proper], sentence_id=sid)
                if sid is not None:
                    sentence_flags.setdefault(sid, set()).add('proper_noun')

            if token.dep_ in {'nsubj', 'nsubjpass'} and token.head.pos_ in {'VERB', 'AUX'}:
                subj_num = _token_number(token)
                verb_num = _verb_number(token.head)
                if subj_num and verb_num and subj_num != verb_num:
                    _add_issue(token.head.idx, token.head.idx + len(token.head.text), 'grammar', 'Subject and verb may not agree.', [], sentence_id=_sentence_id_for_span(token.head.idx, token.head.idx + len(token.head.text), sentences))

            if token.pos_ == 'NOUN' and token.tag_ == 'NN' and token.lemma_.lower() in count_nouns:
                has_det = any(child.dep_ in {'det', 'poss'} for child in token.children)
                prev_token = token.nbor(-1) if token.i > 0 else None
                prev_det = prev_token is not None and prev_token.lower_ in determiners
                if not has_det and not prev_det:
                    suggestion = 'a'
                    if token.text and token.text[0].lower() in 'aeiou':
                        suggestion = 'an'
                    _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Missing article before singular noun.', [suggestion, 'the'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ in obj_pronouns and token.dep_ in {'nsubj', 'nsubjpass'}:
                subj_map = {'me': 'I', 'him': 'he', 'her': 'she', 'us': 'we', 'them': 'they'}
                suggestion = subj_map.get(token.lower_, '')
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Use subject pronoun in this position.', [suggestion] if suggestion else [], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ in subj_pronouns and token.dep_ in {'dobj', 'pobj', 'obj', 'iobj'}:
                obj_map = {'i': 'me', 'he': 'him', 'she': 'her', 'we': 'us', 'they': 'them'}
                suggestion = obj_map.get(token.lower_, '')
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Use object pronoun in this position.', [suggestion] if suggestion else [], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            next_token = token.nbor(1) if token.i + 1 < len(doc) else None
            prev_token = token.nbor(-1) if token.i > 0 else None

            if token.lower_ == 'your' and next_token and next_token.lower_ in {'are', 'were'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', "Did you mean \"you're\"?", ["you're"], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == "you're" and next_token and next_token.pos_ in {'NOUN', 'PROPN', 'ADJ'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "your"?', ['your'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'their' and next_token and next_token.lower_ in {'is', 'are', 'was', 'were'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "there"?', ['there'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'there' and next_token and next_token.pos_ in {'NOUN', 'PROPN'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "their"?', ['their'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == "they're" and next_token and next_token.pos_ in {'NOUN', 'PROPN'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "their"?', ['their'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'its' and next_token and next_token.lower_ in {'is', 'was', 'has'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', "Did you mean \"it's\"?", ["it's"], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == "it's" and next_token and next_token.pos_ in {'NOUN', 'PROPN'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "its"?', ['its'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'then' and prev_token and prev_token.lower_ in comparatives:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Use "than" for comparisons.', ['than'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

    if progress_cb:
        progress_cb(32, "Checking sentence rules...")

    filler_words = {'really', 'very', 'just', 'actually', 'basically', 'literally', 'quite', 'perhaps', 'maybe'}
    wordy_phrases = [
        (r'\bdue to the fact that\b', 'because'),
        (r'\bat this point in time\b', 'now'),
        (r'\bin order to\b', 'to'),
        (r'\bin the event that\b', 'if'),
        (r'\bhas the ability to\b', 'can'),
        (r'\bfor the purpose of\b', 'to'),
        (r'\ba large number of\b', 'many'),
        (r'\ba majority of\b', 'most'),
        (r'\bin the near future\b', 'soon'),
        (r'\bmake a decision\b', 'decide'),
        (r'\btake into account\b', 'consider')
    ]
    confusion_patterns = [
        (r'\bcould care less\b', 'Did you mean "couldn\'t care less"?', ["couldn't care less"]),
        (r'\bbased off\b', 'Use "based on" instead of "based off".', ['based on']),
        (r'\bfor all intensive purposes\b', 'Did you mean "for all intents and purposes"?', ['for all intents and purposes']),
        (r'\birregardless\b', 'Use "regardless".', ['regardless']),
        (r'\bdifferent then\b', 'Did you mean "different from"?', ['different from']),
        (r'\bbetween you and I\b', 'Use an object pronoun after "between".', ['between you and me']),
        (r'\bthe reason is because\b', 'Avoid double "reason"; use "because" or "the reason is that".', ['because', 'the reason is that']),
        (r'\bmore better\b', 'Use "better" without "more".', ['better'])
    ]
    count_noun_targets = {'people', 'students', 'children', 'books', 'cars', 'results', 'problems', 'issues', 'items', 'examples', 'times', 'days', 'weeks', 'years', 'things'}
    long_sentence_limit = 40
    max_filler_hits = 1
    max_wordy_hits = 2

    for sentence in sentences:
        if _time_guard():
            break
        sent_text = text[sentence['start']:sentence['end']]
        sent_id = sentence['id']
        words = list(re.finditer(r"[^\W\d_]+(?:'[^\W\d_]+)?", sent_text))
        word_count = len(words)
        if word_count < 2:
            continue

        first_alpha = re.search(r'[A-Za-z]', sent_text)
        if first_alpha:
            pos = sentence['start'] + first_alpha.start()
            if text[pos:pos + 1].islower():
                sentence_flags.setdefault(sent_id, set()).add('capitalization')
                _add_issue(pos, pos + 1, 'grammar', 'Capitalize the start of the sentence.', [], sentence_id=sent_id)

        stripped = sent_text.rstrip()
        if stripped and stripped[-1] not in '.!?':
            end_pos = sentence['start'] + len(stripped)
            if end_pos > sentence['start']:
                sentence_flags.setdefault(sent_id, set()).add('end_punctuation')
                _add_issue(end_pos - 1, end_pos, 'grammar', 'Add ending punctuation.', ['.'], sentence_id=sent_id)

        if re.search(r"\bi\b", sent_text):
            for match in re.finditer(r"\bi\b", sent_text):
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Capitalize "I" when used as a pronoun.', ['I'], sentence_id=sent_id)

        for match in re.finditer(r"\b(youre|dont|cant|isnt|im|ive|ill|weve|theyre|doesnt|didnt|wont|arent|werent|wasnt|hasnt|havent|couldnt|wouldnt|shouldnt|lets|thats|theres|whats|whos|wheres|heres)\b", sent_text, flags=re.IGNORECASE):
            missing = match.group(1).lower()
            mapping = {
                'youre': "you're",
                'dont': "don't",
                'cant': "can't",
                'isnt': "isn't",
                'im': "I'm",
                'ive': "I've",
                'ill': "I'll",
                'weve': "we've",
                'theyre': "they're",
                'doesnt': "doesn't",
                'didnt': "didn't",
                'wont': "won't",
                'arent': "aren't",
                'werent': "weren't",
                'wasnt': "wasn't",
                'hasnt': "hasn't",
                'havent': "haven't",
                'couldnt': "couldn't",
                'wouldnt': "wouldn't",
                'shouldnt': "shouldn't",
                'lets': "let's",
                'thats': "that's",
                'theres': "there's",
                'whats': "what's",
                'whos': "who's",
                'wheres': "where's",
                'heres': "here's"
            }
            suggestion = mapping.get(missing, "")
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Missing apostrophe in contraction.', [suggestion] if suggestion else [], sentence_id=sent_id)

        for match in re.finditer(r"\b([A-Za-z]+)\s+\1\b", sent_text, flags=re.IGNORECASE):
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'style', 'Repeated word.', [], sentence_id=sent_id)

        for match in re.finditer(r"\b(alot|eachother|everytime)\b", sent_text, flags=re.IGNORECASE):
            typo = match.group(1).lower()
            fixes = {'alot': 'a lot', 'eachother': 'each other', 'everytime': 'every time'}
            suggestion = fixes.get(typo)
            if suggestion:
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', f'Use "{suggestion}".', [suggestion], sentence_id=sent_id)

        for match in re.finditer(r"\b(should|would|could|might|may|must)\s+of\b", sent_text, flags=re.IGNORECASE):
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "have" with this modal verb.', [f"{match.group(1)} have"], sentence_id=sent_id)

        for match in re.finditer(r"\bsuppose to\b", sent_text, flags=re.IGNORECASE):
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "supposed to".', ['supposed to'], sentence_id=sent_id)

        for match in re.finditer(r"\b(the|an|a)\s+affect\b", sent_text, flags=re.IGNORECASE):
            _add_issue(sentence['start'] + match.start(0), sentence['start'] + match.end(0), 'grammar', 'Did you mean "effect"?', ['effect'], sentence_id=sent_id)

        for match in re.finditer(r"\b(to|can|could|should|would|may|might|will|does|did|do)\s+effect\b", sent_text, flags=re.IGNORECASE):
            _add_issue(sentence['start'] + match.start(0), sentence['start'] + match.end(0), 'grammar', 'Did you mean "affect"?', ['affect'], sentence_id=sent_id)

        for pattern, message, suggestions in confusion_patterns:
            for match in re.finditer(pattern, sent_text, flags=re.IGNORECASE):
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', message, suggestions, sentence_id=sent_id)

        for match in re.finditer(r"\bless\s+([A-Za-z]+)\b", sent_text, flags=re.IGNORECASE):
            noun = match.group(1).lower()
            if noun in count_noun_targets:
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "fewer" with countable nouns.', ['fewer'], sentence_id=sent_id)

        for match in re.finditer(r"\bamount of\s+([A-Za-z]+)\b", sent_text, flags=re.IGNORECASE):
            noun = match.group(1).lower()
            if noun in count_noun_targets:
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "number of" with countable nouns.', ['number of'], sentence_id=sent_id)

        first_word = words[0].group(0).lower()
        if first_word in greetings and len(words) >= 2:
            name_token = words[1]
            after_name_index = sentence['start'] + name_token.end()
            if after_name_index < len(text) and text[after_name_index] != ',':
                _add_issue(sentence['start'] + name_token.start(), sentence['start'] + name_token.end(), 'grammar', 'Add a comma after the greeting name.', [','], sentence_id=sent_id)

        if len(words) > 12 and ',' not in sent_text:
            if re.search(r"\b(and|but|because|so)\b", sent_text, flags=re.IGNORECASE):
                sentence_flags.setdefault(sent_id, set()).add('run_on')
                conj_match = re.search(r"\b(and|but|because|so)\b", sent_text, flags=re.IGNORECASE)
                if conj_match:
                    _add_issue(sentence['start'] + conj_match.start(), sentence['start'] + conj_match.end(), 'grammar', 'Possible run-on sentence; consider a comma or split it.', [], sentence_id=sent_id)

        if re.search(r"\b(a|an)\s+[A-Za-z]", sent_text, flags=re.IGNORECASE):
            for match in re.finditer(r"\b(a|an)\s+([A-Za-z][\w-]*)", sent_text, flags=re.IGNORECASE):
                article = match.group(1).lower()
                word = match.group(2)
                lower = word.lower()
                vowel = lower[0] in 'aeiou'
                special_an = lower.startswith(('honest', 'hour', 'heir'))
                special_a = lower.startswith(('university', 'unicorn', 'user'))
                if article == 'a' and (vowel or special_an):
                    _add_issue(sentence['start'] + match.start(1), sentence['start'] + match.start(1) + 1, 'grammar', 'Use "an" before vowel sounds.', ['an'], sentence_id=sent_id)
                if article == 'an' and (special_a or (not vowel and not special_an)):
                    _add_issue(sentence['start'] + match.start(1), sentence['start'] + match.start(1) + 2, 'grammar', 'Use "a" before consonant sounds.', ['a'], sentence_id=sent_id)

        if re.search(r"\bpeople\s+is\b", sent_text, flags=re.IGNORECASE):
            match = re.search(r"\bpeople\s+is\b", sent_text, flags=re.IGNORECASE)
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "people are" for plural subject.', ['people are'], sentence_id=sent_id)

        if re.search(r"\bresults\s+shows\b", sent_text, flags=re.IGNORECASE):
            match = re.search(r"\bresults\s+shows\b", sent_text, flags=re.IGNORECASE)
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "results show" for plural subject.', ['results show'], sentence_id=sent_id)

        if re.search(r"\b(he|she|it)\s+([a-z]+)\b", sent_text, flags=re.IGNORECASE):
            for match in re.finditer(r"\b(he|she|it)\s+([a-z]+)\b", sent_text, flags=re.IGNORECASE):
                verb = match.group(2)
                auxiliaries = {'is', 'was', 'has', 'does', 'did', 'will', 'would', 'can', 'could', 'should', 'might', 'may', 'must'}
                if verb in auxiliaries or verb.endswith(('ed', 'ing')):
                    continue
                if not verb.endswith('s'):
                    _add_issue(sentence['start'] + match.start(2), sentence['start'] + match.end(2), 'grammar', 'Add -s for third-person singular.', [], sentence_id=sent_id)

        if word_count >= long_sentence_limit:
            _add_issue(sentence['start'], sentence['end'], 'style', 'Long sentence; consider splitting it.', [], sentence_id=sent_id)

        filler_hits = 0
        if filler_words:
            for match in re.finditer(r"\b(" + "|".join(sorted(filler_words)) + r")\b", sent_text, flags=re.IGNORECASE):
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'style', 'Filler word; consider removing.', [], sentence_id=sent_id)
                filler_hits += 1
                if filler_hits >= max_filler_hits:
                    break

        wordy_hits = 0
        for pattern, suggestion in wordy_phrases:
            if wordy_hits >= max_wordy_hits:
                break
            for match in re.finditer(pattern, sent_text, flags=re.IGNORECASE):
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'style', 'Wordy phrase; consider a shorter alternative.', [suggestion], sentence_id=sent_id)
                wordy_hits += 1
                if wordy_hits >= max_wordy_hits:
                    break

        doc_sentence = doc_sentences.get(sent_id)
        if doc_sentence is not None:
            passive = any(tok.dep_ in {'nsubjpass', 'auxpass'} for tok in doc_sentence)
            if passive:
                _add_issue(sentence['start'], sentence['end'], 'style', 'Passive voice; consider using active voice.', [], sentence_id=sent_id)
            adverb_count = sum(1 for tok in doc_sentence if tok.tag_ == 'RB' and tok.text.lower().endswith('ly'))
            if adverb_count >= 4:
                _add_issue(sentence['start'], sentence['end'], 'style', 'Heavy adverb use; consider tightening.', [], sentence_id=sent_id)

    if progress_cb:
        progress_cb(48, "Checking mechanics...")

    for match in re.finditer(r' {2,}', text):
        if _time_guard():
            break
        _add_issue(match.start(), match.end(), 'grammar', 'Extra spaces.', ['Use a single space.'])

    for match in re.finditer(r'\s+([,.;:!?])', text):
        if _time_guard():
            break
        _add_issue(match.start(), match.end(), 'grammar', 'Remove space before punctuation.', [])

    for match in re.finditer(r'([,.;:!?])([A-Za-z])', text):
        if _time_guard():
            break
        _add_issue(match.start(1), match.start(2) + 1, 'grammar', 'Add a space after punctuation.', [])

    if progress_cb:
        progress_cb(60, "Checking spelling...")

    if SpellChecker or sym_spell:
        spell = SpellChecker() if SpellChecker else None
        if spell:
            spell.word_frequency.load_words(list(allowlist_lower))
        tokens_for_spell = []
        if doc is not None:
            tokens_for_spell = list(doc)
        else:
            for match in re.finditer(r"[^\W\d_]+(?:'[^\W\d_]+)?", text):
                tokens_for_spell.append(match)
        total_tokens = max(1, len(tokens_for_spell))
        for idx, token in enumerate(tokens_for_spell):
            if _time_guard():
                break
            if doc is not None:
                word = token.text
                start = token.idx
                end = token.idx + len(token.text)
                if token.is_space or token.is_punct:
                    continue
                if token.like_url or token.like_email:
                    continue
                if token.pos_ == 'PROPN':
                    continue
            else:
                word = token.group(0)
                start = token.start()
                end = token.end()
                if _overlaps_ignored(start, end):
                    continue
            if not word:
                continue
            if word.isupper() and len(word) > 1:
                continue
            if any(ch.isdigit() for ch in word):
                continue
            if _is_code_like(word):
                continue
            if '-' in word:
                continue
            if word[0].isupper():
                continue
            lower = word.lower()
            if lower in allowlist_lower:
                continue
            if zipf_frequency and zipf_frequency(lower, 'en') >= 4.5:
                continue
            unknown = False
            if spell:
                try:
                    unknown = lower in spell.unknown([lower])
                except Exception:
                    logger.info("Spellcheck skip len=%s reason=candidates_error", len(lower))
                    continue
            elif sym_spell:
                try:
                    unknown = sym_spell.word_frequency.lookup(lower) == 0
                except Exception:
                    unknown = False
            if not unknown:
                continue
            suggestions = []
            if sym_spell and symspell_verbosity:
                try:
                    lookups = sym_spell.lookup(lower, symspell_verbosity, max_edit_distance=2)
                    suggestions = [item.term for item in lookups if item.term != lower]
                except Exception:
                    suggestions = []
            if not suggestions and spell:
                try:
                    cand = spell.candidates(lower) or []
                    suggestions = [c for c in cand if c != lower]
                except Exception:
                    logger.info("Spellcheck skip len=%s reason=candidates_error", len(lower))
                    continue
            if zipf_frequency and suggestions:
                suggestions = [c for c in suggestions if zipf_frequency(c, 'en') >= 4.0]
            deduped = []
            for suggestion in suggestions:
                if suggestion not in deduped:
                    deduped.append(suggestion)
            deduped = deduped[:3]
            _add_issue(start, end, 'spelling', 'Possible spelling mistake.', deduped, sentence_id=_sentence_id_for_span(start, end, sentences))
            if progress_cb and idx % 80 == 0:
                progress_cb(60 + int(15 * idx / total_tokens), "Checking spelling...")

    if progress_cb:
        progress_cb(78, "Checking style...")

    if proselint_lint:
        try:
            style_hits = proselint_lint(text) or []
        except Exception:
            style_hits = []
        for hit in style_hits:
            if _time_guard():
                break
            if not isinstance(hit, dict):
                continue
            start = hit.get('start')
            end = hit.get('end')
            message = (hit.get('message') or '').strip()
            if start is None or end is None or not message:
                continue
            _add_issue(start, end, 'style', message, [], sentence_id=_sentence_id_for_span(start, end, sentences))

    for sentence in sentences:
        sid = sentence.get('id')
        flags = sentence_flags.get(sid, set())
        key_flags = {'capitalization', 'end_punctuation', 'proper_noun', 'run_on'}
        if len(flags.intersection(key_flags)) >= 2:
            original = sentence.get('text') or ''
            suggestion = _apply_rewrite_rules(original)
            split_suggestion = _split_on_conjunction(suggestion)
            if split_suggestion:
                suggestion = split_suggestion
            suggestion = _with_end_punct(suggestion)
            templates = _rewrite_templates(original)
            rewrites_added = 0
            if templates:
                for template in templates:
                    if rewrites_added >= 2:
                        break
                    if _is_structural_rewrite(original, template):
                        _add_issue(sentence['start'], sentence['end'], 'style', template, [], no_highlight=True, sentence_id=sid, is_rewrite=True)
                        rewrites_added += 1
            if rewrites_added < 2 and suggestion and suggestion.strip() and suggestion.strip() != original.strip():
                if _is_structural_rewrite(original, suggestion):
                    _add_issue(sentence['start'], sentence['end'], 'style', suggestion, [], no_highlight=True, sentence_id=sid, is_rewrite=True)

    def _dedupe_issues(items):
        seen = set()
        result = []
        last_end = -1
        for item in sorted(items, key=lambda i: (i['start'], -(i['end'] - i['start']))):
            key = (item['start'], item['end'], item['kind'], item['message'])
            if key in seen:
                continue
            if item.get('no_highlight'):
                seen.add(key)
                result.append(item)
                continue
            if item['start'] < last_end:
                continue
            seen.add(key)
            result.append(item)
            last_end = item['end']
        return result

    issues = _dedupe_issues(issues)

    if progress_cb:
        progress_cb(95, "Finalizing...")

    for idx, issue in enumerate(issues, start=1):
        issue.setdefault('issue_id', f'issue-{idx}')

    summary = {
        'spelling': sum(1 for i in issues if i['kind'] == 'spelling' and not i.get('no_highlight')),
        'grammar': sum(1 for i in issues if i['kind'] == 'grammar' and not i.get('no_highlight')),
        'style': sum(1 for i in issues if i['kind'] == 'style' and not i.get('no_highlight') and not i.get('is_rewrite'))
    }

    sentence_count = len(sentences)
    if sentence_count == 0 and text.strip():
        sentence_count = max(1, len(re.findall(r'[.!?]+', text)))

    word_count = token_count
    read_time_minutes = int(math.ceil(word_count / 200)) if word_count else 0

    rewrite_count = sum(1 for i in issues if i.get('is_rewrite'))
    issue_total = summary['spelling'] + summary['grammar'] + summary['style'] + rewrite_count
    score = max(35, min(100, 100 - (issue_total * 2)))

    stats = {
        'word_count': word_count,
        'sentence_count': sentence_count,
        'read_time_minutes': read_time_minutes
    }

    warning = '; '.join(warnings) if warnings else None
    return {
        'issues': issues,
        'summary': summary,
        'sentences': sentences,
        'stats': stats,
        'score': score,
        'issue_total': issue_total,
        'rewrite_count': rewrite_count
    }, None, warning

def build_highlighted_html(text, issues):
    if not issues:
        return Markup(escape(text))
    pieces = []
    last_index = 0
    def _issue_length(issue):
        return (issue.get('end', 0) or 0) - (issue.get('start', 0) or 0)

    sorted_issues = sorted(issues, key=lambda i: (i.get('start', 0), -_issue_length(i)))
    for issue in sorted_issues:
        if issue.get('no_highlight'):
            continue
        start = issue.get('start', 0) or 0
        end = issue.get('end', 0) or 0
        if start < last_index or end <= start or start > len(text):
            continue
        pieces.append(escape(text[last_index:start]))
        segment = escape(text[start:end])
        issue_kind = issue.get('kind') or issue.get('type') or 'style'
        issue_id = escape(str(issue.get('issue_id') or ''))
        data_kind = escape(issue_kind)
        pieces.append(
            f'<span class="improve-issue-{issue_kind}" data-issue-id="{issue_id}" data-kind="{data_kind}" '
            f'data-start="{start}" data-end="{end}" tabindex="0" role="button">{segment}</span>'
        )
        last_index = end
    pieces.append(escape(text[last_index:]))
    return Markup(''.join(pieces))
