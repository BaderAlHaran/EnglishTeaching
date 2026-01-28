import os
import re
import threading
from typing import List

import torch
from transformers import T5ForConditionalGeneration, T5Tokenizer

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_BASE_DIR, "grammar_model")
PREFIX = "gec: "

_MODEL = None
_TOKENIZER = None
_DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
_MODEL_LOCK = threading.Lock()


def _load_model():
    global _MODEL, _TOKENIZER
    if _MODEL is not None and _TOKENIZER is not None:
        return
    with _MODEL_LOCK:
        if _MODEL is not None and _TOKENIZER is not None:
            return
        if not os.path.isdir(MODEL_PATH):
            raise RuntimeError(f"Model path not found: {MODEL_PATH}")
        print(f"[grammar_engine] BASE_DIR={_BASE_DIR}")
        print(f"[grammar_engine] MODEL_PATH={MODEL_PATH}")
        print(f"[grammar_engine] MODEL_PATH exists={os.path.isdir(MODEL_PATH)}")
        try:
            files = os.listdir(MODEL_PATH)
            print(f"[grammar_engine] MODEL_PATH files={files[:10]}")
        except Exception as exc:
            print(f"[grammar_engine] MODEL_PATH list failed: {exc}")
        _TOKENIZER = T5Tokenizer.from_pretrained(MODEL_PATH)
        _MODEL = T5ForConditionalGeneration.from_pretrained(MODEL_PATH)
        _MODEL.to(_DEVICE)
        _MODEL.eval()


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
_MAX_INPUT_TOKENS = 512
_MAX_OUTPUT_TOKENS = 512
_CHUNK_MAX_CHARS = 1200


def _split_sentences(text: str) -> List[str]:
    text = text.strip()
    if not text:
        return []
    sentences = _SENTENCE_SPLIT_RE.split(text)
    return [s for s in sentences if s.strip()]


def _chunk_sentences(sentences: List[str], max_chars: int = _CHUNK_MAX_CHARS) -> List[str]:
    _load_model()
    if not sentences:
        return []
    prefix_tokens = len(_TOKENIZER.encode(PREFIX, add_special_tokens=False))
    token_limit = max(32, _MAX_INPUT_TOKENS - prefix_tokens - 8)
    chunks = []
    current = []
    current_len = 0
    current_tokens = 0

    def _sentence_token_len(sentence: str) -> int:
        return len(_TOKENIZER.encode(sentence, add_special_tokens=False))

    def _flush_current():
        nonlocal current, current_len, current_tokens
        if current:
            chunks.append(" ".join(current).strip())
            current = []
            current_len = 0
            current_tokens = 0

    def _split_by_tokens(sentence: str) -> List[str]:
        words = re.findall(r"\S+|\s+", sentence)
        parts = []
        buf = ""
        buf_tokens = 0
        for piece in words:
            if not piece.strip():
                buf += piece
                continue
            piece_tokens = _sentence_token_len(piece)
            if piece_tokens > token_limit:
                if buf.strip():
                    parts.append(buf.strip())
                parts.append(piece.strip())
                buf = ""
                buf_tokens = 0
                continue
            if buf_tokens + piece_tokens > token_limit:
                if buf.strip():
                    parts.append(buf.strip())
                buf = piece
                buf_tokens = piece_tokens
            else:
                buf += piece
                buf_tokens += piece_tokens
        if buf.strip():
            parts.append(buf.strip())
        return parts

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
        if len(sentence) > max_chars or _sentence_token_len(sentence) > token_limit:
            _flush_current()
            for part in _split_by_tokens(sentence):
                if part:
                    chunks.append(part)
            continue
        sentence_tokens = _sentence_token_len(sentence)
        if (current_len + len(sentence) + (1 if current else 0) > max_chars) or (current_tokens + sentence_tokens > token_limit):
            _flush_current()
            current = [sentence]
            current_len = len(sentence)
            current_tokens = sentence_tokens
        else:
            current.append(sentence)
            current_len += len(sentence) + (1 if current_len else 0)
            current_tokens += sentence_tokens
    _flush_current()
    return chunks


def _correct_chunk(text: str) -> str:
    _load_model()
    if not text.strip():
        return text
    prefixed = PREFIX + text.strip()
    inputs = _TOKENIZER(
        prefixed,
        return_tensors="pt",
        truncation=True,
        max_length=_MAX_INPUT_TOKENS
    )
    inputs = {k: v.to(_DEVICE) for k, v in inputs.items()}
    with torch.no_grad():
        input_len = int(inputs["input_ids"].shape[1])
        max_out = min(_MAX_OUTPUT_TOKENS, max(64, input_len + 64))
        outputs = _MODEL.generate(
            **inputs,
            max_length=max_out,
            num_beams=4,
            early_stopping=True
        )
    decoded = _TOKENIZER.decode(outputs[0], skip_special_tokens=True)
    return decoded.strip()


def correct_long_text(text: str) -> str:
    _load_model()
    if text is None:
        return ""
    raw = text.strip()
    if not raw:
        return text
    sentences = _split_sentences(raw)
    if not sentences:
        return text
    chunks = _chunk_sentences(sentences, max_chars=1200)
    corrected_parts = []
    for chunk in chunks:
        corrected_parts.append(_correct_chunk(chunk))
    return " ".join([part for part in corrected_parts if part])
