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
_DEBUG_TREE_PRINTED = False


def _is_model_dir(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    has_config = os.path.isfile(os.path.join(path, "config.json"))
    has_tokenizer = os.path.isfile(os.path.join(path, "tokenizer.json")) or os.path.isfile(
        os.path.join(path, "tokenizer_config.json")
    )
    has_weights = os.path.isfile(os.path.join(path, "model.safetensors")) or os.path.isfile(
        os.path.join(path, "pytorch_model.bin")
    )
    return has_config and has_tokenizer and has_weights


def _print_model_tree_once(base_path: str):
    global _DEBUG_TREE_PRINTED
    if _DEBUG_TREE_PRINTED:
        return
    _DEBUG_TREE_PRINTED = True
    print(f"[grammar_engine] BASE_DIR={_BASE_DIR}")
    print(f"[grammar_engine] Expected MODEL_PATH={MODEL_PATH}")
    try:
        for root, dirs, files in os.walk(base_path):
            depth = root.replace(base_path, "").count(os.sep)
            if depth > 2:
                dirs[:] = []
                continue
            rel = os.path.relpath(root, base_path)
            print(f"[grammar_engine] {rel}: dirs={dirs} files={files[:10]}")
    except Exception as exc:
        print(f"[grammar_engine] tree walk failed: {exc}")


def _find_model_dir() -> str:
    # 1) direct expected path
    if _is_model_dir(MODEL_PATH):
        return MODEL_PATH
    # 2) common nested extraction path
    nested = os.path.join(MODEL_PATH, "grammar_model")
    if _is_model_dir(nested):
        return nested
    # 3) search within base dir for a valid model folder
    try:
        for entry in os.listdir(_BASE_DIR):
            candidate = os.path.join(_BASE_DIR, entry)
            if _is_model_dir(candidate):
                return candidate
            if os.path.isdir(candidate):
                inner = os.path.join(candidate, "grammar_model")
                if _is_model_dir(inner):
                    return inner
    except Exception:
        pass
    return ""


def _load_model():
    global _MODEL, _TOKENIZER
    if _MODEL is not None and _TOKENIZER is not None:
        return
    with _MODEL_LOCK:
        if _MODEL is not None and _TOKENIZER is not None:
            return
        _print_model_tree_once(_BASE_DIR)
        model_dir = _find_model_dir()
        if not model_dir:
            raise RuntimeError(f"Model path not found: {MODEL_PATH}")
        print(f"[grammar_engine] Using model dir: {model_dir}")
        _TOKENIZER = T5Tokenizer.from_pretrained(model_dir)
        _MODEL = T5ForConditionalGeneration.from_pretrained(model_dir)
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
