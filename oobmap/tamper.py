import random
import re
from typing import Callable


def inline_comments(payload: str) -> str:
    return payload.replace(" ", "/**/")


def randomize_case(payload: str) -> str:
    keywords = [
        "SELECT", "FROM", "WHERE", "AND", "OR", "IF", "CASE", "WHEN",
        "THEN", "ELSE", "END", "LOAD_FILE", "EXEC", "CAST", "SUBSTRING",
        "SUBSTR", "CHAR", "COPY", "INTO", "PROGRAM", "NSLOOKUP",
    ]
    for kw in keywords:
        payload = re.sub(
            re.escape(kw),
            lambda m: "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in m.group(0)
            ),
            payload,
            flags=re.IGNORECASE,
        )
    return payload


def between_comments(payload: str) -> str:
    for kw in ["SELECT", "FROM", "WHERE", "UNION", "EXEC", "CAST", "COPY"]:
        mid = len(kw) // 2
        payload = re.sub(
            re.escape(kw),
            kw[:mid] + "/**/" + kw[mid:],
            payload,
            flags=re.IGNORECASE,
        )
    return payload


def hex_encode_strings(payload: str) -> str:
    return re.sub(r"'([^']*)'", lambda m: "0x" + m.group(1).encode().hex(), payload)


def double_url_encode(payload: str) -> str:
    from urllib.parse import quote
    return quote(quote(payload, safe=""), safe="")


TAMPERS: dict[str, tuple[Callable[[str], str], str]] = {
    "inline-comments":    (inline_comments,    "Replace spaces with /**/"),
    "randomize-case":     (randomize_case,     "Randomly capitalize SQL keywords"),
    "between-comments":   (between_comments,   "Split keywords mid-word: SEL/**/ECT"),
    "hex-encode-strings": (hex_encode_strings, "Convert 'string' literals to 0x hex"),
    "double-url-encode":  (double_url_encode,  "Double URL-encode the full payload"),
}


def apply_tampers(payload: str, names: list[str]) -> str:
    for name in names:
        fn, _ = TAMPERS[name]
        payload = fn(payload)
    return payload
