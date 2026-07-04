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


from .encoding import hex_encode_strings, double_url_encode, url_encode


def space_to_random_blank(payload: str) -> str:
    blanks = ["\t", "\n", "\x0b", "\x0c", "\r"]
    return "".join(random.choice(blanks) if c == " " else c for c in payload)


TAMPERS: dict[str, tuple[Callable[[str], str], str]] = {
    "inline-comments":    (inline_comments,       "Replace spaces with /**/"),
    "randomize-case":     (randomize_case,        "Randomly capitalize SQL keywords"),
    "between-comments":   (between_comments,      "Split keywords mid-word: SEL/**/ECT"),
    "hex-encode-strings": (hex_encode_strings,    "Convert 'string' literals to 0x hex"),
    "double-url-encode":  (double_url_encode,     "Double URL-encode the full payload"),
    "url-encode":         (url_encode,            "URL-encode the full payload once"),
    "space2randomblank":  (space_to_random_blank, "Replace spaces with a random whitespace character (tab/newline/etc.)"),
}


def apply_tampers(payload: str, names: list[str]) -> str:
    for name in names:
        fn, _ = TAMPERS[name]
        payload = fn(payload)
    return payload


# Tampers whose SQL rewriting only works for specific DBMS dialects.
# hex-encode-strings relies on bare 0x<hex> literal syntax, only valid in MySQL/MSSQL.
_HEX_ENCODE_COMPATIBLE_DBMS = {"mysql", "mysql-stacked", "mssql", "mssql-cmdshell"}


def tamper_warnings(tamper_names: list[str], dbms: str | None) -> list[str]:
    """Return human-readable warnings for tamper/DBMS combinations known to
    break query syntax. Advisory only — callers print these and continue;
    this function never raises and never blocks execution."""
    warnings = []
    if "hex-encode-strings" in tamper_names and dbms and dbms not in _HEX_ENCODE_COMPATIBLE_DBMS:
        warnings.append(
            "tamper 'hex-encode-strings' emits bare 0x<hex> literals, valid "
            f"only in MySQL/MSSQL — likely to break query syntax for --dbms {dbms}."
        )
    return warnings
