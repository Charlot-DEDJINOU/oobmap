from typing import Callable

from .encoding import hex_encode_strings, double_url_encode, url_encode
from .whitespace import inline_comments, space_to_random_blank
from .keywords import randomize_case, between_comments

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


__all__ = ["TAMPERS", "apply_tampers", "tamper_warnings"]
