import re

_VERSIONED_KEYWORDS = ["SELECT", "FROM", "WHERE", "AND", "OR", "UNION"]
_VERSIONED_MORE_KEYWORDS = [
    "SELECT", "FROM", "WHERE", "AND", "OR", "UNION",
    "IF", "CASE", "WHEN", "THEN", "ELSE", "END",
    "ORDER", "GROUP", "LIMIT",
]


def _keyword_pattern(keywords: list[str]) -> re.Pattern:
    return re.compile(r"\b(" + "|".join(sorted(keywords, key=len, reverse=True)) + r")\b", re.IGNORECASE)


def versionedkeywords(payload: str) -> str:
    return _keyword_pattern(_VERSIONED_KEYWORDS).sub(lambda m: f"/*!{m.group(0)}*/", payload)


def versionedmorekeywords(payload: str) -> str:
    return _keyword_pattern(_VERSIONED_MORE_KEYWORDS).sub(lambda m: f"/*!{m.group(0)}*/", payload)


def halfversionedmorekeywords(payload: str) -> str:
    result, count = _keyword_pattern(_VERSIONED_MORE_KEYWORDS).subn(lambda m: f"/*!{m.group(0)}", payload)
    if count:
        result += "*/"
    return result


def modsecurityversioned(payload: str) -> str:
    return f"/*!{payload}*/"


def modsecurityzeroversioned(payload: str) -> str:
    return f"/*!00000{payload}*/"
