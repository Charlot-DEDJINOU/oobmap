import random
import re

_BLUECOAT_KEYWORD = re.compile(r"\b(SELECT|UNION|WHERE|AND|OR|FROM)\s", re.IGNORECASE)
_BLUECOAT_BLANKS = ["%09", "%0a", "%0c", "%0d", "%0b"]


def bluecoat(payload: str) -> str:
    match = _BLUECOAT_KEYWORD.search(payload)
    if match:
        blank = random.choice(_BLUECOAT_BLANKS)
        end = match.end()
        payload = payload[:end - 1] + blank + payload[end:]
    return payload.replace("=", " LIKE ")


def commentbeforeparentheses(payload: str) -> str:
    return payload.replace("(", "/**/(")


_MULTISPACE_KEYWORDS = re.compile(r"\b(AND|OR|SELECT|WHERE|UNION)\b", re.IGNORECASE)


def multiplespaces(payload: str) -> str:
    return _MULTISPACE_KEYWORDS.sub(lambda m: f"   {m.group(0)}   ", payload)
