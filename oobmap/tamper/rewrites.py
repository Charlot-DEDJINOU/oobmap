import re

_IF_PATTERN = re.compile(r"\bIF\(", re.IGNORECASE)


def _find_matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    in_quote = False
    i = open_idx
    while i < len(s):
        c = s[i]
        if c == "'":
            in_quote = not in_quote
        elif not in_quote:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _split_top_level_commas(s: str) -> list[str]:
    parts = []
    depth = 0
    in_quote = False
    start = 0
    for i, c in enumerate(s):
        if c == "'":
            in_quote = not in_quote
        elif not in_quote:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "," and depth == 0:
                parts.append(s[start:i])
                start = i + 1
    parts.append(s[start:])
    return parts


def if2case(payload: str) -> str:
    match = _IF_PATTERN.search(payload)
    if not match:
        return payload

    open_idx = match.end() - 1
    close_idx = _find_matching_paren(payload, open_idx)
    if close_idx == -1:
        return payload

    inner = payload[open_idx + 1:close_idx]
    parts = _split_top_level_commas(inner)

    if len(parts) != 3:
        before = payload[:match.end()]
        rest = if2case(payload[match.end():])
        return before + rest

    cond, then, els = (if2case(p.strip()) for p in parts)
    replacement = f"CASE WHEN ({cond}) THEN ({then}) ELSE ({els}) END"
    before = payload[:match.start()]
    after = if2case(payload[close_idx + 1:])
    return before + replacement + after
