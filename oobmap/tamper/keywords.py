import random
import re


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


