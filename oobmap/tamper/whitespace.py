import random


def inline_comments(payload: str) -> str:
    return payload.replace(" ", "/**/")


def space_to_random_blank(payload: str) -> str:
    blanks = ["\t", "\n", "\x0b", "\x0c", "\r"]
    return "".join(random.choice(blanks) if c == " " else c for c in payload)
