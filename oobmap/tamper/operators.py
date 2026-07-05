import re


def between(payload: str) -> str:
    payload = re.sub(r">\s*(\d+)", r" NOT BETWEEN 0 AND \1", payload)
    payload = re.sub(r"=\s*(\d+)", r" BETWEEN \1 AND \1", payload)
    return payload


def equaltolike(payload: str) -> str:
    return payload.replace("=", " LIKE ")


def equaltorlike(payload: str) -> str:
    return payload.replace("=", " RLIKE ")


_COMPARISON_TOKEN = r"([\w']+)"


def greatest(payload: str) -> str:
    pattern = re.compile(_COMPARISON_TOKEN + r"\s*>\s*" + _COMPARISON_TOKEN)
    return pattern.sub(lambda m: f"GREATEST({m.group(1)},{m.group(2)})<>{m.group(2)}", payload)


def least(payload: str) -> str:
    pattern = re.compile(_COMPARISON_TOKEN + r"\s*<\s*" + _COMPARISON_TOKEN)
    return pattern.sub(lambda m: f"LEAST({m.group(1)},{m.group(2)})<>{m.group(2)}", payload)
