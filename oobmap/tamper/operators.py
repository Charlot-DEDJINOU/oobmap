import re


def between(payload: str) -> str:
    payload = re.sub(r">\s*(\d+)", r" NOT BETWEEN 0 AND \1", payload)
    payload = re.sub(r"=\s*(\d+)", r" BETWEEN \1 AND \1", payload)
    return payload


def equaltolike(payload: str) -> str:
    return payload.replace("=", " LIKE ")


def equaltorlike(payload: str) -> str:
    return payload.replace("=", " RLIKE ")
