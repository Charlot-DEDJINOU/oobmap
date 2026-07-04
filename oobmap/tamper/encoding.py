import re


def hex_encode_strings(payload: str) -> str:
    return re.sub(r"'([^']*)'", lambda m: "0x" + m.group(1).encode().hex(), payload)


def double_url_encode(payload: str) -> str:
    from urllib.parse import quote
    return quote(quote(payload, safe=""), safe="")


def url_encode(payload: str) -> str:
    from urllib.parse import quote
    return quote(payload, safe="")
