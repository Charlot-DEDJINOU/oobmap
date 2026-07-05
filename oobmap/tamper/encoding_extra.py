import base64
import re


def apostrophemask(payload: str) -> str:
    return payload.replace("'", "%EF%BC%87")


def apostrophenullencode(payload: str) -> str:
    return payload.replace("'", "%00%27")


def appendnullbyte(payload: str) -> str:
    return payload + "%00"


def base64encode(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def escapequotes(payload: str) -> str:
    return payload.replace("'", "\\'").replace('"', '\\"')


def percentage(payload: str) -> str:
    return "".join(f"%{c}" for c in payload)


def decentities(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)


def hexentities(payload: str) -> str:
    return "".join(f"&#x{ord(c):X};" for c in payload)


def htmlencode(payload: str) -> str:
    return "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in payload)


_ALREADY_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")


def _unicode_encode(payload: str, template: str) -> str:
    result = []
    i = 0
    while i < len(payload):
        if payload[i] == "%" and _ALREADY_ENCODED.match(payload, i):
            result.append(payload[i:i + 3])
            i += 3
        else:
            result.append(template % ord(payload[i]))
            i += 1
    return "".join(result)


def charunicodeencode(payload: str) -> str:
    return _unicode_encode(payload, "%%u%04X")


def charunicodeescape(payload: str) -> str:
    return _unicode_encode(payload, "\\u%04X")
