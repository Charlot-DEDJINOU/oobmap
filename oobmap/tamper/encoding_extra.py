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


def _overlong_byte_pair(c: str) -> str:
    cp = ord(c)
    b1 = 0xC0 | (cp >> 6)
    b2 = 0x80 | (cp & 0x3F)
    return f"%{b1:02X}%{b2:02X}"


def overlongutf8(payload: str) -> str:
    return "".join(_overlong_byte_pair(c) if not c.isalnum() else c for c in payload)


def overlongutf8more(payload: str) -> str:
    return "".join(_overlong_byte_pair(c) for c in payload)


def unmagicquotes(payload: str) -> str:
    if "'" not in payload:
        return payload
    return payload.replace("'", "%bf%27") + "--"


_HEX_LITERAL = re.compile(r"\b0x([0-9A-Fa-f]+)\b")


def _hex_to_char_concat(match: re.Match) -> str:
    hex_digits = match.group(1)
    if len(hex_digits) % 2 != 0:
        return match.group(0)
    chars = [str(int(hex_digits[i:i + 2], 16)) for i in range(0, len(hex_digits), 2)]
    return "CONCAT(" + ",".join(f"CHAR({n})" for n in chars) + ")"


def hex2char(payload: str) -> str:
    return _HEX_LITERAL.sub(_hex_to_char_concat, payload)
