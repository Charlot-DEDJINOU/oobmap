import base64


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
