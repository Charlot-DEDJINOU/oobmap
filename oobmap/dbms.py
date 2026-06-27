from dataclasses import dataclass


@dataclass(frozen=True)
class DbmsProfile:
    name: str

    def metadata_expression(self, key: str) -> str | None:
        return METADATA.get(self.name, {}).get(key)

    def table_expression(self, index: int) -> str:
        if self.name == "mssql":
            return (
                "SELECT name FROM ("
                "SELECT TABLE_NAME AS name, ROW_NUMBER() OVER (ORDER BY TABLE_NAME) AS rn "
                "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'"
                f") AS t WHERE rn={index + 1}"
            )
        if self.name == "mysql":
            return (
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=database() "
                f"ORDER BY table_name LIMIT 1 OFFSET {index}"
            )
        if self.name == "postgres-program":
            return (
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public' AND table_type='BASE TABLE' "
                f"ORDER BY table_name LIMIT 1 OFFSET {index}"
            )
        if self.name == "oracle-http":
            return (
                "SELECT table_name FROM ("
                "SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) AS rn "
                "FROM all_tables"
                f") WHERE rn={index + 1}"
            )
        if self.name == "sqlite-lab":
            return (
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                f"ORDER BY name LIMIT 1 OFFSET {index}"
            )
        raise ValueError(f"tables are not implemented for {self.name}")

    def column_expression(self, table: str, index: int) -> str:
        escaped = sql_string(table)
        if self.name == "mssql":
            return (
                "SELECT name FROM ("
                "SELECT COLUMN_NAME AS name, ROW_NUMBER() OVER (ORDER BY ORDINAL_POSITION) AS rn "
                f"FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME={escaped}"
                f") AS c WHERE rn={index + 1}"
            )
        if self.name == "mysql":
            return (
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name={escaped} "
                f"ORDER BY ordinal_position LIMIT 1 OFFSET {index}"
            )
        if self.name == "postgres-program":
            return (
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema='public' AND table_name={escaped} "
                f"ORDER BY ordinal_position LIMIT 1 OFFSET {index}"
            )
        if self.name == "oracle-http":
            upper = sql_string(table.upper())
            return (
                "SELECT column_name FROM ("
                "SELECT column_name, ROW_NUMBER() OVER (ORDER BY column_id) AS rn "
                f"FROM all_tab_columns WHERE table_name={upper}"
                f") WHERE rn={index + 1}"
            )
        if self.name == "sqlite-lab":
            # SQLite PRAGMA cannot be used as a scalar subquery in this context.
            # The local training lab is intentionally focused on extraction basics.
            raise ValueError("columns are not implemented for sqlite-lab")
        raise ValueError(f"columns are not implemented for {self.name}")


def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


METADATA = {
    "sqlite-lab": {
        "banner": "SELECT sqlite_version()",
        "current_user": "SELECT 'sqlite'",
        "current_db": "SELECT 'main'",
    },
    "mssql": {
        "banner": "SELECT @@version",
        "current_user": "SELECT SYSTEM_USER",
        "current_db": "SELECT DB_NAME()",
    },
    "mysql": {
        "banner": "SELECT @@version",
        "current_user": "SELECT USER()",
        "current_db": "SELECT DATABASE()",
    },
    "oracle-http": {
        "banner": "SELECT banner FROM v$version WHERE rownum=1",
        "current_user": "SELECT USER FROM dual",
        "current_db": "SELECT ora_database_name FROM dual",
    },
    "postgres-program": {
        "banner": "SELECT version()",
        "current_user": "SELECT current_user",
        "current_db": "SELECT current_database()",
    },
}


DBMS = {name: DbmsProfile(name) for name in METADATA}
