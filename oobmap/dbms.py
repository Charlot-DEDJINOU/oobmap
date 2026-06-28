from dataclasses import dataclass


@dataclass(frozen=True)
class DbmsProfile:
    name: str

    def metadata_expression(self, key: str) -> str | None:
        return METADATA.get(self.name, {}).get(key)

    def table_expression(self, index: int, database: str | None = None) -> str:
        if self.name == "mssql":
            catalog_filter = f" AND TABLE_CATALOG={sql_string(database)}" if database else ""
            return (
                "SELECT name FROM ("
                "SELECT TABLE_NAME AS name, ROW_NUMBER() OVER (ORDER BY TABLE_NAME) AS rn "
                f"FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'{catalog_filter}"
                f") AS t WHERE rn={index + 1}"
            )
        if self.name == "mysql":
            schema = sql_string(database) if database else "database()"
            return (
                "SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema={schema} "
                f"ORDER BY table_name LIMIT 1 OFFSET {index}"
            )
        if self.name == "postgres-program":
            schema = sql_string(database or "public")
            return (
                "SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema={schema} AND table_type='BASE TABLE' "
                f"ORDER BY table_name LIMIT 1 OFFSET {index}"
            )
        if self.name == "oracle-http":
            owner_filter = f" WHERE owner={sql_string(database.upper())}" if database else ""
            return (
                "SELECT table_name FROM ("
                "SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) AS rn "
                f"FROM all_tables{owner_filter}"
                f") WHERE rn={index + 1}"
            )
        if self.name == "sqlite-lab":
            return (
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                f"ORDER BY name LIMIT 1 OFFSET {index}"
            )
        raise ValueError(f"tables are not implemented for {self.name}")

    def column_expression(self, table: str, index: int, database: str | None = None) -> str:
        escaped = sql_string(table)
        if self.name == "mssql":
            catalog_filter = f" AND TABLE_CATALOG={sql_string(database)}" if database else ""
            return (
                "SELECT name FROM ("
                "SELECT COLUMN_NAME AS name, ROW_NUMBER() OVER (ORDER BY ORDINAL_POSITION) AS rn "
                f"FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME={escaped}{catalog_filter}"
                f") AS c WHERE rn={index + 1}"
            )
        if self.name == "mysql":
            schema = sql_string(database) if database else "database()"
            return (
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema={schema} AND table_name={escaped} "
                f"ORDER BY ordinal_position LIMIT 1 OFFSET {index}"
            )
        if self.name == "postgres-program":
            schema = sql_string(database or "public")
            return (
                "SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema={schema} AND table_name={escaped} "
                f"ORDER BY ordinal_position LIMIT 1 OFFSET {index}"
            )
        if self.name == "oracle-http":
            upper = sql_string(table.upper())
            owner_filter = f" AND owner={sql_string(database.upper())}" if database else ""
            return (
                "SELECT column_name FROM ("
                "SELECT column_name, ROW_NUMBER() OVER (ORDER BY column_id) AS rn "
                f"FROM all_tab_columns WHERE table_name={upper}{owner_filter}"
                f") WHERE rn={index + 1}"
            )
        if self.name in ("sqlite-lab", "sqlite-http"):
            # PRAGMA table_info() cannot be a subquery, but pragma_table_info()
            # is a table-valued function (SQLite >= 3.16) that can.
            return (
                f"SELECT name FROM pragma_table_info('{table}') "
                f"ORDER BY cid LIMIT 1 OFFSET {index}"
            )
        raise ValueError(f"columns are not implemented for {self.name}")

    def dump_expression(
        self,
        table: str,
        columns: list[str],
        index: int,
        where: str | None = None,
        database: str | None = None,
    ) -> str:
        if not columns:
            raise ValueError("at least one column is required")
        projection = self.concat_columns(columns)
        where_clause = f" WHERE {where}" if where else ""
        source = self.qualified_table(table, database)

        if self.name == "mssql":
            order = columns[0]
            return (
                "SELECT row_value FROM ("
                f"SELECT {projection} AS row_value, ROW_NUMBER() OVER (ORDER BY {order}) AS rn "
                f"FROM {source}{where_clause}"
                f") AS d WHERE rn={index + 1}"
            )
        if self.name in {"mysql", "postgres-program", "sqlite-lab"}:
            return (
                f"SELECT {projection} FROM {source}{where_clause} "
                f"ORDER BY {columns[0]} LIMIT 1 OFFSET {index}"
            )
        if self.name == "oracle-http":
            return (
                "SELECT row_value FROM ("
                f"SELECT {projection} AS row_value, ROW_NUMBER() OVER (ORDER BY {columns[0]}) AS rn "
                f"FROM {source}{where_clause}"
                f") WHERE rn={index + 1}"
            )
        raise ValueError(f"dump is not implemented for {self.name}")

    def dbs_expression(self, index: int) -> str:
        if self.name == "mysql":
            return (
                "SELECT schema_name FROM information_schema.schemata "
                f"ORDER BY schema_name LIMIT 1 OFFSET {index}"
            )
        if self.name == "mssql":
            return (
                "SELECT name FROM ("
                "SELECT name, ROW_NUMBER() OVER (ORDER BY name) AS rn "
                "FROM master.sys.databases"
                f") AS t WHERE rn={index + 1}"
            )
        if self.name == "postgres-program":
            return (
                "SELECT datname FROM pg_database "
                f"WHERE datistemplate=false ORDER BY datname LIMIT 1 OFFSET {index}"
            )
        if self.name == "oracle-http":
            return (
                "SELECT username FROM ("
                "SELECT username, ROW_NUMBER() OVER (ORDER BY username) AS rn "
                "FROM all_users"
                f") WHERE rn={index + 1}"
            )
        raise ValueError(f"dbs enumeration is not implemented for {self.name}")

    def concat_columns(self, columns: list[str]) -> str:
        pieces = [self.cast_text(column) for column in columns]
        separator = sql_string("|")
        if len(pieces) == 1:
            return pieces[0]
        if self.name == "mssql":
            return f" + {separator} + ".join(pieces)
        if self.name == "mysql":
            args = []
            for index, piece in enumerate(pieces):
                if index:
                    args.append(separator)
                args.append(piece)
            return "CONCAT(" + ",".join(args) + ")"
        return f" || {separator} || ".join(pieces)

    def cast_text(self, expression: str) -> str:
        if self.name == "mssql":
            return f"CAST({expression} AS NVARCHAR(MAX))"
        if self.name == "mysql":
            return f"CAST({expression} AS CHAR)"
        if self.name == "oracle-http":
            return f"TO_CHAR({expression})"
        if self.name in {"postgres-program", "sqlite-lab"}:
            return f"CAST({expression} AS TEXT)"
        return expression

    def qualified_table(self, table: str, database: str | None = None) -> str:
        if not database:
            return table
        if self.name == "mssql":
            return f"{database}..{table}"
        if self.name in {"mysql", "postgres-program", "oracle-http"}:
            return f"{database}.{table}"
        return table


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

METADATA["postgres-dblink"] = METADATA["postgres-program"]
METADATA["mssql-cmdshell"] = METADATA["mssql"]
METADATA["mysql-stacked"] = METADATA["mysql"]
METADATA["sqlite-http"] = METADATA["sqlite-lab"]

DBMS["postgres-dblink"] = DbmsProfile("postgres-program")
DBMS["mssql-cmdshell"] = DbmsProfile("mssql")
DBMS["mysql-stacked"] = DbmsProfile("mysql")
DBMS["sqlite-http"] = DbmsProfile("sqlite-lab")
