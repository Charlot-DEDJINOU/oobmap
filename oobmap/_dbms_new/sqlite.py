from ._sql import sql_string


def table_expression(index: int, database: str | None = None) -> str:
    return (
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        f"ORDER BY name LIMIT 1 OFFSET {index}"
    )


def column_expression(table: str, index: int, database: str | None = None) -> str:
    # PRAGMA table_info() cannot be a subquery, but pragma_table_info()
    # is a table-valued function (SQLite >= 3.16) that can.
    return (
        f"SELECT name FROM pragma_table_info('{table}') "
        f"ORDER BY cid LIMIT 1 OFFSET {index}"
    )


def dump_expression(
    table: str,
    columns: list[str],
    index: int,
    where: str | None = None,
    database: str | None = None,
) -> str:
    projection = concat_columns(columns)
    where_clause = f" WHERE {where}" if where else ""
    source = qualified_table(table, database)
    return (
        f"SELECT {projection} FROM {source}{where_clause} "
        f"ORDER BY {columns[0]} LIMIT 1 OFFSET {index}"
    )


def dbs_expression(index: int) -> str:
    raise ValueError("dbs enumeration is not implemented for sqlite-http")


def concat_columns(columns: list[str]) -> str:
    pieces = [cast_text(column) for column in columns]
    separator = sql_string("|")
    if len(pieces) == 1:
        return pieces[0]
    return f" || {separator} || ".join(pieces)


def cast_text(expression: str) -> str:
    return f"CAST({expression} AS TEXT)"


def qualified_table(table: str, database: str | None = None) -> str:
    return table


METADATA = {
    "banner": "SELECT sqlite_version()",
    "current_user": "SELECT 'sqlite'",
    "current_db": "SELECT 'main'",
}
