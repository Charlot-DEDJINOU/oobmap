from ._sql import sql_string


def table_expression(index: int, database: str | None = None) -> str:
    catalog_filter = f" AND TABLE_CATALOG={sql_string(database)}" if database else ""
    return (
        "SELECT name FROM ("
        "SELECT TABLE_NAME AS name, ROW_NUMBER() OVER (ORDER BY TABLE_NAME) AS rn "
        f"FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'{catalog_filter}"
        f") AS t WHERE rn={index + 1}"
    )


def column_expression(table: str, index: int, database: str | None = None) -> str:
    escaped = sql_string(table)
    catalog_filter = f" AND TABLE_CATALOG={sql_string(database)}" if database else ""
    return (
        "SELECT name FROM ("
        "SELECT COLUMN_NAME AS name, ROW_NUMBER() OVER (ORDER BY ORDINAL_POSITION) AS rn "
        f"FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME={escaped}{catalog_filter}"
        f") AS c WHERE rn={index + 1}"
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
    order = columns[0]
    return (
        "SELECT row_value FROM ("
        f"SELECT {projection} AS row_value, ROW_NUMBER() OVER (ORDER BY {order}) AS rn "
        f"FROM {source}{where_clause}"
        f") AS d WHERE rn={index + 1}"
    )


def dbs_expression(index: int) -> str:
    return (
        "SELECT name FROM ("
        "SELECT name, ROW_NUMBER() OVER (ORDER BY name) AS rn "
        "FROM master.sys.databases"
        f") AS t WHERE rn={index + 1}"
    )


def concat_columns(columns: list[str]) -> str:
    pieces = [cast_text(column) for column in columns]
    separator = sql_string("|")
    if len(pieces) == 1:
        return pieces[0]
    return f" + {separator} + ".join(pieces)


def cast_text(expression: str) -> str:
    return f"CAST({expression} AS NVARCHAR(MAX))"


def qualified_table(table: str, database: str | None = None) -> str:
    if not database:
        return table
    return f"{database}..{table}"


METADATA = {
    "banner": "SELECT @@version",
    "current_user": "SELECT SYSTEM_USER",
    "current_db": "SELECT DB_NAME()",
}
