from ._sql import sql_string


def table_expression(index: int, database: str | None = None) -> str:
    schema = sql_string(database) if database else "database()"
    return (
        "SELECT table_name FROM information_schema.tables "
        f"WHERE table_schema={schema} "
        f"ORDER BY table_name LIMIT 1 OFFSET {index}"
    )


def column_expression(table: str, index: int, database: str | None = None) -> str:
    escaped = sql_string(table)
    schema = sql_string(database) if database else "database()"
    return (
        "SELECT column_name FROM information_schema.columns "
        f"WHERE table_schema={schema} AND table_name={escaped} "
        f"ORDER BY ordinal_position LIMIT 1 OFFSET {index}"
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
    return (
        "SELECT schema_name FROM information_schema.schemata "
        f"ORDER BY schema_name LIMIT 1 OFFSET {index}"
    )


def concat_columns(columns: list[str]) -> str:
    pieces = [cast_text(column) for column in columns]
    separator = sql_string("|")
    if len(pieces) == 1:
        return pieces[0]
    args = []
    for index, piece in enumerate(pieces):
        if index:
            args.append(separator)
        args.append(piece)
    return "CONCAT(" + ",".join(args) + ")"


def cast_text(expression: str) -> str:
    return f"CAST({expression} AS CHAR)"


def qualified_table(table: str, database: str | None = None) -> str:
    if not database:
        return table
    return f"{database}.{table}"


METADATA = {
    "banner": "SELECT @@version",
    "current_user": "SELECT USER()",
    "current_db": "SELECT DATABASE()",
}
