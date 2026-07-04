from ._sql import sql_string


def table_expression(index: int, database: str | None = None) -> str:
    owner_filter = f" WHERE owner={sql_string(database.upper())}" if database else ""
    return (
        "SELECT table_name FROM ("
        "SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) AS rn "
        f"FROM all_tables{owner_filter}"
        f") WHERE rn={index + 1}"
    )


def column_expression(table: str, index: int, database: str | None = None) -> str:
    upper = sql_string(table.upper())
    owner_filter = f" AND owner={sql_string(database.upper())}" if database else ""
    return (
        "SELECT column_name FROM ("
        "SELECT column_name, ROW_NUMBER() OVER (ORDER BY column_id) AS rn "
        f"FROM all_tab_columns WHERE table_name={upper}{owner_filter}"
        f") WHERE rn={index + 1}"
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
        "SELECT row_value FROM ("
        f"SELECT {projection} AS row_value, ROW_NUMBER() OVER (ORDER BY {columns[0]}) AS rn "
        f"FROM {source}{where_clause}"
        f") WHERE rn={index + 1}"
    )


def dbs_expression(index: int) -> str:
    return (
        "SELECT username FROM ("
        "SELECT username, ROW_NUMBER() OVER (ORDER BY username) AS rn "
        "FROM all_users"
        f") WHERE rn={index + 1}"
    )


def concat_columns(columns: list[str]) -> str:
    pieces = [cast_text(column) for column in columns]
    separator = sql_string("|")
    if len(pieces) == 1:
        return pieces[0]
    return f" || {separator} || ".join(pieces)


def cast_text(expression: str) -> str:
    return f"TO_CHAR({expression})"


def qualified_table(table: str, database: str | None = None) -> str:
    if not database:
        return table
    return f"{database}.{table}"


METADATA = {
    "banner": "SELECT banner FROM v$version WHERE rownum=1",
    "current_user": "SELECT USER FROM dual",
    "current_db": "SELECT ora_database_name FROM dual",
}
