def sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
