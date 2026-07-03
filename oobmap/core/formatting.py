import csv
import io
import json

from ..utils.logging import _log


def split_dump_row(value: str, column_count: int) -> list[str]:
    parts = value.split("|")
    if len(parts) < column_count:
        parts.extend([""] * (column_count - len(parts)))
    if len(parts) > column_count:
        head = parts[: column_count - 1]
        tail = "|".join(parts[column_count - 1 :])
        parts = head + [tail]
    return parts


def print_dump_row(columns: list[str], row: list[str]):
    pairs = [f"{column}={value}" for column, value in zip(columns, row)]
    _log("INFO", ", ".join(pairs))


def print_dump_table(columns: list[str], rows: list[list[str]]):
    widths = [len(column) for column in columns]
    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    header = " | ".join(column.ljust(width) for column, width in zip(columns, widths))
    sep = "-+-".join("-" * width for width in widths)
    print(header)
    print(sep)
    for row in rows:
        print(" | ".join(value.ljust(width) for value, width in zip(row, widths)))


def format_table(columns: list[str], rows: list[list[str]]) -> str:
    widths = [len(c) for c in columns]
    for row in rows:
        widths = [max(w, len(v)) for w, v in zip(widths, row)]
    header = " | ".join(c.ljust(w) for c, w in zip(columns, widths))
    sep = "-+-".join("-" * w for w in widths)
    lines = [header, sep] + [" | ".join(v.ljust(w) for v, w in zip(row, widths)) for row in rows]
    return "\n".join(lines)


def format_json(columns: list[str], rows: list[list[str]]) -> str:
    return json.dumps([dict(zip(columns, row)) for row in rows], indent=2)


def format_csv(columns: list[str], rows: list[list[str]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    writer.writerows(rows)
    return out.getvalue()
